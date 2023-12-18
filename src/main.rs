/*

using statement

 */
use pnet::{
    datalink::{Channel, DataLinkReceiver, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::{ipv4_checksum, ipv6_checksum, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket},
        Packet,
    },
    transport::{self, TransportChannelType, TransportProtocol, TransportSender},
};
use rand::{rngs::ThreadRng, thread_rng, Rng};
use std::ops::Deref;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

/*

Consts

 */
pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const ETHERNET_HEADER_LEN: usize = 14;

/*

config struct

 */
pub struct Config {
    interface_ip: IpAddr,
    source_port: u16,
    destination_ip: IpAddr,
    ports_to_scan: Vec<u16>,
    wait_after_send: Duration,
    timeout: Duration,
    all_sent: Arc<AtomicBool>,
}
impl Config {
    pub fn new(
        destination_ip: IpAddr,
        ports_to_scan: Vec<u16>,
        interface_ip: IpAddr,
        timeout: u64,
    ) -> Self {
        //get ephemeral port to use
        let source_port: u16 = generate_random_sequence(10024, 65535) as u16;
        Self {
            interface_ip,
            source_port,
            destination_ip,
            //set the kill flag, giving every syn packet a 500 millisecond roundtrip
            wait_after_send: Duration::from_millis(1500 * ports_to_scan.len() as u64),
            ports_to_scan,
            //timeout just in case we need it.
            timeout: Duration::from_secs(timeout),
            //kill flag
            all_sent: Arc::new(AtomicBool::new(false)),
        }
    }
}

/*

main

 */
fn main() {
    //setting up values for new config and an interface to send into receive_packets
    let interface_name = std::env::args().nth(1);
    //set up var to use, make sure its in scope
    let destination_ip: IpAddr;

    if let Some(ip) = std::env::args().nth(2) {
        match ip.parse::<IpAddr>() {
            Ok(ip) => destination_ip = ip,
            Err(err) => {
                panic!("error parsing ip address {}\n error: \n {}", ip, err);
            }
        }
    } else {
        panic!("no ipv4 or ipv6 address provided")
    }

    //change to desired ports
    let ports_to_scan: Vec<u16> = vec![443];
    let (interface, interface_ip): (NetworkInterface, IpAddr) = get_interface(interface_name);

    //timeout value if op isnt working correctly, going to be in secs.
    let timeout: u64 = 10;

    //config
    let config: Config = Config::new(destination_ip, ports_to_scan, interface_ip, timeout);

    //create the arcs to send among other threads
    let config_arc = Arc::new(config);
    let config_arc_clone = config_arc.clone();

    let rx_builder = thread::Builder::new().name("receive_thread".to_string());
    let tx_builder = thread::Builder::new().name("send_thread".to_string());

    //set up senders for sender syn packets (sender) and rst packets to close the connection (receiver)
    let syn_sender: TransportSender =
        get_socket(destination_ip).expect("Failed to create tx_sender");
    let rst_sender: TransportSender =
        get_socket(destination_ip).expect("Failed to create rx_sender");

    //get interface to receive syn packet responses
    let rx = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    //receiving packet thread
    let rx_thread = rx_builder.spawn(move || {
        receive_packets(&config_arc, rst_sender, rx);
    });

    //sending packet thread
    let tx_thread = tx_builder.spawn(move || {
        send_packets(&config_arc_clone, syn_sender);
    });

    //joining the handles
    let _ = rx_thread.expect("receive failed").join();
    let _ = tx_thread.expect("send failed").join();
}

//build out socket
fn get_socket(destination: IpAddr) -> Result<TransportSender, String> {
    match destination {
        IpAddr::V4(_) => {
            match transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
            ) {
                Ok((ts, _)) => Ok(ts),
                Err(e) => Err(format!("{}", e)),
            }
        }
        IpAddr::V6(_) => {
            match transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
            ) {
                Ok((ts, _)) => Ok(ts),
                Err(e) => Err(format!("{}", e)),
            }
        }
    }
}

//get the interface to establish a data link channel
fn get_interface(interface_name: Option<String>) -> (NetworkInterface, IpAddr) {
    let interfaces = pnet::datalink::interfaces();

    //checks if interface exists, and if not it lists out available interfaces
    let Some(interface_name) = interface_name else {
        println!("Interface names available:");
        { interfaces.iter() }.for_each(|interface| println!("{}", interface.name));
        std::process::exit(1);
    };

    //set up closure to use
    let interfaces_name_match = |interface: &NetworkInterface| interface.name == interface_name;

    if let Some(interface) = interfaces.into_iter().find(interfaces_name_match) {
        match interface.ips.first() {
            Some(ip_network) => {
                let interface_ip = ip_network.ip();
                (interface, interface_ip)
            }
            None => {
                panic!(
                    "cant get ip for interface \n {} \n interface: \n {}",
                    interface_name, interface,
                );
            }
        }
    } else {
        panic!("no interface named {}", interface_name);
    }
}

//build rst or syn packet
fn build_packet(
    tcp_packet: &mut MutableTcpPacket,
    source_ip: IpAddr,
    dest_ip: IpAddr,
    source_port: u16,
    dest_port: u16,
    syn: bool,
) {
    tcp_packet.set_source(source_port); //ephemeral port
    tcp_packet.set_destination(dest_port); //port being probed
    tcp_packet.set_sequence(0);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_sequence(0);

    //if syn, set syn flag, if rst set rst flag
    if syn {
        tcp_packet.set_sequence(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);
        tcp_packet.set_urgent_ptr(0);
    } else {
        tcp_packet.set_flags(TcpFlags::RST);
    }

    let checksum = match (source_ip, dest_ip) {
        (IpAddr::V4(src), IpAddr::V4(dest)) => {
            ipv4_checksum(&tcp_packet.to_immutable(), &src, &dest)
        }
        (IpAddr::V6(src), IpAddr::V6(dest)) => {
            ipv6_checksum(&tcp_packet.to_immutable(), &src, &dest)
        }
        _ => panic!("cant create socket in get_socket"),
    };
    tcp_packet.set_checksum(checksum);
}

/*

send packets: sends packets to all of the relevant ports

 */

fn send_packets(config: &Config, mut sender: TransportSender) {
    for destination_port in config.ports_to_scan.iter() {
        //get buffer to send
        let mut vec: Vec<u8> = get_buffer(config);
        //create packet
        let mut tcp_packet =
            MutableTcpPacket::new(&mut vec[..]).expect("Failed to create mutable TCP packet");
        //build packet
        build_packet(
            &mut tcp_packet,
            config.interface_ip,
            config.destination_ip,
            config.source_port,
            *destination_port,
            true,
        );

        //send packet
        if let Err(e) = sender.send_to(tcp_packet.to_immutable(), config.destination_ip) {
            eprintln!("Error sending packet: {}", e);
        } else {
            println!(
                "sent syn packet to port {} on host {}",
                destination_port, config.destination_ip
            );
        }
    }
    //sleep to change the all_sent flag
    thread::sleep(config.wait_after_send);
    //mark to true to kill receive_packets loop
    config.all_sent.store(true, Ordering::SeqCst);
}

/*

receive packets : receives packets

 */
fn receive_packets(
    config: &Config,
    mut sender: TransportSender,
    mut rx: Box<dyn DataLinkReceiver>,
) {
    let start = Instant::now();
    //loops over received packets, may not be all our packets
    loop {
        //we got a packet
        match rx.next() {
            //we got a packet
            Ok(packet) => {
                //Build from bottom up the stack, starting with ethernet
                let eth_packet = EthernetPacket::new(packet).unwrap();
                //get the type of packet riding on ethernet packet
                match eth_packet.get_ethertype() {
                    //type of IPv4, we want this
                    EtherTypes::Ipv4 => {
                        let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                        //if next layer up isn't tcp, we don't care
                        if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            //get buffer to have a lifetime outside the function, done for ownership reasons
                            let mut buffer = get_buffer(config);
                            //develop rst packet to send
                            let rst_packet = handle_tcp(
                                ipv4_packet.payload(),
                                config,
                                ipv4_packet.get_source().into(),
                                &mut buffer,
                            );
                            //rst_packet is a Result<Option> so this unwraps it all
                            match rst_packet {
                                Ok(rst_packet) => {
                                    if let Some(rst_packet) = rst_packet {
                                        let _ = sender.send_to(rst_packet, config.destination_ip);
                                    }
                                }
                                Err(e) => {
                                    //prints too much
                                    println!("error {:?}", e)
                                }
                            }
                        }
                    }
                    //type of IPv6, we want this
                    EtherTypes::Ipv6 => {
                        let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();

                        //if next layer up isn't tcp, we don't care
                        if ipv6_packet.get_next_header() == IpNextHeaderProtocols::Tcp {
                            //get buffer to have a lifetime outside the function, done for ownership reasons
                            let mut buffer = get_buffer(config);
                            let rst_packet = handle_tcp(
                                ipv6_packet.payload(),
                                config,
                                ipv6_packet.get_source().into(),
                                &mut buffer,
                            );
                            match rst_packet {
                                Ok(rst_packet) => {
                                    if let Some(rst_packet) = rst_packet {
                                        println!("{:?}", rst_packet.get_source());
                                        println!("{:?}", config.destination_ip);
                                        let _ = sender.send_to(rst_packet, config.destination_ip);
                                    }
                                }
                                Err(e) => {
                                    //oops
                                    println!("error: {:?}", e);
                                }
                            }
                        }
                    }
                    //we dont care, do nothing so we can check breaking condition
                    _ => {}
                }
            }
            //print out if there is an error receiving a packet
            Err(e) => {
                println!("error while receiving packet: {:?}", e)
            }
        }
        //check if all_sent flag is true
        if config.all_sent.load(Ordering::SeqCst)
            //check if timeout is hit
            || Instant::now().duration_since(start) > config.timeout
        {
            break;
        }
    }
}

//handles the tcp packet
fn handle_tcp<'a>(
    ip_payload: &[u8],
    config: &Config,
    ip_addr: IpAddr,
    buffer: &'a mut [u8],
) -> Result<Option<MutableTcpPacket<'a>>, String> {
    //create tcp packet with the ip packet payload
    let tcp_packet =
        TcpPacket::new(ip_payload).ok_or_else(|| "Failed to create TCP packet".to_string())?;

    //if not ours, Ok a None value
    if tcp_packet.get_destination() != config.source_port {
        return Ok(None);
    }

    //build mutable tcp packet with the input buffer
    let mut rst_packet = MutableTcpPacket::new(buffer)
        .ok_or_else(|| "Failed to create mutable TCP packet".to_string())?;

    //check flags
    if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK {
        //Its ours and the port is open
        println!("port {} open on host {}", tcp_packet.get_source(), ip_addr);
        //build rst packet
        build_packet(
            &mut rst_packet,
            config.interface_ip,
            config.destination_ip,
            config.source_port,
            tcp_packet.get_source(),
            false,
        );
        Ok(Some(rst_packet))
    } else if tcp_packet.get_flags() == TcpFlags::RST {
        //packet is ours and port is closed
        /*

        TODO: handle other potential situations

         */
        Err(format!(
            "misc flag {} on port {}",
            tcp_packet.get_flags(),
            tcp_packet.get_source()
        ))
    } else {
        /*
        flag is something we dont handle yet or not relevant

        TODO: handle other potential situations

         */
        Ok(None)
    }
}

//reduce redundancy
fn get_buffer(config: &Config) -> Vec<u8> {
    //check if ipv4 or ipv6
    let header_length = match config.destination_ip {
        IpAddr::V4(_) => IPV4_HEADER_LEN,
        IpAddr::V6(_) => IPV6_HEADER_LEN,
    };
    //get and return buffer of correct length
    let vec: Vec<u8> = vec![0; ETHERNET_HEADER_LEN + header_length + 86];
    vec
}

fn generate_random_sequence(min: u32, max: u32) -> u32 {
    let mut rng = thread_rng();
    rng.gen_range(min..max)
}
