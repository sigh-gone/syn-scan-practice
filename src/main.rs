/*

usings

 */
use pnet::datalink::{Channel, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{ipv4_checksum, ipv6_checksum, TcpOption};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket}; //TcpOption
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol, TransportSender};
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Clone)]
pub struct Config {
    interface_ip: IpAddr,
    source_port: u16,
    destination_ip: IpAddr,
    ports_to_scan: Vec<u16>,
    timeout: Duration,
    wait_after_send: Duration,
    all_sent: Arc<AtomicBool>,
}

fn main() {
    //setting up values for new config and an interface to send into receive_packets
    let interface_name = std::env::args().nth(1);
    let destination_ip: IpAddr = "127.0.0.1".parse().expect("Invalid IP address");
    let ports_to_scan: Vec<u16> = vec![80, 443, 53];
    let (interface, source_ip): (NetworkInterface, IpAddr) = get_interface(interface_name);
    let timeout: Duration = Duration::from_secs(1);
    let wait_after_send: u64 = 5;

    //config
    let config: Config = Config::new(
        destination_ip,
        ports_to_scan,
        source_ip,
        timeout,
        wait_after_send,
    );
    //sending to another thread
    let config_clone = config.clone();

    //set up senders for sender syn packets (sender) and rst packets (receiver)
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

    //receiving thread
    let rx_thread = thread::spawn(move || {
        receive_packets(config_clone, rst_sender, rx);
    });

    //sending thread
    let tx_thread = thread::spawn(move || {
        send_packets(config, syn_sender);
    });

    //joining the handles
    let _ = rx_thread.join();
    let _ = tx_thread.join();
}

//build out config
impl Config {
    pub fn new(
        destination_ip: IpAddr,
        ports_to_scan: Vec<u16>,
        source_ip: IpAddr,
        timeout: Duration,
        wait_after_send: u64,
    ) -> Self {
        let mut rng: ThreadRng = thread_rng();
        let source_port: u16 = rng.gen_range(10024..65535);
        Self {
            interface_ip: source_ip,
            source_port,
            destination_ip,
            ports_to_scan,
            timeout,
            wait_after_send: Duration::from_secs(wait_after_send),
            all_sent: Arc::new(AtomicBool::new(false)),
        }
    }
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

//get the interface to establish a datalink channel
fn get_interface(interface_name: Option<String>) -> (NetworkInterface, IpAddr) {
    let interfaces = pnet::datalink::interfaces();

    let Some(interface_name) = interface_name else {
        println!("Interface names available:");
        { interfaces.iter() }.for_each(|iface| println!("{}", iface.name));
        std::process::exit(1);
    };

    let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface_name;

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
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(dest_port);
    tcp_packet.set_sequence(0);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_sequence(0);
    tcp_packet.set_options(&[
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::nop(),
        TcpOption::nop(),
        TcpOption::wscale(7),
    ]);
    if syn {
        tcp_packet.set_flags(TcpFlags::SYN);
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
        _ => return, // TODO: Panic?
    };
    tcp_packet.set_checksum(checksum);
}

/*

send sockets

 */

fn send_packets(config: Config, mut sender: TransportSender) {
    let header_length = match config.destination_ip {
        IpAddr::V4(_) => IPV4_HEADER_LEN,
        IpAddr::V6(_) => IPV6_HEADER_LEN,
    };

    for destination_port in config.ports_to_scan {
        let mut vec: Vec<u8> = vec![0; ETHERNET_HEADER_LEN + header_length + 86];
        let mut tcp_packet =
            MutableTcpPacket::new(&mut vec[..]).expect("Failed to create mutable TCP packet");
        build_packet(
            &mut tcp_packet,
            config.interface_ip,
            config.destination_ip,
            config.source_port,
            destination_port,
            true,
        );

        if let Err(e) = sender.send_to(tcp_packet.to_immutable(), config.destination_ip) {
            eprintln!("Error sending packet: {}", e);
        } else {
            println!("sent {:?}", destination_port);
        }
    }
    thread::sleep(config.wait_after_send);
    config.all_sent.store(true, Ordering::SeqCst)
}

/*

receive packets

 */
fn receive_packets(config: Config, mut sender: TransportSender, mut rx: Box<dyn DataLinkReceiver>) {
    let start = Instant::now();
    loop {
        //doesnt get in here
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();

                match eth_packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                        if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                            continue;
                        }

                        let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
                        if tcp_packet.get_destination() == config.source_port
                            && tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK
                        {
                            let header_length = match config.destination_ip {
                                IpAddr::V4(_) => IPV4_HEADER_LEN,
                                IpAddr::V6(_) => IPV6_HEADER_LEN,
                            };
                            println!(
                                "port {} open on host {}",
                                tcp_packet.get_source(),
                                ipv4_packet.get_source()
                            );
                            let mut vec: Vec<u8> =
                                vec![0; ETHERNET_HEADER_LEN + header_length + 86];
                            let mut rst_packet = MutableTcpPacket::new(&mut vec[..])
                                .expect("Failed to create mutable TCP packet");

                            build_packet(
                                &mut rst_packet,
                                config.interface_ip,
                                config.destination_ip,
                                config.source_port,
                                tcp_packet.get_source(),
                                false,
                            );
                            let _ = sender.send_to(rst_packet, config.destination_ip);
                        } else if tcp_packet.get_destination() == config.source_port
                            && tcp_packet.get_flags() == TcpFlags::RST
                        {
                            println!("{:?}, closed", tcp_packet.get_source());
                        } else if tcp_packet.get_destination() == config.source_port {
                            println!("extra flag {:?}", tcp_packet.get_flags());
                        }
                    }
                    EtherTypes::Ipv6 => {
                        let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();
                        if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Tcp {
                            continue;
                        }

                        let tcp_packet = TcpPacket::new(ipv6_packet.payload()).unwrap();
                        if tcp_packet.get_destination() == config.source_port {
                            if (tcp_packet.get_flags() & (TcpFlags::SYN | TcpFlags::ACK))
                                == (TcpFlags::SYN | TcpFlags::ACK)
                            {
                                println!("{:?} open", tcp_packet.get_source());
                            } else if tcp_packet.get_flags() == TcpFlags::RST {
                                println!("closed");
                            }
                        }
                    }
                    _ => {
                        continue;
                    }
                }
            }
            Err(e) => {
                println!("error while receiving packet: {:?}", e)
            }
        }
        if config.all_sent.load(Ordering::SeqCst)
            || Instant::now().duration_since(start) > config.timeout
        {
            break;
        }
    }
}
