use pnet::datalink::{Channel, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{ipv4_checksum, ipv6_checksum, TcpOption};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket}; //TcpOption
use pnet::packet::Packet;
use pnet::transport::{
    self, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
};
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Clone)]
pub struct Config {
    //interface: NetworkInterface,
    interface_ip: IpAddr,
    source_port: u16,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    ports_to_scan: Vec<u16>,
    timeout: Duration,
}

fn main() {
    let destination_ip: IpAddr = "54.230.18.118".parse().expect("Invalid IP address");
    let ports_to_scan: Vec<u16> = vec![80, 443, 100];
    let (interface, source_ip): (NetworkInterface, IpAddr) = get_interface("en0");
    let timeout = Duration::from_secs(1);
    let config: Config = Config::new(destination_ip, ports_to_scan, source_ip, timeout);
    let config_clone = config.clone();

    let (tx, rx): (TransportSender, TransportReceiver) =
        get_socket(destination_ip).expect("Failed to create socket");
    let (rx_sender, _): (TransportSender, TransportReceiver) =
        get_socket(destination_ip).expect("Failed to create socket");

    let (mut _tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let h = thread::spawn(move || {
        receive_packets(config_clone, rx_sender, rx);
    });
    send_packets(config, tx);
    let _ = h.join();
}

impl Config {
    pub fn new(
        destination_ip: IpAddr,
        ports_to_scan: Vec<u16>,
        source_ip: IpAddr,
        timeout: Duration,
    ) -> Self {
        let mut rng: ThreadRng = thread_rng();
        let source_port: u16 = rng.gen_range(10024..65535);
        Self {
            interface_ip: source_ip,
            source_port,
            source_ip,
            destination_ip,
            ports_to_scan,
            timeout,
        }
    }
}

fn get_socket(destination: IpAddr) -> Result<(TransportSender, TransportReceiver), String> {
    match destination {
        IpAddr::V4(_) => {
            match transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
            ) {
                Ok((ts, tr)) => Ok((ts, tr)),
                Err(e) => Err(format!("{}", e)),
            }
        }
        IpAddr::V6(_) => {
            if let Ok((ts, tr)) = transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
            ) {
                Ok((ts, tr))
            } else {
                panic!(
                    "Failed to create socket for IPv6 destination: {:?}",
                    destination
                );
            }
        }
    }
}

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
            println!("sent");
        }
    }
}

fn get_interface(interface_name: &str) -> (NetworkInterface, IpAddr) {
    let interfaces = pnet::datalink::interfaces();
    let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface_name;

    if let Some(interface) = interfaces.into_iter().find(interfaces_name_match) {
        match interface.ips.first() {
            Some(ip_network) => {
                let ip = ip_network.ip();
                (interface, ip)
            }
            None => {
                panic!(
                    "cant get ip for interface \n {} \n interface: \n {}",
                    interface_name,
                    interface.to_string()
                );
            }
        }
    } else {
        panic!("no interface named {}", interface_name);
    }
}

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
                        if tcp_packet.get_destination() == config.source_port {
                            /*if (tcp_packet.get_flags() & (TcpFlags::SYN | TcpFlags::ACK))
                                == (TcpFlags::SYN | TcpFlags::ACK)
                            {*/
                            if tcp_packet.get_flags()
                                == pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK
                            {
                                let header_length = match config.destination_ip {
                                    IpAddr::V4(_) => IPV4_HEADER_LEN,
                                    IpAddr::V6(_) => IPV6_HEADER_LEN,
                                };
                                println!("{:?} open", tcp_packet.get_source());
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
                            } else if tcp_packet.get_flags() == TcpFlags::RST {
                                println!("closed");
                            } else {
                                println!("{:?}", tcp_packet.get_flags());
                            }
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
        if Instant::now().duration_since(start) > config.timeout {
            break;
        }
    }
}

fn build_packet(
    tcp_packet: &mut MutableTcpPacket,
    source_ip: std::net::IpAddr,
    dest_ip: std::net::IpAddr,
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

    match source_ip {
        IpAddr::V4(src) => {
            if let Ok(dest_ip) = dest_ip.to_string().parse::<Ipv4Addr>() {
                let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &src, &dest_ip);
                tcp_packet.set_checksum(checksum);
            }
        }
        IpAddr::V6(src) => {
            if let Ok(dest_ip) = dest_ip.to_string().parse::<Ipv6Addr>() {
                let checksum = ipv6_checksum(&tcp_packet.to_immutable(), &src, &dest_ip);
                tcp_packet.set_checksum(checksum);
            }
        }
    }
}
