use pnet::datalink::{Channel, NetworkInterface}; //{self, Channel, DataLinkReceiver, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket}; //, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{ipv4_checksum, ipv6_checksum, TcpOption};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket}; //TcpOption
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol, TransportSender};
use rand::{thread_rng, Rng};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr}; //, Ipv6Addr};
pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const ETHERNET_HEADER_LEN: usize = 14;

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut rng = thread_rng();
    let port: u16 = rng.gen_range(1024..65535);
    let dest = "99.86.91.111".parse::<IpAddr>().unwrap();
    //let pi = "192.168.1.3".parse::<IpAddr>().unwrap();
    let ports: Vec<u16> = vec![80, 443, 100];
    let mut socket = get_socket(dest).unwrap();
    let (interface, iface_ip) = get_interface("en0");

    match iface_ip {
        IpAddr::V4(_) => {
            send_packets_ipv4(&mut socket, ports, port, dest, iface_ip);
        }
        IpAddr::V6(_) => {
            send_packets_ipv6(&mut socket, ports, port, dest, iface_ip);
        }
    }
    receive_packets(interface, port);

    Ok(())
}

fn get_socket(destination: IpAddr) -> Result<TransportSender, String> {
    match destination {
        IpAddr::V4(_) => {
            if let Ok((ts, _tr)) = transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
            ) {
                Ok(ts)
            } else {
                panic!("cant get socket v4");
            }
        }
        IpAddr::V6(_) => {
            let (ts, mut _tr) = transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
            )
            .unwrap();
            if let Ok((ts, _tr)) = transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
            ) {
                Ok(ts)
            } else {
                panic!("cant get socket v6");
            }
        }
    }
}

fn send_packets_ipv4(
    ts: &mut TransportSender,
    ports: Vec<u16>,
    source_port: u16,
    dest_ip: std::net::IpAddr,
    source_ip: std::net::IpAddr,
) {
    for dest_port in ports {
        let mut vec: Vec<u8> = vec![0; 66];
        let mut tcp_packet =
            MutableTcpPacket::new(&mut vec[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();
        build_syn_packet(&mut tcp_packet, source_ip, dest_ip, source_port, dest_port);
        let tcp_packet = TcpPacket::new(tcp_packet.packet()).unwrap();
        let _ = ts.send_to(tcp_packet, dest_ip.to_string().parse::<IpAddr>().unwrap());
    }
}

fn send_packets_ipv6(
    ts: &mut TransportSender,
    ports: Vec<u16>,
    source_port: u16,
    dest_ip: std::net::IpAddr,
    source_ip: std::net::IpAddr,
) {
    for dest_port in ports {
        let mut vec: Vec<u8> = vec![0; 86];
        let mut tcp_packet =
            MutableTcpPacket::new(&mut vec[(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN)..]).unwrap();
        build_syn_packet(&mut tcp_packet, source_ip, dest_ip, source_port, dest_port);
        let tcp_packet = TcpPacket::new(tcp_packet.packet()).unwrap();
        let _ = ts.send_to(tcp_packet, dest_ip.to_string().parse::<IpAddr>().unwrap());
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
                    "cant get ip for interfac\n{}\n{}",
                    interface_name, interface
                );
            }
        }
    } else {
        panic!("no interface named {}", interface_name);
    }
}

fn receive_packets(interface: NetworkInterface, s_port: u16) {
    let (mut _t, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    loop {
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
                        if tcp_packet.get_destination() == s_port {
                            if (tcp_packet.get_flags() & (TcpFlags::SYN | TcpFlags::ACK))
                                == (TcpFlags::SYN | TcpFlags::ACK)
                            {
                                println!("{:?} open", tcp_packet.get_source());
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
                        if tcp_packet.get_destination() == s_port {
                            if (tcp_packet.get_flags() & (TcpFlags::SYN | TcpFlags::ACK))
                                == (TcpFlags::SYN | TcpFlags::ACK)
                            {
                                println!("{:?} open", tcp_packet.get_source());
                            } else if tcp_packet.get_flags() == TcpFlags::RST {
                                println!("closed");
                            }
                        }
                    }
                    _ => continue,
                }
            }
            Err(e) => {
                println!("error while receiving packet: {:?}", e)
            }
        }
    }
}

fn build_syn_packet(
    tcp_packet: &mut MutableTcpPacket,
    source_ip: std::net::IpAddr,
    dest_ip: std::net::IpAddr,
    source_port: u16,
    dest_port: u16,
) {
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(dest_port);
    tcp_packet.set_sequence(0);
    tcp_packet.set_flags(TcpFlags::SYN);
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
