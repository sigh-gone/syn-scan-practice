use pnet::datalink::{Channel, NetworkInterface}; //{self, Channel, DataLinkReceiver, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket}; //, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet; //, MutableIpv4Packet, Ipv4Flags};
                                    //use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket}; //TcpOption
use pnet::packet::Packet;
use pnet::transport::{
    self, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
}; //transport_channel,};
use pnet_packet::tcp::{ipv4_checksum, ipv6_checksum, TcpOption};
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
    let pi = "192.168.1.3".parse::<IpAddr>().unwrap();
    let ports: Vec<u16> = vec![80, 443, 100];
    let mut socket = get_socket(dest).unwrap();

    send_packets_ipv4(&mut socket, ports, port, dest, pi);
    receive_packets_("en0", port);

    Ok(())
}

fn get_socket(destination: IpAddr) -> Result<TransportSender, String> {
    match destination.clone() {
        IpAddr::V4(_) => {
            let (ts, mut _tr) = transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
            )
            .unwrap();
            Ok(ts)
        }
        IpAddr::V6(_) => {
            let (ts, mut _tr) = transport::transport_channel(
                4096,
                TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
            )
            .unwrap();
            Ok(ts)
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
        let tcp_packet = TcpPacket::new(&tcp_packet.packet()).unwrap();
        let _ = ts.send_to(tcp_packet, dest_ip.to_string().parse::<IpAddr>().unwrap());
    }
}

#[warn(dead_code)]
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
        let tcp_packet = TcpPacket::new(&tcp_packet.packet()).unwrap();
        let _ = ts.send_to(tcp_packet, dest_ip.to_string().parse::<IpAddr>().unwrap());
    }
}

/*fn send_ipv4(ports: Vec<u16>, s_port: u16, destination: Ipv4Addr, source: Ipv4Addr) {
    let (mut ts, mut _tr) = transport::transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )
    .unwrap();
    for port in ports {
        let mut vec: Vec<u8> = vec![0; 66];
        let mut tcp_packet =
            MutableTcpPacket::new(&mut vec[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();
        build_syn_packet(&mut tcp_packet, source, destination, s_port, port, 0);
        let tcp_packet = TcpPacket::new(&tcp_packet.packet()).unwrap();
        let _ = ts.send_to(
            tcp_packet,
            destination.to_string().parse::<IpAddr>().unwrap(),
        );
    }
}*/

/*
fn send_packet(packet: MutableTcpPacket, dest_ip: std::net::IpAddr) {
    let (mut ts, mut _tr) = transport::transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )
    .unwrap();

    //transport::send_to(&mut ts, packet, std::net::IpAddr::V4(source_ip), std::net::IpAddr::V4(dest_ip)).unwrap();

    let tcp_packet = TcpPacket::new(&packet.packet()).unwrap();
    let _ = ts.send_to(tcp_packet, dest_ip.to_string().parse::<IpAddr>().unwrap());
}
*/

/*
fn receive_packets(interface_name: &str, s_port: u16, count: i32) {
    let interfaces = pnet::datalink::interfaces();
    let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface_name;

    let interface = interfaces.into_iter().find(interfaces_name_match).unwrap();

    let iface_ip = match interface
        .ips
        .iter()
        .nth(0)
        .unwrap_or_else(|| panic!("the interface {} does not have any IP addresses", interface))
        .ip()
    {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
    };
    let (mut _t, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
                        if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK
                            && tcp_packet.get_destination() == s_port
                        {
                            // process the SYN-ACK packet here
                            println!("{:?}", tcp_packet.get_source()); //.get_destination());
                            println!("in");
                        } else if tcp_packet.get_destination() == s_port
                            && tcp_packet.get_flags() == TcpFlags::RST
                        {
                            println!("closed");
                        }
                    }
                }
            }
            Err(e) => println!("error while receiving packet: {:?}", e),
        }
    }
}
*/

fn receive_packets_(interface_name: &str, s_port: u16) {
    let interfaces = pnet::datalink::interfaces();
    let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface_name;
    let interface = interfaces.into_iter().find(interfaces_name_match).unwrap();

    /*let iface_ip = match interface
        .ips
        .iter()
        .nth(0)
        .unwrap_or_else(|| panic!("the interface {} does not have any IP addresses", interface))
        .ip()
    {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
    };*/

    let (mut _t, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
                        if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK
                            && tcp_packet.get_destination() == s_port
                        {
                            // process the SYN-ACK packet here
                            println!("{:?}", tcp_packet.get_source()); //.get_destination());
                            println!("in");
                        } else if tcp_packet.get_destination() == s_port
                            && tcp_packet.get_flags() == TcpFlags::RST
                        {
                            println!("closed");
                        }
                    }
                } else if eth_packet.get_ethertype() == EtherTypes::Ipv6 {
                    let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();
                    if ipv6_packet.get_next_header() == IpNextHeaderProtocols::Tcp {
                        let tcp_packet = TcpPacket::new(ipv6_packet.payload()).unwrap();
                        if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK
                            && tcp_packet.get_destination() == s_port
                        {
                            // process the SYN-ACK packet here
                            println!("{:?}", tcp_packet.get_source()); //.get_destination());
                            println!("in");
                        } else if tcp_packet.get_destination() == s_port
                            && tcp_packet.get_flags() == TcpFlags::RST
                        {
                            println!("closed");
                        }
                    }
                }
            }
            Err(e) => println!("error while receiving packet: {:?}", e),
        }

    }
}

/*
fn build_syn_packet_<'a>(
    tcp_packet: &mut MutableTcpPacket,
    source_ip: std::net::Ipv4Addr,
    dest_ip: std::net::Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    seq_number: u32,
) {
    //let mut tcp_buffer = [0u8; 20];
    //let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(dest_port);
    tcp_packet.set_sequence(seq_number);
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

    let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &dest_ip);
    tcp_packet.set_checksum(checksum);
}
*/

fn build_syn_packet<'a>(
    tcp_packet: &mut MutableTcpPacket,
    source_ip: std::net::IpAddr,
    dest_ip: std::net::IpAddr,
    source_port: u16,
    dest_port: u16,
) {
    //let mut tcp_buffer = [0u8; 20];
    //let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

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

/*

pub struct PartialIpv4TCPPacketData<'a> {
    pub destination_ip: Ipv4Addr,
    pub iface_ip: Ipv4Addr,
    pub iface_name: &'a String,
    pub iface_src_mac: &'a MacAddr,
    pub sport: &'a u16,
    pub dport: &'a u16,
}

pub struct PartialIpv6TCPPacketData<'a> {
    pub destination_ip: Ipv6Addr,
    pub iface_ip: Ipv6Addr,
    pub iface_name: &'a String,
    pub iface_src_mac: &'a MacAddr,
    pub sport: &'a u16,
    pub dport: &'a u16,
}



fn build_syn_packet<'a>(
    source_ip: std::net::Ipv4Addr,
    dest_ip: std::net::Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    seq_number: u32,
) -> Vec<u8> {
    let mut tcp_buffer = [0u8; 20];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(dest_port);
    tcp_packet.set_sequence(seq_number);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_checksum(0);

    let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &dest_ip);
    tcp_packet.set_checksum(checksum);

    Vec::from(tcp_packet.packet())
}

fn get_interface_ipv4_address() -> Option<std::net::Ipv4Addr> {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        for ip_network in interface.ips {
            println!("{:?}", ip_network);
            if let std::net::IpAddr::V4(ipv4_address) = ip_network.ip() {
                //return Some(ipv4_address);
            }
        }
    }
    None
}

fn get_interface_ipv4_address() -> Option<std::net::Ipv4Addr> {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        for ip_network in interface.ips {
            println!("{:?}", ip_network);
            if let std::net::IpAddr::V4(ipv4_address) = ip_network.ip() {
                //return Some(ipv4_address);
            }
        }
    }
    None
}

pub fn build_tcp_ipv6(partial_packet: &PartialIpv6TCPPacketData, tmp_packet: &mut [u8]) {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV6_HEADER_LEN: usize = 40;

    // Setup Ethernet header
    {
        let mut eth_header =
            MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_destination(MacAddr::broadcast());
        eth_header.set_source(*partial_packet.iface_src_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    // Setup IP header
    {
        let mut ip_header = MutableIpv6Packet::new(
            &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN)],
        )
        .unwrap();

        ip_header.set_version(6);
        ip_header.set_flow_label(0);
        ip_header.set_payload_length(0);
        ip_header.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_header.set_hop_limit(64);
        ip_header.set_source(partial_packet.iface_ip);
        ip_header.set_destination(partial_packet.destination_ip);
    }

    // Setup TCP header
    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV6_HEADER_LEN)..])
                .unwrap();

        tcp_header.set_source(*partial_packet.sport);
        tcp_header.set_destination(*partial_packet.dport);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(8);
        tcp_header.set_sequence(0);

        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);

        let checksum = pnet::packet::tcp::ipv6_checksum(
            &tcp_header.to_immutable(),
            &partial_packet.iface_ip,
            &partial_packet.destination_ip,
        );
        tcp_header.set_checksum(checksum);
    }
}


pub fn build_tcp_ipv4(partial_packet: &PartialIpv4TCPPacketData, tmp_packet: &mut [u8]) {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;

    // Setup Ethernet header
    {
        let mut eth_header =
            MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_destination(MacAddr::broadcast());
        eth_header.set_source(*partial_packet.iface_src_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    // Setup IP header
    {
        let mut ip_header = MutableIpv4Packet::new(
            &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
        )
        .unwrap();
        ip_header.set_header_length(69);
        ip_header.set_total_length(52);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(partial_packet.iface_ip);
        ip_header.set_destination(partial_packet.destination_ip);
        ip_header.set_identification(rand::random::<u16>());
        ip_header.set_ttl(64);
        ip_header.set_version(4);
        ip_header.set_flags(Ipv4Flags::DontFragment);

        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    // Setup TCP header
    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..])
                .unwrap();

        tcp_header.set_source(*partial_packet.sport);
        tcp_header.set_destination(*partial_packet.dport);

        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(8);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_sequence(0);

        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);

        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &partial_packet.iface_ip,
            &partial_packet.destination_ip,
        );
        tcp_header.set_checksum(checksum);
    }
}



*/
