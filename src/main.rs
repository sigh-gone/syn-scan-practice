use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{self, transport_channel, TransportChannelType, TransportProtocol};
use pnet_packet::tcp::ipv4_checksum;
use rand::{thread_rng, Rng};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

#[tokio::main]
async fn main() -> Result<(), String> {
    /*send_tcp_ipv4(
        "99.86.91.111".parse::<Ipv4Addr>().unwrap(),
        "en0".to_string(),
    )
    .await;*/
    //build_syn_packet(, dest_ip, source_port, dest_port, seq_number)
    Ok(())

    //let s = get_interface_ipv4_address().unwrap();
    //println!("{:?}", s.to_string());
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

pub async fn send_tcp_ipv4(destination_ip: Ipv4Addr, interface: String) {
    let interfaces = pnet::datalink::interfaces();
    let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface;

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

    let mut rng = thread_rng();
    let port: u16 = rng.gen_range(1024..65535);
    //let resp = reqwest::get("https://api.ipify.org").await.unwrap();
    //let public_ip = resp.text().await.unwrap();
    let public_ip = public_ip::addr().await.unwrap();
    let pi = public_ip.to_string().parse::<Ipv4Addr>().unwrap();

    println!("{:?}", iface_ip.to_string());
    let sport: u16 = port;
    let dport: u16 = 443;
    let partial_packet: PartialIpv4TCPPacketData = PartialIpv4TCPPacketData {
        destination_ip,
        iface_ip: pi,
        iface_name: &interface.name,
        iface_src_mac: &interface.mac.unwrap(),
        sport: &sport,
        dport: &dport,
    };

    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    //this size would be the same
    tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
        build_tcp_ipv4(&partial_packet, packet);
    });

    match rx.next() {
        Ok(packet) => {
            let eth_packet = EthernetPacket::new(packet).unwrap();
            if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
                    if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK
                        && tcp_packet.get_destination() == *partial_packet.sport
                    {
                        // process the SYN-ACK packet here
                        println!("in");
                    } else {
                        println!("{:?}", tcp_packet.get_flags());
                    }
                }
            }
        }
        Err(e) => println!("error while receiving packet: {:?}", e),
    }
    /*     loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                    let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
                        if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK
                            && tcp_packet.get_destination() == *partial_packet.sport
                        {
                            // process the SYN-ACK packet here
                            println!("in");
                        } else {
                            println!("{:?}", tcp_packet.get_flags());
                        }
                    }
                }
            }
            Err(e) => println!("error while receiving packet: {:?}", e),
        }
    }
    */
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

/*fn smoke() {
    // Set up the socket
    let (mut tcp_sender, rx) = transport_channel(
        4096,
        TransportChannelType::Layer4(pnet::transport::TransportProtocol::Ipv4(
            pnet::packet::ip::IpNextHeaderProtocols::Tcp,
        )),
    )
    .unwrap();
    tcp_sender.send_to(packet, destination)
}
*/

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

fn send_packet(packet: Vec<u8>, source_ip: std::net::Ipv4Addr, dest_ip: std::net::Ipv4Addr) {
    let (mut ts, mut tr) = transport::transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )
    .unwrap();
    //transport::send_to(&mut ts, packet, std::net::IpAddr::V4(source_ip), std::net::IpAddr::V4(dest_ip)).unwrap();
    let arr = vector_as_u8_4_array(packet);
    let tcp_packet = TcpPacket::new(&arr).unwrap();
    ts.send_to(tcp_packet, dest_ip.to_string().parse::<IpAddr>().unwrap());
}

#[macro_use]
macro_rules! convert_u8vec_to_array {
    ($container:ident, $size:expr) => {{
        if $container.len() != $size {
            None
        } else {
            use std::mem;
            let mut arr: [_; $size] = unsafe { mem::uninitialized() };
            for element in $container.into_iter().enumerate() {
                let old_val = mem::replace(&mut arr[element.0], element.1);
                unsafe { mem::forget(old_val) };
            }
            Some(arr)
        }
    }};
}

fn vector_as_u8_4_array(vector: Vec<u8>) -> [u8; 20] {
    let mut arr = [0u8; 20];
    for i in (0..20) {
        arr[i] = vector[i];
    }
    arr
}
