use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::TcpOption;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::tcp::TcpPacket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn main() {
    println!("Hello, world!");
}

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

pub fn build_random_ipv4(partial_packet: &PartialIpv4TCPPacketData, tmp_packet: &mut [u8]) {
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

pub fn build_random_ipv6(partial_packet: &PartialIpv6TCPPacketData, tmp_packet: &mut [u8]) {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 40;

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
            &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
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

        let checksum = pnet::packet::tcp::ipv6_checksum(
            &tcp_header.to_immutable(),
            &partial_packet.iface_ip,
            &partial_packet.destination_ip,
        );
        tcp_header.set_checksum(checksum);
    }
}

pub fn send_tcp_ipv4(destination_ip: Ipv4Addr, interface: String, count: u32) {
    let interfaces = pnet::datalink::interfaces();

    println!("List of Available Interfaces\n");

    for interface in interfaces.iter() {
        let iface_ip = interface.ips.iter().next().map(|x| match x.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
        });

        println!(
            "Interface name: {:?}\nInterface MAC: {:?}\nInterface IP: {:?}\n",
            &interface.name,
            &interface.mac.unwrap(),
            iface_ip
        )
    }

    let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface;
    let interface = interfaces
        .into_iter()
        .filter(interfaces_name_match)
        .next()
        .expect(&format!("could not find interface by name {}", interface));

    let iface_ip = match interface
        .ips
        .iter()
        .nth(0)
        .expect(&format!(
            "the interface {} does not have any IP addresses",
            interface
        ))
        .ip()
    {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
    };

    let partial_packet: PartialIpv4TCPPacketData = PartialIpv4TCPPacketData {
        destination_ip: destination_ip,
        iface_ip,
        iface_name: &interface.name,
        iface_src_mac: &interface.mac.unwrap(),
    };

    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    //v6 0x86DD
    //v4 2048
    tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
        build_random_ipv4(&partial_packet, packet);
    });
    if let Ok(packet) = rx.next() {
        let eth_packet = EthernetPacket::new(packet).unwrap();
        if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
            // Extract the IPv4 packet
            if let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()) {
                // Check if the IP protocol is TCP
                if ipv4_packet.get_next_level_protocol()
                    == pnet::packet::ip::IpNextHeaderProtocols::Tcp
                {
                    // Extract the TCP segment
                    if let Some(tcp_segment) = TcpPacket::new(ipv4_packet.payload()) {
                        // Do something with the TCP segment
                        println!("{:?}", tcp_segment.get_flags());
                        if tcp_segment.get_destination() == *partial_packet.sport
                            && tcp_segment.get_flags() == TcpFlags::SYN + TcpFlags::ACK
                        {
                            println!(
                                "Received TCP packet with source port {}, destination port {}",
                                tcp_segment.get_source(),
                                tcp_segment.get_destination()
                            );
                        }
                    }
                }
            }
        }
    }
}
