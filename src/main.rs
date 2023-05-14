use pnet::datalink::{Channel, NetworkInterface}; //{self, Channel, DataLinkReceiver, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket}; //, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet; //, MutableIpv4Packet, Ipv4Flags};
                                    //use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket}; //TcpOption
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol}; //transport_channel,};
use pnet_packet::tcp::ipv4_checksum;
use rand::{thread_rng, Rng};
use std::net::{IpAddr, Ipv4Addr}; //, Ipv6Addr};

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut rng = thread_rng();
    let port: u16 = rng.gen_range(1024..65535);
    let public_ip = public_ip::addr().await.unwrap();
    let pi = public_ip.to_string().parse::<Ipv4Addr>().unwrap();
    let dest = "99.86.91.111".parse::<Ipv4Addr>().unwrap();
    let packet = build_syn_packet(pi, dest, port, 443, 0);

    send_packet(packet, dest);
    receive_packets(port, 16);

    Ok(())
}

fn send_packet(packet: Vec<u8>, dest_ip: std::net::Ipv4Addr) {
    let (mut ts, mut _tr) = transport::transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )
    .unwrap();

    //transport::send_to(&mut ts, packet, std::net::IpAddr::V4(source_ip), std::net::IpAddr::V4(dest_ip)).unwrap();
    let arr = demo(packet);
    let tcp_packet = TcpPacket::new(&arr).unwrap();
    let _ = ts.send_to(tcp_packet, dest_ip.to_string().parse::<IpAddr>().unwrap());
}

fn demo<T>(v: Vec<T>) -> [T; 20]
where
    T: Copy,
{
    let slice = v.as_slice();
    let array: [T; 20] = match slice.try_into() {
        Ok(ba) => ba,
        Err(_) => panic!("Expected a Vec of length {} but it was {}", 32, v.len()),
    };
    array
}

fn receive_packets(s_port: u16, count: i32) {
    let interfaces = pnet::datalink::interfaces();
    let interfaces_name_match = |iface: &NetworkInterface| iface.name == "en0";

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
                        } else {
                            // println!("{:?}", tcp_packet.get_flags());
                        }
                    }
                }
            }
            Err(e) => println!("error while receiving packet: {:?}", e),
        }
    }
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
