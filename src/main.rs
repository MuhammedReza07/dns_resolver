/// Module containing conversion functionality for primitives not provided
/// by the standard library, such as the conversion u32 -> u8.
mod conversions;

/// Module containing utilities for working with DNS queries, such as specialised
/// structs (e.g. DnsHeader, DnsQuestion, etc.), and the functionality needed to both
/// read and write them from/to a UDP packet.
mod dns_message;

/// Module containing utilities for handling a DNS-compatible UDP packet, i.e.
/// a UDP packet of size 512 bytes. The module's functionality is specifically
/// adapted to the DNS protocol and is therefore unsuitable for use in non-DNS
/// applications.
mod udp_packet;

use std::str::FromStr;
use std::net;

const LOCAL_ADDRESS: (net::Ipv4Addr, u16) = (net::Ipv4Addr::UNSPECIFIED, 0);
const NAME_SERVER_ADDRESS: (&str, u16) = ("8.8.8.8", 53);

fn main() -> Result<(), udp_packet::UdpPacketIoError> {
    let dns_message: dns_message::DnsMessage = dns_message::DnsMessage {
        header: dns_message::DnsHeader::default(),
        questions: vec![
            dns_message::DnsQuestion {
                name: udp_packet::DomainName::from_str("www.mit.edu")?,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    
    let mut udp_packet: udp_packet::UdpPacket = udp_packet::UdpPacket::new();
    dns_message.write_to_udp_packet(&mut udp_packet);
    
    let udp_socket = net::UdpSocket::bind(LOCAL_ADDRESS)
    .expect("Failed to bind a UdpSocket to address.");
    udp_socket.connect(NAME_SERVER_ADDRESS).expect("Failed to connect to name server.");

    udp_packet.send(&udp_socket)?;
    let mut response_packet: udp_packet::UdpPacket = udp_packet::UdpPacket::new();
    response_packet.recv(&udp_socket)?;

    let decoded_message = dns_message::DnsMessage::read_from_udp_packet(&mut response_packet);
    println!("{}", decoded_message);

    Ok(())
}