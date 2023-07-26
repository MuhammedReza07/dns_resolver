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

use std::fs;
use std::io::Write;
use std::net;
use std::str::FromStr;

const LOCAL_ADDRESS: (net::Ipv4Addr, u16) = (net::Ipv4Addr::UNSPECIFIED, 0);
const NAME_SERVER_ADDRESS: (&str, u16) = ("8.8.8.8", 53);

fn main() -> Result<(), udp_packet::UdpPacketIoError> {
    let dns_message: dns_message::DnsMessage = dns_message::DnsMessage {
        header: dns_message::DnsHeader::default(),
        questions: vec![
            dns_message::DnsQuestion {
                name: udp_packet::DomainName::from_str("google.com")?,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let mut udp_packet: udp_packet::UdpPacket = udp_packet::UdpPacket::new();
    dns_message.write_to_udp_packet(&mut udp_packet);
    println!("{}", udp_packet.position);
    
    let udp_socket = net::UdpSocket::bind(LOCAL_ADDRESS)
    .expect("Failed to bind a UdpSocket to address.");
    udp_socket.connect(NAME_SERVER_ADDRESS).expect("Failed to connect to name server.");

    udp_packet.send(&udp_socket)?;
    let mut response_packet: udp_packet::UdpPacket = udp_packet::UdpPacket::new();
    response_packet.recv(&udp_socket)?;

    println!("{:#?}", dns_message::DnsHeader::read_from_udp_packet(&mut response_packet));
    Ok(())
}

fn generate_test_dataset() {
    let mut responses = fs::File::options()
    .write(true)
    .truncate(true)
    .open("responses.txt")
    .expect("Failed to open output file");

    let mut logs = fs::File::options()
    .write(true)
    .truncate(true)
    .open("logs.txt")
    .expect("Failed to open the logging file.");

    let udp_socket = net::UdpSocket::bind(LOCAL_ADDRESS)
        .expect("Failed to bind a UdpSocket to address.");

    udp_socket.connect(NAME_SERVER_ADDRESS).expect("Failed to connect to name server.");

    let _: Vec<_> = fs::read_to_string("domain_list.txt")
    .expect("Failed to read file")
    .lines()
    .enumerate()
    .map(|(index, name)| {
        let dns_message: dns_message::DnsMessage = dns_message::DnsMessage {
            header: dns_message::DnsHeader::default(),
            questions: vec![
                dns_message::DnsQuestion {
                    name: udp_packet::DomainName::from_str(name).expect("Failed to construct DomainName."),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut udp_packet: udp_packet::UdpPacket = udp_packet::UdpPacket::new();
        dns_message.write_to_udp_packet(&mut udp_packet);
    
        udp_socket.send(&udp_packet.buffer).expect("Failed to send message");

        let mut response_packet = udp_packet::UdpPacket::new();
        udp_socket.recv(&mut response_packet.buffer).expect("Failed to read message.");

        responses.write_all(&response_packet.buffer).expect("Failed to write to output file.");
        println!(
            "Query: {}, status: {:?}, truncated: {}, domain: {}.", 
            index, 
            dns_message::DnsHeader::read_from_udp_packet(&mut response_packet).response_code,
            dns_message::DnsHeader::read_from_udp_packet(&mut response_packet).truncated, name
        );
        logs.write(
            &format!("Query: {}, status: {:?}, truncated: {}, domain: {}.\n", 
            index, dns_message::DnsHeader::read_from_udp_packet(&mut response_packet).response_code, 
            dns_message::DnsHeader::read_from_udp_packet(&mut response_packet).truncated, name
        )
            .as_bytes()
        )
        .expect("Could not write to logs.");
    })
    .collect();
}