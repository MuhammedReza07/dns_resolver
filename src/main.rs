mod conversions;
mod udp_packet;
mod dns_message;

use std::fs;
use std::io::Write;
use std::net;

const LOCAL_ADDRESS: (net::Ipv4Addr, u16) = (net::Ipv4Addr::UNSPECIFIED, 0);
const NAME_SERVER_ADDRESS: (&str, u16) = ("8.8.8.8", 53);

fn main() {
    let dns_message: dns_message::DnsMessage = dns_message::DnsMessage {
        header: dns_message::DnsHeader::default(),
        questions: vec![
            dns_message::DnsQuestion {
                name: String::from("wikipedia.org"),
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
    udp_socket.send(&udp_packet.buffer).expect("Failed to send message");

    let mut response_packet = udp_packet::UdpPacket::new();
    udp_socket.recv(&mut response_packet.buffer).expect("Failed to read message.");

    println!("{:#?}", dns_message::DnsHeader::read_from_udp_packet(&response_packet));
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
                    name: String::from(name),
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
        println!("Query: {}, status: {:?}, domain: {}.", index, dns_message::DnsHeader::read_from_udp_packet(&response_packet).response_code, name);
        logs.write(&format!("Query: {}, status: {:?}, domain: {}.\n", index, dns_message::DnsHeader::read_from_udp_packet(&response_packet).response_code, name).as_bytes())
        .expect("Could not write to logs.");
    })
    .collect();
}