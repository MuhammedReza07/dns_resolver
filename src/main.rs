mod conversions;
mod udp_packet;
mod dns_message;

use std::net;

const NAME_SERVER_ADDRESS: (&str, u16) = ("8.8.8.8", 53);
const LOCAL_ADDRESS: (net::Ipv4Addr, u16) = (net::Ipv4Addr::UNSPECIFIED, 0);

fn main() {
    let dns_message: dns_message::DnsMessage = dns_message::DnsMessage {
        header: dns_message::DnsHeader {
            id: 1978,
            response: false,
            operation_code: dns_message::OperationCode::StandardQuery,
            authoritative_answer: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            z: 0,
            response_code: dns_message::ResponseCode::Success,
            question_count: 1,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0
        },
        questions: vec![
            dns_message::DnsQuestion {
                name: String::from("wikipedia.org"),
                question_type: dns_message::QuestionType::A,
                question_class: dns_message::QuestionClass::IN
            },
        ],
        answers: Vec::new(),
        authorities: Vec::new(),
        additional: Vec::new()
    };

    let mut udp_packet = udp_packet::UdpPacket::new();
    dns_message.write_to_udp_packet(&mut udp_packet);
    
    let udp_socket = net::UdpSocket::bind(LOCAL_ADDRESS)
    .expect("Failed to bind a UdpSocket to address.");

    udp_socket.connect(NAME_SERVER_ADDRESS).expect("Failed to connect to name server.");
    udp_socket.send(&udp_packet.buffer).expect("Failed to send message");

    let mut response_packet = udp_packet::UdpPacket::new();
    udp_socket.recv(&mut response_packet.buffer).expect("Failed to read message.");

    println!("{:#?}", dns_message::DnsHeader::read_from_udp_packet(&response_packet));
}