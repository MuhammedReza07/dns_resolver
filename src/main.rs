use dns_resolver::{dns_message, udp_packet};
use std::env;
use std::str::FromStr;
use std::net;

const LOCAL_ADDRESS: (net::Ipv4Addr, u16) = (net::Ipv4Addr::UNSPECIFIED, 0);
const NAME_SERVER_ADDRESS: (&str, u16) = ("8.8.8.8", 53);
const ACTIVATE_LOGGING: bool = true;

// Grammar: <Operation code> <Question class> <Question type> <Domain name>

#[derive(Debug)]
struct Arguments {
    operation_code: dns_message::OperationCode,
    question_class: dns_message::CombinedClass,
    question_type: dns_message::CombinedType,
    domain_name: udp_packet::DomainName
}

// TODO: Replace the *::Unknown here with some other member indicating an error.
impl Arguments {
    fn get() -> udp_packet::Result<Self> {
        let env_args: Vec<String> = env::args().collect();
        if env_args.len() != 5 {
            panic!("Must supply 4 arguments.")
        }
        let arguments = Self {
            operation_code: FromStr::from_str(env_args[1].to_ascii_uppercase().as_str()).unwrap(),
            question_class: FromStr::from_str(env_args[2].to_uppercase().as_str()).unwrap(),
            question_type: FromStr::from_str(env_args[3].to_uppercase().as_str()).unwrap(),
            domain_name: udp_packet::DomainName::from_str(env_args[4].as_str())?
        };
        Ok(arguments)
    }
}

fn main() -> udp_packet::Result<()> {
    let arguments = Arguments::get()?;
    let dns_message: dns_message::DnsMessage = dns_message::DnsMessage {
        header: dns_message::DnsHeader {
            operation_code: arguments.operation_code,
            ..Default::default()
        },
        questions: vec![
            dns_message::DnsQuestion {
                name: arguments.domain_name,
                question_class: arguments.question_class,
                question_type: arguments.question_type
            },
        ],
        ..Default::default()
    };
    
    let mut udp_packet: udp_packet::UdpPacket = udp_packet::UdpPacket::new();
    dns_message.write_to_udp_packet(&mut udp_packet)?;
    
    let udp_socket = net::UdpSocket::bind(LOCAL_ADDRESS)
    .expect("Failed to bind a UdpSocket to address.");
    udp_socket.connect(NAME_SERVER_ADDRESS).expect("Failed to connect to name server.");

    udp_packet.send(&udp_socket)?;
    let mut response_packet: udp_packet::UdpPacket = udp_packet::UdpPacket::new();
    response_packet.recv(&udp_socket)?;

    let decoded_message = dns_message::DnsMessage::read_from_udp_packet(&mut response_packet)?;
    println!("{}", decoded_message);
    if ACTIVATE_LOGGING {
        std::fs::write("./logs.txt", format!("{:#?}", decoded_message))
        .expect("Failed to log raw output.");
    }

    Ok(())
}