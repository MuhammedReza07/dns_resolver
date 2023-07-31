use crate::conversions;
use std::fmt::Display;
use std::str::FromStr;
use std::net;
use crate::udp_packet;

const DNS_HEADER_LENGTH_BYTES: usize = 12;      // First offset where a NAME (String value) occurs in packets.
const QUESTION_COUNT: u16 = 1;                  // The default QDCOUNT field of the DNS header.
const RECURSION_DESIRED: bool = true;           // The default RD field of the DNS header.
pub const TEST_DOMAIN: &str = "example.com";    // the "example" domains are reserved for testing.

#[derive(Debug, PartialEq)]
pub enum ResponseData {
    Ipv4Address(net::Ipv4Addr),
    DomainName(udp_packet::DomainName),
    Unknown
}

impl ResponseData {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ipv4Address(addr) => addr.octets().to_vec(),
            Self::DomainName(name) => name.0.to_vec(),
            Self::Unknown => "Unknown/unimplemented".as_bytes().to_vec()
        }
    }
}

impl Display for ResponseData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Address(addr) => write!(f, "{}", addr),
            Self::DomainName(name) => write!(f, "{}", name),
            Self::Unknown => write!(f, "Unknown/unimplemented")
        }
    }
}

// Represented by 4 bits
#[derive(Debug, Default, PartialEq)]
pub enum OperationCode {
    #[default]
    StandardQuery,  // QUERY, 0
    InverseQuery,   // IQUERY, 1
    Status,         // STATUS, 2
    Unknown(u16)    // Any
}

impl OperationCode {
    fn from_u16(num: u16) -> Self {
        match num {
            0 => Self::StandardQuery,
            1 => Self::InverseQuery,
            2 => Self::Status,
            _ => Self::Unknown(num)
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            Self::StandardQuery => 0,
            Self::InverseQuery => 1,
            Self::Status => 2,
            Self::Unknown(num) => *num
        }
    }
}

// Represented by 4 bits
#[derive(Debug, Default, PartialEq)]
pub enum ResponseCode {
    #[default]
    Success,            // 0, no error
    FormatError,        // 1, DNS packet could not be interpreted due to malformed a query
    ServerFailure,      // 2, DNS packet could not be interpreted due to internal name server error
    NameError,          // 3, Domain name does not exist, only from authoritative name servers
    NotImplemented,     // 4, the requested functionality has not been implemented by the server
    Refused,            // 5, the name server refuses to respond for some reason
    Unknown(u16)        // Any, unimplemented
}

impl ResponseCode {
    fn from_u16(num: u16) -> Self {
        match num {
            0 => Self::Success,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            _ => Self::Unknown(num)
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            Self::Success => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::Unknown(num) => *num
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum RecordType {
    #[default]
    A,
    CNAME,
    Unknown(u16)
}

impl RecordType {
    fn to_u16(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::CNAME => 5,
            Self::Unknown(num) => *num
        }
    }

    fn from_u16(num: u16) -> Self {
        match num {
            1 => Self::A,
            5 => Self::CNAME,
            _ => Self::Unknown(num)
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum RecordClass {
    #[default]
    IN,
    Unknown(u16)
}

impl RecordClass {
    fn to_u16(&self) -> u16 {
        match self {
            Self::IN => 1,
            Self::Unknown(num) => *num
        }
    }

    fn from_u16(num: u16) -> Self {
        match num {
            1 => Self::IN,
            _ => Self::Unknown(num)
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum QuestionType {
    RecordType(RecordType),
    Unknown(u16)
}

impl Display for QuestionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecordType(record_type) => write!(f, "{:?}", record_type),
            Self::Unknown(_) => write!(f, "{:?}", self)
        }
    }
}

impl Default for QuestionType {
    fn default() -> Self {
        Self::RecordType(RecordType::A)
    }
}

impl QuestionType {
    fn to_u16(&self) -> u16 {
        match self {
            Self::RecordType(record_type) => record_type.to_u16(),
            Self::Unknown(num) => *num
        }
    }

    fn from_u16(num: u16) -> Self {
        match num {
            1 | 5 => Self::RecordType(RecordType::from_u16(num)),
            _ => Self::Unknown(num)
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum QuestionClass {
    RecordClass(RecordClass),
    Unknown(u16)
}

impl Display for QuestionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecordClass(record_class) => write!(f, "{:?}", record_class),
            Self::Unknown(_) => write!(f, "{:?}", self)
        }
    }
}

impl Default for QuestionClass {
    fn default() -> Self {
        Self::RecordClass(RecordClass::IN)
    }
}

impl QuestionClass {
    fn to_u16(&self) -> u16 {
        match self {
            Self::RecordClass(record_class) => record_class.to_u16(),
            Self::Unknown(num) => *num
        }
    }

    fn from_u16(num: u16) -> Self {
        match num {
            1 => Self::RecordClass(RecordClass::from_u16(num)),
            _ => Self::Unknown(num)
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsHeader {
    pub id: u16, // 16 bits, packet identifier

    // 16 bits, header flags
    pub response: bool,                     // 1 bit, set (1) on responses, unset (0) on queries
    pub operation_code: OperationCode,      // 4 bits, indicates the kind of query in the packet
    pub authoritative_answer: bool,         // 1 bit, set if the responding name server is a domain authority
    pub truncated: bool,                    // 1 bit, set if the message's content has been truncated due to being too long
    pub recursion_desired: bool,            // 1 bit, set if the resolver desires recursive service
    pub recursion_available: bool,          // 1 bit, set if the name server is willing to provide recursive service
    pub z: u16,                             // 3 bits, reserved and must be unset
    pub response_code: ResponseCode,        // 4 bits, indicates the response status of the name server

    // Metadata about the other sections of the DNS message
    pub question_count: u16,                // 16 bits
    pub answer_count: u16,                  // 16 bits
    pub authority_count: u16,               // 16 bits
    pub additional_count: u16               // 16 bits
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self { 
            id: Default::default(), 
            response: Default::default(), 
            operation_code: Default::default(), 
            authoritative_answer: Default::default(), 
            truncated: Default::default(), 
            recursion_desired: RECURSION_DESIRED,
            recursion_available: Default::default(), 
            z: Default::default(), 
            response_code: Default::default(), 
            question_count: QUESTION_COUNT, 
            answer_count: Default::default(), 
            authority_count: Default::default(), 
            additional_count: Default::default() 
        }
    }
}

impl DnsHeader {
    fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) {
        if udp_packet.position >= DNS_HEADER_LENGTH_BYTES {
            panic!("DNS header can only be written within bytes 0-11 (DNS_HEADER_LENGTH_BYTES - 1) of DnsMessage.buffer.")
        }
        let flag_bytes = conversions::u16_to_u8(self.response_code.to_u16()
        | (self.z << 4)
        | (conversions::bool_to_u16(self.recursion_available) << 7)
        | (conversions::bool_to_u16(self.recursion_desired) << 8)
        | (conversions::bool_to_u16(self.truncated) << 9)
        | (conversions::bool_to_u16(self.authoritative_answer) << 10)
        | (self.operation_code.to_u16() << 11)
        | (conversions::bool_to_u16(self.response) << 15));
        let slice = [
            conversions::u16_to_u8(self.id),                // id field
            flag_bytes,                                         // header flags, 
            conversions::u16_to_u8(self.question_count),    // question count field
            conversions::u16_to_u8(self.answer_count),      // answer count field
            conversions::u16_to_u8(self.authority_count),   // authority count field
            conversions::u16_to_u8(self.additional_count)   // additional count field
        ].concat();
        udp_packet.write_from_slice(&slice);
    }

    fn read_from_udp_packet(udp_packet: &mut udp_packet::UdpPacket) -> Self {
        let id = udp_packet.read_u16();
        let flag_bytes = udp_packet.read_u16();
        // Flag bitfield format:
        // 0b 1000 0000 0000 0000 (0x8000) response
        // 0b 0111 1000 0000 0000 (0x7800) operation_code
        // 0b 0000 0100 0000 0000 (0x0400) authoritative_answer
        // 0b 0000 0010 0000 0000 (0x0200) truncated 
        // 0b 0000 0001 0000 0000 (0x0100) recursion_desired
        // 0b 0000 0000 1000 0000 (0x0080) recursion_available
        // 0b 0000 0000 0111 0000 (0x0070) z
        // 0b 0000 0000 0000 1111 (0x000f) response_code
        Self {
            id, 
            response: conversions::u16_to_bool((flag_bytes & 0x8000) >> 15), 
            operation_code: OperationCode::from_u16((flag_bytes & 0x7800) >> 11), 
            authoritative_answer: conversions::u16_to_bool((flag_bytes & 0x400) >> 10), 
            truncated: conversions::u16_to_bool((flag_bytes & 0x200) >> 9), 
            recursion_desired: conversions::u16_to_bool((flag_bytes & 0x100) >> 8), 
            recursion_available: conversions::u16_to_bool((flag_bytes & 0x80) >> 7), 
            z: (flag_bytes & 0x70) >> 4, 
            response_code: ResponseCode::from_u16(flag_bytes & 0xf), 
            question_count: udp_packet.read_u16(), 
            answer_count: udp_packet.read_u16(), 
            authority_count: udp_packet.read_u16(), 
            additional_count: udp_packet.read_u16() 
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsQuestion {
    pub name: udp_packet::DomainName,   // Domain name queried
    pub question_type: QuestionType,    // 16 bits, specifies query type
    pub question_class: QuestionClass   // 16 bits, specifies the class of the query, such as IN for the internet
}

impl Display for DnsQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\t{}\t{}", self.name, self.question_class, self.question_type)
    }
}

impl Default for DnsQuestion {
    fn default() -> Self {
        Self {
            name: udp_packet::DomainName::from_str(TEST_DOMAIN).expect("Failed to construct DomainName."), 
            question_type: Default::default(), 
            question_class: Default::default() 
        }
    }
}

impl DnsQuestion {
    fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) {
        udp_packet.write_domain_name(&self.name);
        if udp_packet.position + 4 >= udp_packet::UDP_PACKET_MAX_SIZE_BYTES {
            panic!("Cannot write out of packet bounds.");
        }
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.question_type.to_u16())); 
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.question_class.to_u16()));
    }

    fn read_from_udp_packet(udp_packet: &mut udp_packet::UdpPacket) -> Self {
        Self {
            name: udp_packet.read_domain_name(udp_packet.position),
            question_type: QuestionType::from_u16(udp_packet.read_u16()),
            question_class: QuestionClass::from_u16(udp_packet.read_u16())
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsRecord {
    pub name: udp_packet::DomainName,   // Domain name to which the RR belongs
    pub record_type: RecordType,        // 16 bits, specifies RR type and thus the contents of RDATA
    pub record_class: RecordClass,      // 16 bits, specifies the RR's class and thus the class of the contents of RDATA
    pub ttl: u32,                       // 32 bits, Specifies how long (in seconds) the RR can be cached
    pub length: u16,                    // 16 bits, Specifies the length (in bytes) of the contents of RDATA
    pub data: ResponseData              // The RDATA field, contains the name server's response data
}

impl Display for DnsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\t{:?}\t{:?}\t{}\t{}", self.name, self.record_class, self.record_type, self.ttl, self.data)
    }
}

impl DnsRecord {
    fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) {
        udp_packet.write_domain_name(&self.name);
        if udp_packet.position + 10 + self.length as usize >= udp_packet::UDP_PACKET_MAX_SIZE_BYTES {
            panic!("Cannot write out of packet bounds.");
        }
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.record_type.to_u16()));
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.record_class.to_u16()));
        udp_packet.write_from_slice(&conversions::u32_to_u8(self.ttl));
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.length));
        udp_packet.write_from_slice(&self.data.to_bytes());
    }

    fn read_from_udp_packet(udp_packet: &mut udp_packet::UdpPacket) -> Self {
        let name = udp_packet.read_domain_name(udp_packet.position);
        let record_type = RecordType::from_u16(udp_packet.read_u16());
        let record_class = RecordClass::from_u16(udp_packet.read_u16());
        let ttl = udp_packet.read_u32();
        let length =  udp_packet.read_u16();
        match record_type {
            RecordType::A => Self {
                name,
                record_type,
                record_class,
                ttl,
                length,
                data: ResponseData::Ipv4Address(net::Ipv4Addr::from(udp_packet.read_u32()))
            },
            RecordType::CNAME => Self {
                name,
                record_type,
                record_class,
                ttl,
                length,
                data: ResponseData::DomainName(udp_packet.read_domain_name(udp_packet.position))
            },
            RecordType::Unknown(_) => Self {
                name,
                record_type,
                record_class,
                ttl,
                length,
                data: ResponseData::Unknown
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsMessage {
    pub header: DnsHeader,              // 12 bytes, request and section metadata
    pub questions: Vec<DnsQuestion>,    // Question section, contains the relevant queries
    pub answers: Vec<DnsRecord>,        // Answer section, contains RR:s which answer the queries
    pub authorities: Vec<DnsRecord>,    // Authority section, contains NS RR:s pointing to other name servers
    pub additional: Vec<DnsRecord>      // Additional section, contains additional resources deemed relevant by the name server
}

impl Default for DnsMessage {
    fn default() -> Self {
        Self { 
            header: Default::default(), 
            questions: vec![DnsQuestion::default()], 
            answers: Default::default(), 
            authorities: Default::default(), 
            additional: Default::default() 
        }
    }
}

impl Display for DnsMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for question in self.questions.iter() {
            writeln!(f, "{}", question.to_string())?;
        }
        for answer in self.answers.iter() {
            writeln!(f, "{}", answer.to_string())?;
        }
        for authority in self.authorities.iter() {
            writeln!(f, "{}", authority.to_string())?;
        }
        for additional in self.additional.iter() {
            writeln!(f, "{}", additional.to_string())?;
        }
        Ok(())
    }
}

impl DnsMessage {
    pub fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) {
        self.header.write_to_udp_packet(udp_packet);
        for index in 0..self.header.question_count {
            self.questions[index as usize].write_to_udp_packet(udp_packet);
        }
        for index in 0..self.header.answer_count {
            self.answers[index as usize].write_to_udp_packet(udp_packet);
        }
        for index in 0..self.header.authority_count {
            self.authorities[index as usize].write_to_udp_packet(udp_packet);
        }
        for index in 0..self.header.additional_count {
            self.additional[index as usize].write_to_udp_packet(udp_packet);
        }
    }

    pub fn read_from_udp_packet(udp_packet: &mut udp_packet::UdpPacket) -> Self {
        let header = DnsHeader::read_from_udp_packet(udp_packet);
        let mut questions: Vec<DnsQuestion> = Vec::new();
        let mut answers: Vec<DnsRecord> = Vec::new();
        let mut authorities: Vec<DnsRecord> = Vec::new();
        let mut additional: Vec<DnsRecord> = Vec::new();
        for _ in 0..header.question_count {
            questions.push(DnsQuestion::read_from_udp_packet(udp_packet))
        };
        for _ in 0..header.answer_count {
            answers.push(DnsRecord::read_from_udp_packet(udp_packet))
        };
        for _ in 0..header.authority_count {
            authorities.push(DnsRecord::read_from_udp_packet(udp_packet))
        };
        for _ in 0..header.additional_count {
            additional.push(DnsRecord::read_from_udp_packet(udp_packet))
        };
        Self {
            header,
            questions,
            answers,
            authorities,
            additional
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dns_message::*;
    #[test]
    fn header_encoding_decoding_test() {
        let header = DnsHeader::default();
        let mut udp_packet = udp_packet::UdpPacket::new();
        header.write_to_udp_packet(&mut udp_packet);
        let decoded_header = DnsHeader::read_from_udp_packet(&mut udp_packet);
        assert_eq!(header, decoded_header);
    }

    #[test]
    fn dns_question_write_test() {
        let question = DnsQuestion::default();
        let mut udp_packet = udp_packet::UdpPacket::new();
        question.write_to_udp_packet(&mut udp_packet);
        assert_eq!(udp_packet, udp_packet::UdpPacket {
            buffer: [
                7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            position: 17
        })
    }

    #[test]
    fn default_trait_test() {
        // Enumerations
        assert_eq!(OperationCode::default(), OperationCode::StandardQuery);
        assert_eq!(ResponseCode::default(), ResponseCode::Success);
        assert_eq!(RecordType::default(), RecordType::A);
        assert_eq!(QuestionType::default(), QuestionType::RecordType(RecordType::A));
        assert_eq!(RecordClass::default(), RecordClass::IN);
        assert_eq!(QuestionClass::default(), QuestionClass::RecordClass(RecordClass::IN));

        // Structs
        assert_eq!(
            DnsHeader::default(), 
            DnsHeader {
                id: 0,
                response: false,
                operation_code: OperationCode::StandardQuery,
                authoritative_answer: false,
                truncated: false,
                recursion_desired: RECURSION_DESIRED,
                recursion_available: false,
                z: 0,
                response_code: ResponseCode::Success,
                question_count: QUESTION_COUNT,
                answer_count: 0,
                authority_count: 0,
                additional_count: 0
            }
        );
        assert_eq!(
            DnsQuestion::default(),
            DnsQuestion {
                name: udp_packet::DomainName::from_str(TEST_DOMAIN).expect("Failed to construct DomainName."),
                question_type: QuestionType::RecordType(RecordType::A),
                question_class: QuestionClass::RecordClass(RecordClass::IN)
            }
        );
        assert_eq!(
            DnsMessage::default(),
            DnsMessage {
                header: DnsHeader::default(),
                questions: vec![DnsQuestion::default()],
                answers: Vec::new(),
                authorities: Vec::new(),
                additional: Vec::new()
            }
        )
    }
}