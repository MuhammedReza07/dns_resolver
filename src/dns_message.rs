use crate::build_enum;
use crate::conversions;
use crate::udp_packet;
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::str::FromStr;
use std::net;

// Flag bitfield format (DnsHeader):
// 0b 1000 0000 0000 0000 (0x8000) response
// 0b 0111 1000 0000 0000 (0x7800) operation_code
// 0b 0000 0100 0000 0000 (0x0400) authoritative_answer
// 0b 0000 0010 0000 0000 (0x0200) truncated 
// 0b 0000 0001 0000 0000 (0x0100) recursion_desired
// 0b 0000 0000 1000 0000 (0x0080) recursion_available
// 0b 0000 0000 0111 0000 (0x0070) z
// 0b 0000 0000 0000 1111 (0x000f) response_code

// TODO: Improve variable and enum variant names, make them more consistent.
// It would, for example, be better to use a more descriptive name for the MX, NS and SOA variant of RecordType.
// TODO: Implement proper error handling for this module.

const DNS_HEADER_LENGTH_BYTES: usize = 12;      // First offset where a NAME (String value) occurs in packets.
const QUESTION_COUNT: u16 = 1;                  // The default QDCOUNT field of the DNS header.
const RECURSION_DESIRED: bool = true;           // The default RD field of the DNS header.
pub const TEST_DOMAIN: &str = "example.com";    // the "example" domains are reserved for testing.

build_enum!(
    OperationCode;
    QUERY = 0       // A standard query, i.e. domain_name -> RR
);

build_enum!(
    ResponseCode;
    Success = 0,            // No error
    FormatError = 1,        // DNS packet could not be interpreted due to malformed a query
    ServerFailure = 2,      // DNS packet could not be interpreted due to internal name server error
    NameError = 3,          // Domain name does not exist, only from authoritative name servers
    NotImplemented = 4,     // The requested functionality has not been implemented by the server
    Refused = 5             // The name server refuses to respond for some reason
);

build_enum!(
    RecordType;
    A = 1,          // An Ipv4 address (u32)
    NS = 2,         // Name server domain name
    CNAME = 5,      // Canonical name of an alias
    SOA = 6,        // Name server zone information
    MX = 15,        // The domain name of a MailExchange address
    AAAA = 28       // An Ipv6 address (u128)
);

build_enum!(
    RecordClass;
    IN = 1
);

build_enum!(
    QuestionType;
    Any = 255
);

build_enum!(
    QuestionClass;
    Any = 255
);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CombinedType {
    QuestionType(QuestionType),
    RecordType(RecordType)
}

impl Default for CombinedType {
    fn default() -> Self {
        Self::RecordType(RecordType::default())
    }
}

impl Display for CombinedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuestionType(qtype) => qtype.fmt(f),
            Self::RecordType(rtype) => rtype.fmt(f)
        }
    }
}

impl FromStr for CombinedType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match QuestionType::from_str(s) {
            Ok(qtype) => Ok(CombinedType::QuestionType(qtype)),
            Err(_) => match RecordType::from_str(s) {
                Ok(rtype) => Ok(CombinedType::RecordType(rtype)),
                Err(_) => Err(format!("Encountered invalid variant '{}'.", s))
            }
        }
    }
}

impl TryFrom<u16> for CombinedType {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match QuestionType::try_from(value) {
            Ok(qtype) => Ok(Self::QuestionType(qtype)),
            Err(_) => match RecordType::try_from(value) {
                Ok(rtype) => Ok(Self::RecordType(rtype)),
                Err(_) => Err(format!("Invalid u16 ({}).", value))
            }
        }
    }
}

impl TryInto<u16> for CombinedType {
    type Error = String;

    fn try_into(self) -> Result<u16, Self::Error> {
        match self {
            Self::QuestionType(qtype) => qtype.try_into(),
            Self::RecordType(rtype) => rtype.try_into()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CombinedClass {
    QuestionClass(QuestionClass),
    RecordClass(RecordClass)
}

impl Default for CombinedClass {
    fn default() -> Self {
        Self::RecordClass(RecordClass::default())
    }
}

impl Display for CombinedClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuestionClass(qclass) => qclass.fmt(f),
            Self::RecordClass(rclass) => rclass.fmt(f)
        }
    }
}

impl FromStr for CombinedClass {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match QuestionClass::from_str(s) {
            Ok(qclass) => Ok(CombinedClass::QuestionClass(qclass)),
            Err(_) => match RecordClass::from_str(s) {
                Ok(rclass) => Ok(CombinedClass::RecordClass(rclass)),
                Err(_) => Err(format!("Encountered invalid variant '{}'.", s))
            }
        }
    }
}

impl TryFrom<u16> for CombinedClass {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match QuestionClass::try_from(value) {
            Ok(qclass) => Ok(Self::QuestionClass(qclass)),
            Err(_) => match RecordClass::try_from(value) {
                Ok(rclass) => Ok(Self::RecordClass(rclass)),
                Err(_) => Err(format!("Invalid u16 ({}).", value))
            }
        }
    }
}

impl TryInto<u16> for CombinedClass {
    type Error = String;

    fn try_into(self) -> Result<u16, Self::Error> {
        match self {
            Self::QuestionClass(qclass) => qclass.try_into(),
            Self::RecordClass(rclass) => rclass.try_into()
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ResponseData {
    A(net::Ipv4Addr),
    AAAA(net::Ipv6Addr),
    CNAME(udp_packet::DomainName),
    SOA(udp_packet::SOAData),
    MX(udp_packet::MXData),
    NS(udp_packet::DomainName),
    Unknown
}

impl ResponseData {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::A(addr) => addr.octets().to_vec(),
            Self::AAAA(addr) => addr.octets().to_vec(),
            Self::CNAME(name) => name.0.to_vec(),
            Self::MX(data) => data.as_bytes(),
            Self::NS(name) => name.0.to_vec(),
            Self::SOA(data) => data.as_bytes(),
            Self::Unknown => "Unknown/unimplemented".as_bytes().to_vec()
        }
    }
}

impl Display for ResponseData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(addr) => addr.fmt(f),
            Self::AAAA(addr) => addr.fmt(f),
            Self::CNAME(name) => name.fmt(f),
            Self::MX(data) => data.fmt(f),
            Self::NS(data) => data.fmt(f),
            Self::SOA(info) => info.fmt(f),
            Self::Unknown => write!(f, "Unknown/unimplemented")
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
    fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) -> udp_packet::Result<()> {
        if udp_packet.position >= DNS_HEADER_LENGTH_BYTES {
            panic!("DNS header can only be written within bytes 0-11 (DNS_HEADER_LENGTH_BYTES - 1) of DnsMessage.buffer.")
        }
        let flag_bytes = conversions::u16_to_u8(TryInto::<u16>::try_into(self.response_code).unwrap()
        | (self.z << 4)
        | (conversions::bool_to_u16(self.recursion_available) << 7)
        | (conversions::bool_to_u16(self.recursion_desired) << 8)
        | (conversions::bool_to_u16(self.truncated) << 9)
        | (conversions::bool_to_u16(self.authoritative_answer) << 10)
        | (TryInto::<u16>::try_into(self.operation_code).unwrap() << 11)
        | (conversions::bool_to_u16(self.response) << 15));
        let slice = [
            conversions::u16_to_u8(self.id),
            flag_bytes,
            conversions::u16_to_u8(self.question_count),
            conversions::u16_to_u8(self.answer_count),
            conversions::u16_to_u8(self.authority_count),
            conversions::u16_to_u8(self.additional_count)
        ].concat();
        udp_packet.write_from_slice(&slice, 0)?;
        Ok(())
    }

    fn read_from_udp_packet(udp_packet: &mut udp_packet::UdpPacket) -> udp_packet::Result<Self> {
        let id = udp_packet.read_u16()?;
        let flag_bytes = udp_packet.read_u16()?;
        Ok(Self {
            id, 
            response: conversions::u16_to_bool((flag_bytes & 0x8000) >> 15), 
            operation_code: OperationCode::try_from((flag_bytes & 0x7800) >> 11).unwrap(), 
            authoritative_answer: conversions::u16_to_bool((flag_bytes & 0x400) >> 10), 
            truncated: conversions::u16_to_bool((flag_bytes & 0x200) >> 9), 
            recursion_desired: conversions::u16_to_bool((flag_bytes & 0x100) >> 8), 
            recursion_available: conversions::u16_to_bool((flag_bytes & 0x80) >> 7), 
            z: (flag_bytes & 0x70) >> 4, 
            response_code: ResponseCode::try_from(flag_bytes & 0xf).unwrap(), 
            question_count: udp_packet.read_u16()?, 
            answer_count: udp_packet.read_u16()?, 
            authority_count: udp_packet.read_u16()?, 
            additional_count: udp_packet.read_u16()?
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsQuestion {
    pub name: udp_packet::DomainName,   // Domain name queried
    pub question_type: CombinedType,    // 16 bits, specifies query type
    pub question_class: CombinedClass   // 16 bits, specifies the class of the query, such as IN for the internet
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
    fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) -> udp_packet::Result<()> {
        udp_packet.write_domain_name(&self.name, 4)?;
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.question_type.try_into().unwrap()), 0)?; 
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.question_class.try_into().unwrap()), 0)?;
        Ok(())
    }

    fn read_from_udp_packet(udp_packet: &mut udp_packet::UdpPacket) -> udp_packet::Result<Self> {
        Ok(Self {
            name: udp_packet.read_domain_name(udp_packet.position)?,
            question_type: CombinedType::try_from(udp_packet.read_u16()?).unwrap(),
            question_class: CombinedClass::try_from(udp_packet.read_u16()?).unwrap()
        })
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
        write!(f, "{}\t{}\t{}\t{}\t{}", self.name, self.record_class, self.record_type, self.ttl, self.data)
    }
}

impl DnsRecord {
    fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) -> udp_packet::Result<()> {
        udp_packet.write_domain_name(&self.name, 10)?;
        udp_packet.write_from_slice(&[
            conversions::u16_to_u8(self.record_type.try_into().unwrap()).to_vec(), 
            conversions::u16_to_u8(self.record_class.try_into().unwrap()).to_vec(),
            conversions::u32_to_u8(self.ttl).to_vec(),
            conversions::u16_to_u8(self.length).to_vec(),
            self.data.as_bytes()
        ].concat(), 0)?;
        Ok(())
    }

    fn read_from_udp_packet(udp_packet: &mut udp_packet::UdpPacket) -> udp_packet::Result<Self> {
        let name = udp_packet.read_domain_name(udp_packet.position)?;
        let record_type = RecordType::try_from(udp_packet.read_u16()?).unwrap();
        let record_class = RecordClass::try_from(udp_packet.read_u16()?).unwrap();
        let ttl = udp_packet.read_u32()?;
        let length =  udp_packet.read_u16()?;
        let data = match record_type {
            RecordType::A => ResponseData::A(net::Ipv4Addr::from(udp_packet.read_u32()?)),
            RecordType::AAAA => ResponseData::AAAA(net::Ipv6Addr::from(udp_packet.read_u128()?)),
            RecordType::CNAME => ResponseData::CNAME(udp_packet.read_domain_name(udp_packet.position)?),
            RecordType::MX => ResponseData::MX(udp_packet.read_mx_data()?),
            RecordType::NS => ResponseData::NS(udp_packet.read_domain_name(udp_packet.position)?),
            RecordType::SOA => ResponseData::SOA(udp_packet.read_soa_data(udp_packet.position)?)
        };
        Ok(Self { name, record_type, record_class, ttl, length, data })
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
        writeln!(f, "HEADERS: (TODO)")?;

        writeln!(f)?;
        writeln!(f, "QUESTIONS:")?;
        for question in self.questions.iter() {
            writeln!(f, "{}", question.to_string())?;
        }

        if self.answers.len() > 0 {
            writeln!(f)?;
            writeln!(f, "ANSWER SECTION:")?;
            for answer in self.answers.iter() {
                writeln!(f, "{}", answer.to_string())?;
            }
        }

        if self.authorities.len() > 0 {
            writeln!(f)?;
            writeln!(f, "AUTHORITY SECTION:")?;
            for authority in self.authorities.iter() {
                writeln!(f, "{}", authority.to_string())?;
            }
        }

        if self.additional.len() > 0 {
            writeln!(f)?;
            writeln!(f, "ADDITIONAL SECTION:")?;
            for additional in self.additional.iter() {
                writeln!(f, "{}", additional.to_string())?;
            }
        }

        Ok(())
    }
}

impl DnsMessage {
    pub fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) -> udp_packet::Result<()> {
        self.header.write_to_udp_packet(udp_packet)?;
        for index in 0..self.header.question_count {
            self.questions[index as usize].write_to_udp_packet(udp_packet)?;
        }
        for index in 0..self.header.answer_count {
            self.answers[index as usize].write_to_udp_packet(udp_packet)?;
        }
        for index in 0..self.header.authority_count {
            self.authorities[index as usize].write_to_udp_packet(udp_packet)?;
        }
        for index in 0..self.header.additional_count {
            self.additional[index as usize].write_to_udp_packet(udp_packet)?;
        }
        Ok(())
    }

    pub fn read_from_udp_packet(udp_packet: &mut udp_packet::UdpPacket) -> udp_packet::Result<Self> {
        let header = DnsHeader::read_from_udp_packet(udp_packet)?;
        let mut questions: Vec<DnsQuestion> = Vec::new();
        let mut answers: Vec<DnsRecord> = Vec::new();
        let mut authorities: Vec<DnsRecord> = Vec::new();
        let mut additional: Vec<DnsRecord> = Vec::new();
        for _ in 0..header.question_count {
            questions.push(DnsQuestion::read_from_udp_packet(udp_packet)?)
        };
        for _ in 0..header.answer_count {
            answers.push(DnsRecord::read_from_udp_packet(udp_packet)?)
        };
        for _ in 0..header.authority_count {
            authorities.push(DnsRecord::read_from_udp_packet(udp_packet)?)
        };
        for _ in 0..header.additional_count {
            additional.push(DnsRecord::read_from_udp_packet(udp_packet)?)
        };
        Ok(Self { header, questions, answers, authorities, additional })
    }
}

#[cfg(test)]
mod tests {
    use crate::dns_message::*;
    #[test]
    fn header_encoding_decoding_test() {
        let header = DnsHeader::default();
        let mut udp_packet = udp_packet::UdpPacket::new();
        header.write_to_udp_packet(&mut udp_packet)
        .expect("Failed to write header.");
        udp_packet.position = 0; // Position reset since the test does not take position updates into account
        let decoded_header = DnsHeader::read_from_udp_packet(&mut udp_packet)
        .expect("Failed to decode header.");
        assert_eq!(header, decoded_header);
    }

    #[test]
    fn dns_question_write_test() {
        let question = DnsQuestion::default();
        let mut udp_packet = udp_packet::UdpPacket::new();
        question.write_to_udp_packet(&mut udp_packet)
        .expect("Failed to write to packet.");
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
        assert_eq!(OperationCode::default(), OperationCode::QUERY);
        assert_eq!(ResponseCode::default(), ResponseCode::Success);
        assert_eq!(RecordType::default(), RecordType::A);
        assert_eq!(QuestionType::default(), QuestionType::Any);
        assert_eq!(CombinedType::default(), CombinedType::RecordType(RecordType::A));
        assert_eq!(RecordClass::default(), RecordClass::IN);
        assert_eq!(QuestionClass::default(), QuestionClass::Any);
        assert_eq!(CombinedClass::default(), CombinedClass::RecordClass(RecordClass::IN));

        // Structs
        assert_eq!(
            DnsHeader::default(), 
            DnsHeader {
                id: 0,
                response: false,
                operation_code: OperationCode::QUERY,
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
                question_type: CombinedType::RecordType(RecordType::A),
                question_class: CombinedClass::RecordClass(RecordClass::IN)
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