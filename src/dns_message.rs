use crate::conversions;
use crate::udp_packet;

// TODO: Facilitate construction of complex structs (e.g. DnsHeader, DnsMessage) by implementing the builder pattern.
// Temporary solution: Making every field public.
// TODO: Implement more robust error handling by using a custom error type.

const DNS_HEADER_LENGTH_BYTES: usize = 12; // First offset where a NAME (String value) occurs in packets.
const QUESTION_COUNT: u16 = 1; // The default QDCOUNT field of the DNS header.
const RECURSION_DESIRED: bool = true; // The default RD field of the DNS header.
pub const TEST_DOMAIN: &str = "example.com"; // the "example" domains are reserved for testing.

// Represented by 4 bits
#[derive(Debug, Default, PartialEq)]
pub enum OperationCode {
    #[default]
    StandardQuery, // QUERY, 0
    InverseQuery, // IQUERY, 1
    Status // STATUS, 2
}

impl OperationCode {
    fn from_u16(num: u16) -> Self {
        match num {
            0 => OperationCode::StandardQuery,
            1 => OperationCode::InverseQuery,
            2 => OperationCode::Status,
            _ => panic!("Integers (u16) 3-15 are reserved for future use.")
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            OperationCode::StandardQuery => 0,
            OperationCode::InverseQuery => 1,
            OperationCode::Status => 2,
        }
    }
}

// Represented by 4 bits
#[derive(Debug, Default, PartialEq)]
pub enum ResponseCode {
    #[default]
    Success, // 0, no error
    FormatError, // 1, DNS packet could not be interpreted due to malformed a query
    ServerFailure, // 2, DNS packet could not be interpreted due to internal name server error
    NameError, // 3, Domain name does not exist, only from authoritative name servers
    NotImplemented, // 4, the requested functionality has not been implemented by the server
    Refused, // 5, the name server refuses to respond for some reason
}

impl ResponseCode {
    fn from_u16(num: u16) -> Self {
        match num {
            0 => ResponseCode::Success,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => panic!("Integers (u16) 6-15 are reserved for future use.")
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            ResponseCode::Success => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum RecordType {
    #[default]
    A
}

impl RecordType {
    fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum RecordClass {
    #[default]
    IN
}

impl RecordClass {
    fn to_u16(&self) -> u16 {
        match self {
            RecordClass::IN => 1
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum QuestionType {
    #[default]
    A
}

impl QuestionType {
    fn to_u16(&self) -> u16 {
        match self {
            QuestionType::A => 1
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub enum QuestionClass {
    #[default]
    IN
}

impl QuestionClass {
    fn to_u16(&self) -> u16 {
        match self {
            QuestionClass::IN => 1
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsHeader {
    pub id: u16, // 16 bits, packet identifier

    // 16 bits, header flags
    pub response: bool, // 1 bit, set (1) on responses, unset (0) on queries
    pub operation_code: OperationCode, // 4 bits, indicates the kind of query in the packet
    pub authoritative_answer: bool, // 1 bit, set if the responding name server is a domain authority
    pub truncated: bool, // 1 bit, set if the message's content has been truncated due to being too long
    pub recursion_desired: bool, // 1 bit, set if the resolver desires recursive service
    pub recursion_available: bool, // 1 bit, set if the name server is willing to provide recursive service
    pub z: u16, // 3 bits, reserved and must be unset
    pub response_code: ResponseCode, // 4 bits, indicates the response status of the name server

    // Metadata about the other sections of the DNS message
    pub question_count: u16, // 16 bits
    pub answer_count: u16, // 16 bits
    pub authority_count: u16, // 16 bits
    pub additional_count: u16 // 16 bits
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
        if udp_packet.get_position() >= DNS_HEADER_LENGTH_BYTES {
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
            conversions::u16_to_u8(self.id), // id field
            flag_bytes, // header flags, 
            conversions::u16_to_u8(self.question_count), // question count field
            conversions::u16_to_u8(self.answer_count), // answer count field
            conversions::u16_to_u8(self.authority_count), // authority count field
            conversions::u16_to_u8(self.additional_count) // additional count field
        ].concat();
        udp_packet.write_from_slice(&slice);
    }

    // TODO: Maybe avoid indexing by using slices instead, requires parameter change in conversions::u8_to_u16.
    pub fn read_from_udp_packet(udp_packet: &udp_packet::UdpPacket) -> Self {
        let header_bytes = udp_packet.read_to_slice(0, DNS_HEADER_LENGTH_BYTES);
        let flag_bytes = conversions::u8_to_u16([header_bytes[2], header_bytes[3]]);
        // Flag bitfield format:
        // 0b 1000 0000 0000 0000 (0x8000) response
        // 0b 0111 1000 0000 0000 (0x7800) operation_code
        // 0b 0000 0100 0000 0000 (0x0400) authoritative_answer
        // 0b 0000 0010 0000 0000 (0x0200) truncated 
        // 0b 0000 0001 0000 0000 (0x0100) recursion_desired
        // 0b 0000 0000 1000 0000 (0x0080) recursion_available
        // 0b 0000 0000 0111 0000 (0x0070) z
        // 0b 0000 0000 0000 1111 (0x000f) response_code
        DnsHeader {
            id: conversions::u8_to_u16([header_bytes[0], header_bytes[1]]), 
            response: conversions::u16_to_bool((flag_bytes & 0x8000) >> 15), 
            operation_code: OperationCode::from_u16((flag_bytes & 0x7800) >> 11), 
            authoritative_answer: conversions::u16_to_bool((flag_bytes & 0x400) >> 10), 
            truncated: conversions::u16_to_bool((flag_bytes & 0x200) >> 9), 
            recursion_desired: conversions::u16_to_bool((flag_bytes & 0x100) >> 8), 
            recursion_available: conversions::u16_to_bool((flag_bytes & 0x80) >> 7), 
            z: (flag_bytes & 0x70) >> 4, 
            response_code: ResponseCode::from_u16(flag_bytes & 0xf), 
            question_count: conversions::u8_to_u16([header_bytes[4], header_bytes[5]]), 
            answer_count: conversions::u8_to_u16([header_bytes[6], header_bytes[7]]), 
            authority_count: conversions::u8_to_u16([header_bytes[8], header_bytes[9]]), 
            additional_count: conversions::u8_to_u16([header_bytes[10], header_bytes[11]]) 
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsQuestion {
    pub name: String, // Domain name queried
    pub question_type: QuestionType, // 16 bits, specifies query type
    pub question_class: QuestionClass // 16 bits, specifies the class of the query, such as IN for the internet
}

impl Default for DnsQuestion {
    fn default() -> Self {
        Self {
            name: String::from(TEST_DOMAIN), 
            question_type: Default::default(), 
            question_class: Default::default() 
        }
    }
}

impl DnsQuestion {
    // TODO: Do complete bound checking before writing the string.
    // Proposed solution: extract the conversion of the NAME from String to bytes into a separate function and
    // improve error handling.
    fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) {
        udp_packet.write_string(&self.name);
        if udp_packet.get_position() + 4 >= udp_packet::UDP_PACKET_MAX_SIZE_BYTES {
            panic!("Cannot write out of packet bounds.");
        }
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.question_type.to_u16())); 
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.question_class.to_u16()));
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsRecord {
    pub name: String, // Domain name to which the RR belongs
    pub record_type: RecordType, // 16 bits, specifies RR type and thus the contents of RDATA
    pub record_class: RecordClass, // 16 bits, specifies the RR's class and thus the class of the contents of RDATA
    pub ttl: u32, // 32 bits, Specifies how long (in seconds) the RR can be cached
    pub length: u16, // 16 bits, Specifies the length (in bytes) of the contents of RDATA
    pub data: Vec<u8> // The RDATA field, contains the name server's response data
}

impl DnsRecord {
    // TODO: Do complete bound checking before writing the string.
    // Proposed solution: extract the conversion of the NAME from String to bytes into a separate function and
    // improve error handling.
    fn write_to_udp_packet(&self, udp_packet: &mut udp_packet::UdpPacket) {
        udp_packet.write_string(&self.name);
        if udp_packet.get_position() + 10 + self.data.len() >= udp_packet::UDP_PACKET_MAX_SIZE_BYTES {
            panic!("Cannot write out of packet bounds.");
        }
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.record_type.to_u16()));
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.record_class.to_u16()));
        udp_packet.write_from_slice(&conversions::u32_to_u8(self.ttl));
        udp_packet.write_from_slice(&conversions::u16_to_u8(self.length));
        udp_packet.write_from_slice(&self.data);
    }
}

#[derive(Debug, PartialEq)]
pub struct DnsMessage {
    pub header: DnsHeader, // 12 bytes, request and section metadata
    pub questions: Vec<DnsQuestion>, // Question section, contains the relevant queries
    pub answers: Vec<DnsRecord>, // Answer section, contains RR:s which answer the queries
    pub authorities: Vec<DnsRecord>, // Authority section, contains NS RR:s pointing to other name servers
    pub additional: Vec<DnsRecord> // Additional section, contains additional resources deemed relevant by the name server
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
}

#[cfg(test)]
mod tests {
    use crate::dns_message::*;
    #[test]
    fn header_encoding_decoding_test() {
        let header = DnsHeader::default();
        let mut udp_packet = udp_packet::UdpPacket::new();
        header.write_to_udp_packet(&mut udp_packet);
        let decoded_header = DnsHeader::read_from_udp_packet(&udp_packet);
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
        assert_eq!(QuestionType::default(), QuestionType::A);
        assert_eq!(RecordClass::default(), RecordClass::IN);
        assert_eq!(QuestionClass::default(), QuestionClass::IN);

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
                name: String::from(TEST_DOMAIN),
                question_type: QuestionType::A,
                question_class: QuestionClass::IN
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