use std::net;
use std::str::FromStr;

pub const UDP_PACKET_MAX_SIZE_BYTES: usize = 512;
const NAME_MAX_LENGTH_BYTES: usize = 255;
const LABEL_MAX_LENGTH_BYTES: usize = 63;

// The length of a domain name is given by length = [the dot-separated name as a string].len() + 2
// This is clear from the following path of reasoning:
// Consider the domain name label_1.label_2 ... .label_n.
// It is encoded as [label_1.len()]label_1[label_2.len()]label_2 ... [label_n.len()]label_n\0.
// If the lengths in bytes are considered, the length is given by length =
// [label_1.len()].len() + [label_1[label_2.len()]label_2 ... [label_n.len()]label_n].len() + \0.len()
// = 1 + label_1.label_2 ... .label_n.len() + 1
// = [the dot-separated name as a string].len() + 2

#[derive(Debug)]
pub enum Malformation {
    LabelTooLong,
    NameTooLong,
    InvalidAscii
}

/// Error handling type for UDP packet operations.
#[derive(Debug)]
pub enum UdpPacketIoError  {
    /// The domain name does not conform to the standard constraints.
    MalformedDomainName {
        domain_name: String, // The malformed domain name.
        description: String, // An error message.
        source: Malformation // The malformation
    },

    /// An error occurred while performing networking operations.
    NetworkIo {
        description: String, // An error message.
        source: std::io::Error // The underlying low level error.
    }
}

impl std::fmt::Display for UdpPacketIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpPacketIoError::MalformedDomainName { 
                domain_name, 
                description, 
                source 
            } => write!(f, "an error occurred while processing {}, source: {:?}, description: {}", domain_name, source, description),
            UdpPacketIoError::NetworkIo { 
                description, 
                source 
            } => write!(f, "an error occurred while performing network operations, description: {}, source: {:?}", description, source)
        }
    }
}

impl std::error::Error for UdpPacketIoError {}

#[derive(Debug, PartialEq)]
pub struct DomainName(Vec<u8>);

// TODO: Check for the fact that all characters in the domain name are valid ASCII.
impl FromStr for DomainName {
    type Err = UdpPacketIoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() + 2 > NAME_MAX_LENGTH_BYTES {
            return Err(UdpPacketIoError::MalformedDomainName {
                domain_name: s.to_string(),
                description: String::from("domain name length exceeds 255 bytes"),
                source: Malformation::NameTooLong
            });
        }
        let mut domain_name = Vec::<Vec<u8>>::new();
        for label in s.split(".").collect::<Vec<&str>>() {
            if label.len() > LABEL_MAX_LENGTH_BYTES {
                return Err(UdpPacketIoError::MalformedDomainName {
                    domain_name: s.to_string(), 
                    description: format!("the length of label '{}' exceeds 63 bytes", label), 
                    source: Malformation::LabelTooLong
                });
            }
            domain_name.push([[label.len() as u8].as_slice(), label.as_bytes()].concat())
        }
        domain_name.push(vec![0]); // Adding the zero byte, \0.
        Ok(DomainName(domain_name.concat()))
    }
}

// TODO: Make all struct fields private.
// TODO: Implement equivalents to send_to and recv_from in std::net for UdpPacket.
#[derive(Debug, PartialEq)]
pub struct UdpPacket {
    pub buffer: [u8; UDP_PACKET_MAX_SIZE_BYTES],
    pub position: usize
}

impl UdpPacket {
    pub fn new() -> Self {
        UdpPacket {
            buffer: [0; UDP_PACKET_MAX_SIZE_BYTES],
            position: 0
        }
    }

    pub fn send(&self, udp_socket: &net::UdpSocket) -> Result<usize, UdpPacketIoError> {
        match udp_socket.send(&self.buffer) {
            Ok(num_bytes_read) => Ok(num_bytes_read),
            Err(error) => Err(UdpPacketIoError::NetworkIo { 
                description: String::from("failed to send a packet"), 
                source: error
            })
        }
    }

    pub fn recv(&mut self, udp_socket: &net::UdpSocket) -> Result<usize, UdpPacketIoError> {
        match udp_socket.recv(&mut self.buffer) {
            Ok(num_bytes_read) => Ok(num_bytes_read),
            Err(error) => Err(UdpPacketIoError::NetworkIo { 
                description: String::from("failed to receive a packet"), 
                source: error
            })
        }
    }

    pub fn write_from_slice(&mut self, slice: &[u8]) -> () {
        if self.position + slice.len() >= UDP_PACKET_MAX_SIZE_BYTES {
            panic!("Cannot write out of buffer bounds.");
        }
        for (index, element) in slice.iter().enumerate() {
            self.buffer[self.position + index] = *element;
        }
        self.position += slice.len();
    }

    pub fn read_to_slice(&self, start: usize, length: usize) -> &[u8] {
        if start + length >= UDP_PACKET_MAX_SIZE_BYTES {
            panic!("Cannot read out of buffer bounds.")
        }
        &self.buffer[start..(start + length)]
    }

    // TODO: While this method currently operates without the use of compression, a DNS specification compliant
    // compression algorithm must be used for increased efficiency.
    // While this TODO's resolution is necessary, the compression-free implementation suffices for the purpose of
    // generating shorter queries. As such, it is useful for the generation of name-server responses for the testing
    // of other methods.
    pub fn write_domain_name(&mut self, domain_name: &DomainName) {
        self.write_from_slice(&domain_name.0);
    }

    pub fn read_domain_name(&self, start: usize) -> DomainName {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::dns_message;
    use crate::udp_packet::*;
    #[test]
    fn write_from_slice_test() {
        let buffer = [
            65, 89, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];
        let slice = [65, 89, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0];
        let mut udp_packet = UdpPacket::new();
        udp_packet.write_from_slice(&slice);
        assert_eq!(udp_packet, UdpPacket {
            buffer: buffer,
            position: 12
        });
        let buffer = [
            65, 89, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 65, 89, 1, 0, 
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
        ];
        udp_packet.write_from_slice(&slice);
        assert_eq!(udp_packet, UdpPacket {
            buffer: buffer,
            position: 24
        });
    }

    #[test]
    fn write_string_test() {
        let mut udp_packet: UdpPacket = UdpPacket::new();
        udp_packet.write_domain_name(&DomainName::from_str(dns_message::TEST_DOMAIN)
        .expect("Failed to construct DomainName."));
        assert_eq!(udp_packet, UdpPacket {
            buffer: [
                7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 0, 0,
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
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            position: 13
        })
    }

}