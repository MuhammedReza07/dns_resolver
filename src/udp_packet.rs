use std::fmt::Display;
use std::str::FromStr;
use std::net;
use std::result;

pub const UDP_PACKET_MAX_SIZE_BYTES: usize = 512;
const NAME_MAX_LENGTH_BYTES: usize = 255;
const LABEL_MAX_LENGTH_BYTES: usize = 63;
const MAX_JUMPS: usize = 10;

// TODO: Add functionality to verify that CharacterString:s comply to the constraints set by the standards.
// May require the use of a struct to represent the CharacterString as a struct.

/// Specialised result type for UdpPacket operations.
pub type Result<T> = result::Result<T, UdpPacketError>;

// The length of a domain name is given by length = [the dot-separated name as a string].len() + 2
// This is clear from the following path of reasoning:
// Consider the domain name label_1.label_2 ... .label_n.
// It is encoded as [label_1.len()]label_1[label_2.len()]label_2 ... [label_n.len()]label_n\0.
// If the lengths in bytes are considered, the length is given by length =
// [label_1.len()].len() + [label_1[label_2.len()]label_2 ... [label_n.len()]label_n].len() + \0.len()
// = 1 + label_1.label_2 ... .label_n.len() + 1
// = [the dot-separated name as a string].len() + 2

// TODO: Make the messages display via the Display trait's fmt() function instead of the Debug trait.
// Or just make the error messages cleaner, the method does not really matter.

#[derive(Debug)]
pub enum Malformation {
    LabelTooLong,   // A label's length exceeds allowed limits.
    NameTooLong,    // The domain name is too long.
    InvalidCharset  // The domain name includes characters beyond the allowed charset.
}

/// Error handling type for UDP packet operations.
#[derive(Debug)]
pub enum UdpPacketError {
    /// The domain name does not conform to the standard constraints (for String).
    MalformedDomainName {
        domain_name: String,    // The malformed domain name.
        description: String,    // An error message.
        source: Malformation    // The malformation.
    },

    /// Maximum number of jumps exceeded, i.e. the message might be malformed or malicious.
    MaxJumpsExceeded,

    /// An error occurred while performing networking operations.
    NetworkIo {
        description: String,    // An error message.
        source: std::io::Error  // The underlying low level error.
    },

    /// A packet IO operation was performed out of bounds.
    OutOfBounds {
        length: usize,          // The length of the buffer.
        index: usize            // The erroneous index.
    },

    /// An error occurred while converting bytes, e.g. in a DomainName, to a UTF-8 String.
    FromUtf8 {
        bytes: Vec<u8>,                     // The erroneous bytes.
        source: std::string::FromUtf8Error  // The underlying error.
    }
}

impl std::fmt::Display for UdpPacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpPacketError::MalformedDomainName { 
                domain_name, 
                description, 
                source, 
            } => write!(f, "an error occurred while processing {}, source: {:?}, description: {}", domain_name, source, description),
            UdpPacketError::MaxJumpsExceeded => write!(f, "maximum number of jumps while exceeded while reading a compressed domain name"),
            UdpPacketError::NetworkIo { 
                description, 
                source, 
            } => write!(f, "an error occurred while performing network operations, description: {}, source: {:?}", description, source),
            UdpPacketError::OutOfBounds { 
                length, 
                index, 
            } => write!(f, "attempted to access a buffer of length {} at index {}", length, index),
            UdpPacketError::FromUtf8 { 
                bytes, 
                source, 
            } => write!(f, "Failed to convert byte sequence {:?} to a utf-8 string, source: {}", bytes, source)
        }
    }
}

impl std::error::Error for UdpPacketError {}

#[derive(Debug, Default, PartialEq)]
pub struct CharacterString {
    pub length: usize,
    pub bytes: Vec<u8>
}

impl Display for CharacterString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = String::from_utf8(self.bytes.to_vec())
        .map_err(|error| UdpPacketError::FromUtf8 { 
            bytes: self.bytes.to_vec(), 
            source: error 
        })
        .map_err(|_| std::fmt::Error)?;
        write!(f, "{}", string)
    }
}

impl FromStr for CharacterString {
    type Err = ();

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        Ok(Self {
            length: s.len(),
            bytes: s.as_bytes().to_vec()
        })
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct DomainName {
    pub bytes: Vec<u8>
}

impl Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut labels: Vec<&[u8]> = Vec::new();
        let mut position = 0;
        while self.bytes[position] != 0x00 {
            let length = self.bytes[position] as usize;
            labels.push(&self.bytes[(position + 1)..(position + 1 + length)]);
            labels.push(b".");
            position += length + 1;
        }
        let string = String::from_utf8(labels.concat())
        .map_err(|error| UdpPacketError::FromUtf8 { 
            bytes: self.bytes.to_vec(), 
            source: error 
        })
        .map_err(|_| std::fmt::Error)?;
        write!(f, "{}", string)
    }
}

impl FromStr for DomainName {
    type Err = UdpPacketError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        let mut s = String::from(s);
        s.pop();
        if s.len() + 2 > NAME_MAX_LENGTH_BYTES {
            return Err(UdpPacketError::MalformedDomainName {
                domain_name: s.to_string(),
                description: String::from("domain name length exceeds 255 bytes"),
                source: Malformation::NameTooLong
            });
        }
        let mut domain_name = Vec::<Vec<u8>>::new();
        for label in s.split(".").collect::<Vec<&str>>() {
            if label.len() > LABEL_MAX_LENGTH_BYTES {
                return Err(UdpPacketError::MalformedDomainName {
                    domain_name: s.to_string(), 
                    description: format!("the length of label '{}' exceeds 63 bytes", label), 
                    source: Malformation::LabelTooLong
                });
            }
            domain_name.push([[label.len() as u8].as_slice(), label.as_bytes()].concat())
        }
        domain_name.push(vec![0]); // Adding the zero byte, \0.
        Ok(Self { bytes: domain_name.concat() })
    }
}

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

    pub fn read_u16(&mut self) -> Result<u16> {
        if self.position + 1 >= UDP_PACKET_MAX_SIZE_BYTES {
            return Err(UdpPacketError::OutOfBounds { 
                length: UDP_PACKET_MAX_SIZE_BYTES, 
                index: self.position + 1 
            })
        }
        let result = ((self.buffer[self.position] as u16) << 8) | (self.buffer[self.position + 1] as u16);
        self.position += 2;
        Ok(result)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.position + 3 >= UDP_PACKET_MAX_SIZE_BYTES {
            return Err(UdpPacketError::OutOfBounds { 
                length: UDP_PACKET_MAX_SIZE_BYTES, 
                index: self.position + 3 
            })
        }
        let result = ((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32);
        Ok(result)
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        if self.position + 7 >= UDP_PACKET_MAX_SIZE_BYTES {
            return Err(UdpPacketError::OutOfBounds { 
                length: UDP_PACKET_MAX_SIZE_BYTES, 
                index: self.position + 7 
            })
        }
        let result = ((self.read_u32()? as u64) << 32) | (self.read_u32()? as u64);
        Ok(result)
    }

    pub fn read_u128(&mut self) -> Result<u128> {
        if self.position + 15 >= UDP_PACKET_MAX_SIZE_BYTES {
            return Err(UdpPacketError::OutOfBounds { 
                length: UDP_PACKET_MAX_SIZE_BYTES, 
                index: self.position + 15 
            })
        }
        let result = ((self.read_u64()? as u128) << 64) | (self.read_u64()? as u128);
        Ok(result)
    }

    pub fn send(&self, udp_socket: &net::UdpSocket) -> Result<usize> {
        match udp_socket.send(&self.buffer) {
            Ok(num_bytes_read) => Ok(num_bytes_read),
            Err(error) => Err(UdpPacketError::NetworkIo { 
                description: String::from("failed to send a packet"), 
                source: error
            })
        }
    }

    pub fn send_to<A: net::ToSocketAddrs>(&self, udp_socket: &net::UdpSocket, addr: A) -> Result<usize> {
        match udp_socket.send_to(&self.buffer, addr) {
            Ok(num_bytes_read) => Ok(num_bytes_read),
            Err(error) => Err(UdpPacketError::NetworkIo { 
                description: String::from("failed to send a packet"), 
                source: error
            })
        }
    }

    pub fn recv(&mut self, udp_socket: &net::UdpSocket) -> Result<usize> {
        match udp_socket.recv(&mut self.buffer) {
            Ok(num_bytes_read) => Ok(num_bytes_read),
            Err(error) => Err(UdpPacketError::NetworkIo { 
                description: String::from("failed to receive a packet"), 
                source: error
            })
        }
    }

    pub fn recv_from(&mut self, udp_socket: &net::UdpSocket) -> Result<(usize, net::SocketAddr)> {
        match udp_socket.recv_from(&mut self.buffer) {
            Ok(num_bytes_addr) => Ok(num_bytes_addr),
            Err(error) => Err(UdpPacketError::NetworkIo { 
                description: String::from("failed to receive a packet"), 
                source: error
            })
        }
    }

    pub fn write_from_slice(&mut self, slice: &[u8], margin: Option<usize>) -> Result<()> {
        let margin = match margin {
            Some(value) => value,
            None => 0
        };
        if self.position + slice.len() + margin >= UDP_PACKET_MAX_SIZE_BYTES {
            return Err(UdpPacketError::OutOfBounds { 
                length: UDP_PACKET_MAX_SIZE_BYTES, 
                index: self.position + slice.len()
            })
        }
        for (index, element) in slice.iter().enumerate() {
            self.buffer[self.position + index] = *element;
        }
        self.position += slice.len();
        Ok(())
    }

    pub fn read_to_slice(&self, start: usize, length: usize) -> Result<&[u8]> {
        if start + length >= UDP_PACKET_MAX_SIZE_BYTES {
            return Err(UdpPacketError::OutOfBounds { 
                length: UDP_PACKET_MAX_SIZE_BYTES, 
                index: start + length
            })
        }
        Ok(&self.buffer[start..(start + length)])
    }

    pub fn write_domain_name(&mut self, domain_name: &DomainName, margin: Option<usize>) -> Result<()> {
        self.write_from_slice(&domain_name.bytes, margin)?;
        Ok(())
    }

    pub fn read_domain_name(&mut self) -> Result<DomainName> {
        let mut values: Vec<&[u8]> = Vec::new();
        let mut num_jumps = 0;
        let mut has_jumped = false;
        let mut position = self.position;
        let mut num_bytes_read_before_jump = 0;
        while self.buffer[position] != 0x00 {
            if num_jumps > MAX_JUMPS {
                return Err(UdpPacketError::MaxJumpsExceeded)
            } else if self.buffer[position] & 0xc0 == 0xc0 {
                let offset = (((self.buffer[position] & 0x3f) as u16) << 8) | (self.buffer[position + 1] as u16);
                position = offset as usize;
                has_jumped = true;
                num_jumps += 1;
            } else {
                let length = (self.buffer[position] + 1) as usize;
                if length > LABEL_MAX_LENGTH_BYTES {
                    return Err(UdpPacketError::MalformedDomainName { 
                        domain_name: String::from("a domain name"), 
                        description: format!("the length of a label exceeds 63 bytes"), 
                        source: Malformation::LabelTooLong
                    })
                }
                values.push(self.read_to_slice(position, length)?);
                position += length;
                if !has_jumped {
                    num_bytes_read_before_jump += length
                }
            }
        }
        let mut result = values.concat();
        result.push(0);
        if result.len() > NAME_MAX_LENGTH_BYTES {
            return Err(UdpPacketError::MalformedDomainName { 
                domain_name: match String::from_utf8(result.to_vec()) {
                    Ok(string) => string,
                    Err(error) => return Err(UdpPacketError::FromUtf8 { 
                        bytes: result, 
                        source: error 
                    })
                },
                description: format!("domain name length exceeds 255 bytes"), 
                source: Malformation::NameTooLong
            })
        }
        match has_jumped {
            true => self.position += num_bytes_read_before_jump + 2,
            false => self.position += result.len()
        };
        Ok(DomainName { bytes: result })
    }

    pub fn read_character_string(&mut self) -> Result<CharacterString> {
        let length = self.buffer[self.position] as usize;
        let bytes = self.read_to_slice(self.position, length + 1)?.to_vec();
        Ok(CharacterString {
            length,
            bytes
        })
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
        udp_packet.write_from_slice(&slice, None).expect("Failed to write to packet.");
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
        udp_packet.write_from_slice(&slice, None).expect("Failed to write to packet.");
        assert_eq!(udp_packet, UdpPacket {
            buffer: buffer,
            position: 24
        });
    }

    #[test]
    fn write_string_test() {
        let mut udp_packet: UdpPacket = UdpPacket::new();
        udp_packet.write_domain_name(&DomainName::from_str(dns_message::TEST_DOMAIN).expect("Failed to construct DomainName."), None).expect("Failed to write to packet.");
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