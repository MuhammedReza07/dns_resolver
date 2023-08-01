/// Module containing conversion functionality for primitives not provided
/// by the standard library, such as the conversion u32 -> u8.
pub mod conversions;

/// Module containing utilities for working with DNS queries, such as specialised
/// structs (e.g. DnsHeader, DnsQuestion, etc.), and the functionality needed to both
/// read and write them from/to a UDP packet.
pub mod dns_message;

/// Module containing utilities for handling a DNS-compatible UDP packet, i.e.
/// a UDP packet of size 512 bytes. The module's functionality is specifically
/// adapted to the DNS protocol and is therefore unsuitable for use in non-DNS
/// applications.
pub mod udp_packet;