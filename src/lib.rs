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

/// Module containing macros used for various purposes in other modules. The macros
/// are primarily used to reduce repetitive boilerplate code and to facilitate code
/// maintenance.
pub mod macros {
/// A macro used to construct an enum commonly used in the dns_message module,
/// namely a public enum which can be converted to and from u16 and implementing the
/// Default trait such that the first variant is returned when default() is called.
/// 
/// Note that the variants of the enum cannot include anything other than an identifier,
/// which means that no named or unnamed parameters can be included in a variant.
#[macro_export]
macro_rules! build_enum {
    ($name: ident; $($variant: ident = $value: expr),*$(,)?) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq)]
        pub enum $name {
            #[default]
            $($variant,)*
        }
        impl std::convert::TryFrom<u16> for $name {
            type Error = String;

            fn try_from(value: u16) -> Result<Self, Self::Error> { 
                match value {
                    $($value => Ok(Self::$variant),)*
                    _ => Err(format!("Invalid u16 ({}).", value))
                }
            }
        }
        impl std::convert::TryInto<u16> for $name {
            type Error = String;

            fn try_into(self) -> Result<u16, Self::Error> { 
                match self {
                    $(Self::$variant => Ok($value),)*
                }
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
        impl std::str::FromStr for $name {
            type Err = String;
        
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(stringify!($variant) => Ok(Self::$variant),)*
                    _ => Err(format!("Encountered invalid variant '{}'.", s))
                }
            }
        }
    };
}
}