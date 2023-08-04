/// Module containing conversion functionality for primitives not provided
/// by the standard library, such as the conversion u32 -> u8.
pub mod conversions;

/// Module containing utilities for working with DNS queries, such as specialised
/// structs (e.g. DnsHeader, DnsQuestion, etc.), and the functionality needed to both
/// read and write them from/to a UDP packet.
pub mod dns_message;

/// Utilities for formatting data in the form of a table, useful for various terminal
/// applications.
pub mod tabulation {
    // TODO: Implement proper error handling for this module.
    // TODO: Make Table generic such that data: Vec<Vec<Option<T>>>.
    // TODO: Maybe add a trait for conversion into a table?
    // TODO: Make construction more efficient and use fewer steps.
    // TODO: Make it possible to indicate that a given member of Table.data should not be padded.
    // TODO: Maybe implement the Display trait? (If even possible...)
    // This is equivalent to displaying the table using a &self, instead of &mut self.

    use std::collections::HashSet;

    #[derive(Debug)]
    pub struct Table {
        num_columns: usize,
        pub data: Vec<Vec<Option<String>>>
    }

    impl Table {
        pub fn new(data: Option<Vec<Vec<Option<String>>>>) -> Self {
            match data {
                Some(data) => {
                    let lengths: HashSet<usize> = data.iter().map(|vec| vec.len()).collect();
                    if lengths.len() != 1 {
                        panic!("Cannot generate a table with no rows (data.len() = 0) or rows of different lengths (data.len() != 1).");
                    }
                    Self { num_columns: data[0].len(), data }
                },
                None => Self { num_columns: 0, data: Vec::new() }
            }
        }

        pub fn push(&mut self, value: Vec<Option<String>>) {
            match self.num_columns {
                0 => {
                    self.num_columns = value.len();
                    self.data.push(value);
                },
                _ => {
                    if value.len() != self.num_columns {
                        panic!("Cannot push value with value.len() != self.num_columns");
                    }
                    self.data.push(value);
                }
            }
        }

        pub fn get_column(&self, column: usize) -> Vec<&Option<String>> {
            if column >= self.num_columns {
                panic!("Attempted to access Vec out of bounds.");
            }
            self.data.iter().map(|row| match row.get(column) {
                Some(value) => value,
                None => &None
            }).collect()
        }

        pub fn get_column_max_length(&self, column: usize) -> usize {
            let column = self.get_column(column);
            let mut max_length = 0;
            for value in column {
                match value {
                    Some(value) => if value.len() > max_length {
                        max_length = value.len();
                    },
                    _ => ()
                }
            }
            max_length
        }

        pub fn insert_padding(&mut self) {
            let mut max_lengths: Vec<usize> = Vec::new();
            for column in 0..self.num_columns {
                max_lengths.push(self.get_column_max_length(column));
            }
            for row in self.data.iter_mut() {
                for (index, value) in row.iter_mut().enumerate() {
                    match value {
                        Some(string) => {
                            for _ in 0..(max_lengths[index] - string.len()) {
                                string.push(' ');
                            }
                        },
                        None => {
                            let string = vec![' '; max_lengths[index]].into_iter().collect();
                            *value = Some(string);
                        }
                    }
                }
            }
        }
        
        pub fn write(&mut self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.insert_padding();
            for row in self.data.iter() {
                let vec_str: Vec<&str> = row.iter().map(|option| option.as_deref().unwrap()).collect();
                writeln!(f, "{}", vec_str.join("\t"))?;
            }
            Ok(())
        }
    }
}

/// Module containing utilities for handling a DNS-compatible UDP packet, i.e.
/// a UDP packet of size 512 bytes. The module's functionality is specifically
/// adapted to the DNS protocol and is therefore unsuitable for use in non-DNS
/// applications.
pub mod udp_packet;

/// Module containing macros used for various purposes in other modules. The macros
/// are primarily used to reduce repetitive boilerplate code and to facilitate code
/// maintenance.
pub mod macros { 
// TODO: Replace () with some other type which can be converted into another error type.

/// Error type for the build_enum! macro.
#[derive(Debug)]
pub enum BuildEnumError {
    /// Encountered an invalid u16 during conversion to variant.
    InvalidU16 {
        uint_16: u16            // The integer that caused the error.
    },

    /// Encopuntered an invalid &str during conversion to variant.
    InvalidStrVariant {
        variant_str: String     // The variant &str which caused the error.
    }
}

impl std::fmt::Display for BuildEnumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStrVariant { 
                variant_str
             } => write!(f, "encountered invalid str '{}' while converting to variant", variant_str),
             Self::InvalidU16 { 
                uint_16
             } => write!(f, "encountered invalid u16 {} while converting to variant", uint_16)
        }
    }
}

impl std::error::Error for BuildEnumError {}

/// A macro used to construct an enum commonly used in the dns_message module,
/// namely a public enum which can be converted to and from u16 and implementing the
/// Default trait such that the first variant is returned when default() is called.
/// 
/// Note that the variants of the enum cannot include anything other than an identifier,
/// which means that no named or unnamed parameters can be included in a variant.
#[macro_export]
macro_rules! build_enum {
    ($name:ident; $($variant:ident = $value:expr),*$(,)?) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq)]
        pub enum $name {
            #[default]
            $($variant,)*
        }
        impl std::convert::TryFrom<u16> for $name {
            type Error = crate::macros::BuildEnumError;

            fn try_from(value: u16) -> Result<Self, Self::Error> { 
                match value {
                    $($value => Ok(Self::$variant),)*
                    _ => Err(crate::macros::BuildEnumError::InvalidU16 {
                        uint_16: value,
                    })
                }
            }
        }
        impl std::convert::TryInto<u16> for $name {
            type Error = ();

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
            type Err = crate::macros::BuildEnumError;
        
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(stringify!($variant) => Ok(Self::$variant),)*
                    _ => Err(crate::macros::BuildEnumError::InvalidStrVariant {
                        variant_str: String::from(s),
                    })
                }
            }
        }
    };
}
}