// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum NumbersError {
    ValueExceedsType,
    NegativeAsUsize,
    ArchitectureLimitExceeded { bits: u8, max_value: String },
    ParseIntError,
    InvalidCBORIntLength { length: usize },
    Unknown,
}

impl std::error::Error for NumbersError {}

impl std::fmt::Display for NumbersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValueExceedsType => write!(f, "value exceeds expected type"),
            Self::NegativeAsUsize => write!(f, "Cannot use negative value as usize"),
            Self::InvalidCBORIntLength { length } => {
                write!(f, "invalid CBOR int length: {}", length)
            }
            Self::ParseIntError => write!(f, "Error parsing integer from &str value"),
            Self::ArchitectureLimitExceeded { bits, max_value } => {
                write!(
                    f,
                    "architecture limit exceeded: {} bits, max value: {}",
                    bits, max_value
                )
            }
            Self::Unknown => write!(f, "unknown NumbersError encountered"),
        }
    }
}
