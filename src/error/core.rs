// SPDX-License-Identifier: MIT

#[derive(Debug, PartialEq, Eq)]
pub enum CoreError {
    InvalidValue(String),
    Unknown,
}

impl std::error::Error for CoreError {}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidValue(s) => write!(f, "invalid value: \"{s}\""),
            Self::Unknown => write!(f, "unknown CoreError encountered"),
        }
    }
}
