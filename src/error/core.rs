// SPDX-License-Identifier: MIT

#[derive(Debug, PartialEq, Eq)]
pub enum CoreError {
    InvalidValue(String),
    Custom(String),
    Unknown,
}

impl CoreError {
    pub fn custom<D: std::fmt::Display>(message: D) -> Self {
        CoreError::Custom(message.to_string())
    }
}

impl std::error::Error for CoreError {}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidValue(s) => write!(f, "invalid value: {s}"),
            Self::Custom(s) => f.write_str(s.as_str()),
            Self::Unknown => write!(f, "unknown CoreError encountered"),
        }
    }
}
