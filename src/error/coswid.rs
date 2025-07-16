// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CoswidError {
    UnsetMandatoryField(String, String),
    InvalidFieldValue(String, String, String),
    InvalidValue(String),
    Custom(String),
    Unknown,
}

impl CoswidError {
    pub fn custom(msg: &str) -> Self {
        Self::Custom(msg.to_string())
    }

    pub fn invalid_value(msg: &str) -> Self {
        Self::InvalidValue(msg.to_string())
    }
}

impl std::error::Error for CoswidError {}

impl std::fmt::Display for CoswidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsetMandatoryField(object, field) => {
                write!(f, "{object} field(s) {field} must be set")
            }
            Self::InvalidFieldValue(object, field, message) => {
                write!(f, " invalid {object}.{field} value: {message}")
            }
            Self::InvalidValue(message) => write!(f, "invalid value: {message}"),
            Self::Custom(message) => f.write_str(message.as_str()),
            Self::Unknown => write!(f, "unknown CoswidError encountered"),
        }
    }
}
