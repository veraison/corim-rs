// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CotlError {
    UnsetMandatoryField(String, String),
    Custom(String),
    Unknown,
}

impl CotlError {
    pub fn unset_mandatory_field<D: std::fmt::Display>(object: D, field: D) -> Self {
        CotlError::UnsetMandatoryField(object.to_string(), field.to_string())
    }

    pub fn custom<D: std::fmt::Display>(message: D) -> Self {
        CotlError::Custom(message.to_string())
    }
}

impl std::error::Error for CotlError {}

impl std::fmt::Display for CotlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsetMandatoryField(object, field) => {
                write!(f, "{object} field(s) {field} must be set")
            }
            Self::Custom(message) => f.write_str(message.as_str()),
            Self::Unknown => write!(f, "unknown CotlError encountered"),
        }
    }
}
