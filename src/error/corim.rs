// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CorimError {
    InvalidConciseTagTypeChoice,
    InvalidCorimRole(String),
    InvalidFieldValue(String, String, String),
    UnsetMandatoryField(String, String),
    CoseHeaderNotSet(i64, String),
    InvalidCoseHeader(i64, String, String),
    InvalidCoseKey(String),
    InvalidSignature,
    OutsideValidityPeriod,
    Custom(String),
    Unknown,
}

impl CorimError {
    pub fn unset_mandatory_field<D: std::fmt::Display>(object: D, field: D) -> Self {
        CorimError::UnsetMandatoryField(object.to_string(), field.to_string())
    }

    pub fn custom<D: std::fmt::Display>(message: D) -> Self {
        CorimError::Custom(message.to_string())
    }
}

impl std::error::Error for CorimError {}

impl std::fmt::Display for CorimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConciseTagTypeChoice => {
                write!(f, "Invalid ConciseTagTypeChoice encountered")
            }
            Self::InvalidCorimRole(role) => {
                write!(f, "Invalid CoRIM role \"{role}\"")
            }
            Self::InvalidFieldValue(object, field, message) => {
                write!(f, " invalid {object}.{field} value: {message}")
            }
            Self::UnsetMandatoryField(object, field) => {
                write!(f, "{object} field(s) {field} must be set")
            }
            Self::CoseHeaderNotSet(value, label) => {
                write!(f, "COSE header {value} ({label}) not set")
            }
            Self::InvalidCoseHeader(value, label, message) => {
                write!(
                    f,
                    "invalid value for COSE header {value} ({label}): {message}"
                )
            }
            Self::InvalidCoseKey(message) => {
                write!(f, "invalid COSE key: {message}")
            }
            Self::OutsideValidityPeriod => {
                write!(f, "current time is outside manifest's validity period")
            }
            Self::InvalidSignature => f.write_str("invalid signature"),
            Self::Custom(message) => f.write_str(message.as_str()),
            Self::Unknown => write!(f, "unknown CorimError encountered"),
        }
    }
}
