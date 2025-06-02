// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CorimError {
    InvalidConciseTagTypeChoice,
    InvalidCorimRole(String),
    Unknown,
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
            Self::Unknown => write!(f, "unknown CorimError encountered"),
        }
    }
}
