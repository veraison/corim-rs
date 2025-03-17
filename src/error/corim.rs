// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CorimError {
    Unknown,
}

impl std::error::Error for CorimError {}

impl std::fmt::Display for CorimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown CorimError encountered"),
        }
    }
}
