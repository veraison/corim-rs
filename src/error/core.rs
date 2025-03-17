// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CoreError {
    Unknown,
}

impl std::error::Error for CoreError {}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown CoreError encountered"),
        }
    }
}
