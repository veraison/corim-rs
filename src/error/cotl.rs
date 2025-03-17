// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CotlError {
    Unknown,
}

impl std::error::Error for CotlError {}

impl std::fmt::Display for CotlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown CotlError encountered"),
        }
    }
}
