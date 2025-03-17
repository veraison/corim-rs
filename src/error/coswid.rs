// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CoswidError {
    Unknown,
}

impl std::error::Error for CoswidError {}

impl std::fmt::Display for CoswidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown CoswidError encountered"),
        }
    }
}
