// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum ComidError {
    EmptyTriplesMap,
    Unknown,
}

impl std::error::Error for ComidError {}

impl std::fmt::Display for ComidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTriplesMap => {
                write!(f, "a TriplesMap must have at least one non-empty field")
            }
            Self::Unknown => write!(f, "unknown ComidError encountered"),
        }
    }
}
