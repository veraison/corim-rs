// SPDX-License-Identifier: MIT

use crate::Label;

#[derive(Debug)]
pub enum ComidError {
    EmptyTriplesMap,
    InvalidComidRole(Label<'static>),
    Unknown,
}

impl std::error::Error for ComidError {}

impl std::fmt::Display for ComidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTriplesMap => {
                write!(f, "a TriplesMap must have at least one non-empty field")
            }
            Self::InvalidComidRole(role) => write!(f, "invalid CoMID role {role}"),
            Self::Unknown => write!(f, "unknown ComidError encountered"),
        }
    }
}
