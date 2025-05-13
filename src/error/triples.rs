// SPDX-License-Identifier: MIT

use crate::HashAlgorithm;

#[derive(Debug)]
pub enum TriplesError {
    EmptyTripleRecordCondition,
    EmptyClassMap,
    EmptyEnvironmentMap,
    EmptyMeasurementValuesMap,
    InvalidIpAddrType,
    InvalidMacAddrType,
    DigestAlreadyExists(String, HashAlgorithm),
    Unknown,
}

impl std::error::Error for TriplesError {}

impl std::fmt::Display for TriplesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIpAddrType => write!(f, "invalid IP address type"),
            Self::InvalidMacAddrType => write!(f, "invalid MAC address type"),
            Self::EmptyMeasurementValuesMap => {
                write!(
                    f,
                    "a MeasurementValuesMap must have at least one non-empty field"
                )
            }
            Self::EmptyEnvironmentMap => {
                write!(
                    f,
                    "an EnvironmentMap must have at least one non-empty field"
                )
            }
            Self::EmptyClassMap => {
                write!(f, "a ClassMap must have at least one non-empty field")
            }
            Self::EmptyTripleRecordCondition => {
                write!(f, "a TripleRecord must have at least one non-empty field")
            }
            Self::DigestAlreadyExists(label, alg) => {
                write!(f, "{alg} digest for label {label} already exists")
            }
            Self::Unknown => write!(f, "unknown TriplesError encountered"),
        }
    }
}
