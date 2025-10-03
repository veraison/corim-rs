// SPDX-License-Identifier: MIT

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoservError {
    #[error("Invalid JSON name `{0}`")]
    InvalidName(String),
    #[error("Invalid CBOR key `{0}`")]
    InvalidKey(i32),
    #[error("The verification key type is not compatible with the serialization format")]
    WrongVerificationKeyType,
    #[error("Trying to serialize an undefined verification key")]
    VerificationKeyUndefined,
}
