// SPDX-License-Identifier: MIT

/// Why loading a CRL file failed during trust-material setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X5chainCrlLoadErrorKind {
    NoCrlPemBlock,
    InvalidPemBlockType(String),
    Parse(String),
}

#[derive(Debug)]
pub enum X5chainError {
    HeaderNotSet,
    EmptyChain,
    VerificationFailed(String),
    CertificateExpired,
    CertificateNotYetValid,
    CertificateRevoked,
    CrlExpired,
    CrlNotYetValid,
    CrlMissingNextUpdate,
    UnsupportedCrl(String),
    InvalidCertificateSignature(String),
    SigningCertMustNotBeCa,
    SigningCertLacksDigitalSignature,
    UnsupportedKeyType(String),
    CoseSignatureVerificationFailed(String),
    CrlLoadError {
        path: String,
        kind: X5chainCrlLoadErrorKind,
    },
}

impl std::error::Error for X5chainError {}

impl std::fmt::Display for X5chainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderNotSet => f.write_str("x5chain: header not set in CoRIM"),
            Self::EmptyChain => f.write_str("x5chain: empty chain"),
            Self::VerificationFailed(reason) => {
                write!(f, "x5chain verification failed: {reason}")
            }
            Self::CertificateExpired => f.write_str("x5chain: certificate has expired"),
            Self::CertificateNotYetValid => f.write_str("x5chain: certificate is not yet valid"),
            Self::CertificateRevoked => f.write_str("x5chain: certificate revoked"),
            Self::CrlExpired => f.write_str("x5chain: CRL has expired"),
            Self::CrlNotYetValid => f.write_str("x5chain: CRL is not yet valid"),
            Self::CrlMissingNextUpdate => f.write_str("x5chain: CRL has no nextUpdate"),
            Self::UnsupportedCrl(detail) => write!(f, "x5chain: unsupported CRL: {detail}"),
            Self::InvalidCertificateSignature(detail) => write!(f, "x5chain: {detail}"),
            Self::SigningCertMustNotBeCa => {
                f.write_str("x5chain: signing certificate must not be a CA")
            }
            Self::SigningCertLacksDigitalSignature => {
                f.write_str("x5chain: signing certificate lacks digitalSignature key usage")
            }
            Self::UnsupportedKeyType(detail) => {
                write!(f, "x5chain: unsupported key type: {detail}")
            }
            Self::CoseSignatureVerificationFailed(detail) => {
                write!(f, "x5chain: COSE signature verification failed: {detail}")
            }
            Self::CrlLoadError { path, kind } => match kind {
                X5chainCrlLoadErrorKind::NoCrlPemBlock => {
                    write!(
                        f,
                        "x5chain: parsing CRL from {path}: no X509 CRL PEM block found"
                    )
                }
                X5chainCrlLoadErrorKind::InvalidPemBlockType(block_type) => {
                    write!(
                        f,
                        "x5chain: parsing CRL from {path}: invalid PEM block type \"{block_type}\""
                    )
                }
                X5chainCrlLoadErrorKind::Parse(detail) => {
                    write!(f, "x5chain: parsing CRL from {path}: {detail}")
                }
            },
        }
    }
}
