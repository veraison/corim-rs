// SPDX-License-Identifier: MIT

//! # corim-rs
//!
//! A Rust implementation of the Concise Reference Integrity Manifest (CoRIM) specification.
//!
//! This library provides types and structures for working with:
//! - CoRIM manifests (Reference Integrity Manifests)
//! - CoMID tags (Concise Module Identifiers)
//! - CoSWID tags (Concise Software Identifiers)
//! - CoTL tags (Concise Trust Lists)
//!
//! The implementation follows the CoRIM specification and uses CBOR for serialization.
//!
//! Anywhere a `Vec<T>` is used in this implementation of the CoRIM Specification should never be empty.
//!
//! ## Optional: `openssl` feature
//!
//! Enable `feature = "openssl"` for COSE signing/verification (`corim_rs::openssl`) and
//! **x5chain PKIX trust verification** (`corim_rs::x509chain`).
//!
//! ### Primary integrator API
//!
//! - [`load_trust_anchors`] — load [`TrustAnchors`] from DER/PEM paths (optional CRLs;
//!   default [`CrlPolicy::Strict`]; use [`TrustAnchors::with_crl_policy`] for permissive)
//! - [`SignedCorim::verify_with_x5chain`] — end-to-end: COSE x5chain → leaf policy → PKIX
//!   → optional CRL → COSE Sign1 verify. Array elements after the leaf are concatenated
//!   and parsed as one or more DER intermediate certificates.
//!
//! Decode the CoRIM first (`Corim::from_cbor`). External-key verification without PKIX
//! remains [`SignedCorim::verify_signature`].
//!
//! ### Advanced / tooling API (`x509chain` module)
//!
//! - [`verify_with_x5chain`] — **free function**: PKIX + optional CRL on a presented DER
//!   chain only; **does not verify COSE**. Not the same as [`SignedCorim::verify_with_x5chain`].
//! - [`verify_x509_chain`] — structural signature chain only (no trust anchors, no CRL, no leaf policy)
//! - [`TrustAnchors::from_der_anchors_and_crls`], [`parse_certificate_der_or_pem`], [`SignedCorim::x509_certificate_ders`]
//!
//! [`TrustAnchors`] uses `None` anchors → OS store at verify time (`rustls-native-certs`);
//! `Some` → explicit anchors only. Unparseable OS-store entries are skipped.
//!
//! ```toml
//! corim-rs = { version = "0.2", features = ["openssl"] }
//! ```
//!
//! Default features are unchanged (`default = []`).

/// Macros for easier implementation definitions.
#[macro_use]
pub(crate) mod macros;

/// Module containing CoMID tag types and structures
pub mod comid;

/// Core types and utilities used across the library
pub mod core;

/// CoRIM manifest types and structures
pub mod corim;

/// CoSWID tag types and structures
pub mod coswid;

/// CoTL (Trust List) types and structures
pub mod cotl;

/// Triple types used in CoMID tags
pub mod triples;

/// Fixed Bytes Arrays
pub mod fixed_bytes;

/// Errors for easily handling problems.
pub mod error;

/// Custom CoRIM Results.
pub mod result;

/// Provides the Emtpy Trait.
pub mod empty;

/// Provides the Number Traits.
pub mod numbers;

/// Optional signing implementation
#[cfg(feature = "openssl")]
pub mod openssl;
#[cfg(feature = "openssl")]
pub use openssl::*;

/// PKIX path validation and trust anchors for CoRIM x5chain verification.
#[cfg(feature = "openssl")]
pub mod x509chain;
#[cfg(feature = "openssl")]
pub use x509chain::*;

/// Test utilities
#[cfg(test)]
pub(crate) mod test;

// Use all public items from each module
pub use comid::*;
pub use core::*;
pub use corim::*;
pub use coswid::*;
pub use cotl::*;
pub use empty::*;
pub use error::*;
pub use fixed_bytes::*;
pub use numbers::*;
pub use result::*;
pub use triples::*;
