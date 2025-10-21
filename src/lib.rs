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

/// Macros for easier implementation definitions.
pub(crate) mod macros;

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
