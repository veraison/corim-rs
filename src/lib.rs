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
//! Anywhere a `Vec<T>` is used in this implementation of the CoRIM Specificaiton should never be empty.

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

/// Test utilities
#[cfg(test)]
pub(crate) mod test;

// Use all public items from each module
use comid::*;
use core::*;
use corim::*;
use coswid::*;
use cotl::*;
use empty::*;
use error::*;
use fixed_bytes::*;
use numbers::*;
use result::*;
use triples::*;
