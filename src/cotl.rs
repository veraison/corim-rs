// SPDX-License-Identifier: MIT

//! Module for handling Concise Trust List (CoTL) tags.
//!
//! This module implements the CoTL specification, providing structures and types for
//! managing lists of trusted CoMID and CoSWID tags. CoTL tags are used to establish
//! trust relationships and control tag distribution in a Reference Integrity Manifest (RIM).
//!
//! # Key Components
//!
//! - [`ConciseTlTag`]: The main CoTL tag structure (CBOR tag 507)
//! - [`TagIdentityMap`]: Identification information for referenced tags
//! - [`ValidityMap`]: Validity periods for trust lists
//!
//! # Trust List Management
//!
//! CoTL tags support:
//! - Listing trusted CoMID and CoSWID tags
//! - Defining validity periods for trust relationships
//! - Extensible attributes for future expansion
//!
//! # Example
//!
//! ```rust
//! use corim_rs::cotl::{ConciseTlTag, TagIdentityMap};
//! use corim_rs::core::ValidityMap;
//!
//! // Create a basic CoTL tag
//! let tag = ConciseTlTag {
//!     tag_identity: TagIdentityMap {
//!         tag_id: "example-trust-list".into(),
//!         tag_version: None,
//!     },
//!     tags_list: vec![].into(),  // Add trusted tags here
//!     tl_validity: ValidityMap {
//!         not_before: None,
//!         not_after: 1735689600,  // Dec 31, 2024
//!     },
//!     extensions: None,
//! };
//! ```

use serde::{Deserialize, Serialize};

use crate::{ExtensionMap, OneOrMore, TagIdentityMap, ValidityMap};

// A Concise Trust List (CoTL) tag structure tagged with CBOR tag 507
///
/// CoTL tags provide a mechanism to maintain lists of trusted CoMID and CoSWID tags.
/// They can be used to establish trust relationships and manage tag distribution.
#[derive(Serialize, Deserialize)]
#[serde(tag = "507")]
#[repr(C)]
pub struct ConciseTlTag {
    /// Identity information for this trust list tag
    #[serde(rename = "tag-identity")]
    pub tag_identity: TagIdentityMap,

    /// List of trusted tags referenced by this trust list
    #[serde(rename = "tags-list")]
    pub tags_list: OneOrMore<TagIdentityMap>,

    /// Validity period for this trust list
    #[serde(rename = "tl-validity")]
    pub tl_validity: ValidityMap,

    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionMap>,
}
