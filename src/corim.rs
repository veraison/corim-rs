// SPDX-License-Identifier: MIT

//! # Concise Reference Integrity Manifest (CoRIM) Implementation
//!
//! This module provides a complete implementation of CoRIM (Concise Reference Integrity Manifest)
//! structures according to the specification. CoRIM enables expressing reference integrity
//! measurements for software and hardware components using CBOR encoding.
//!
//! ## Core Types
//!
//! - [`Corim`] - The top-level type representing either a signed or unsigned manifest
//! - [`CorimMap`] - The main manifest structure containing tags and metadata (CBOR tag 501)
//! - [`COSESign1Corim`] - A signed manifest wrapper using COSE_Sign1 (CBOR tag 18)
//!
//! ## Key Features
//!
//! * **Multiple Tag Types**: Support for CoSWID, CoMID, and CoTL tags
//! * **Flexible Identification**: Manifests can be identified by UUID or string
//! * **Signing Support**: Both signed (COSE_Sign1) and unsigned manifests
//! * **Validity Periods**: Optional time-based validity for manifests and signatures
//! * **Entity Attribution**: Track manifest creators and signers
//! * **Extensibility**: Extension points for future capabilities
//!
//! ## Data Model
//!
//! The CoRIM structure follows this general hierarchy:
//!
//! ```text
//! Corim
//! ├── CorimMap (unsigned)
//! │   ├── id
//! │   ├── tags
//! │   ├── dependent-rims
//! │   ├── profile
//! │   ├── rim-validity
//! │   ├── entities
//! │   └── extension
//! │
//! └── COSESign1Corim (signed)
//!     ├── protected
//!     ├── unprotected
//!     ├── payload
//!     └── signature
//! ```
//!
//! ## Example Usage
//!
//! ```rust
//! use corim_rs::corim::{Corim, CorimMap, CorimIdTypeChoice, TaggedUnsignedCorimMap};
//!
//! // Create an unsigned CoRIM
//! let rim = Corim::TaggedUnsignedCorimMap(
//!     TaggedUnsignedCorimMap::new(
//!         CorimMap {
//!             id: "Corim-Unique-Identifier-01".to_string().into(),
//!             tags: vec![].into(),
//!             dependent_rims: None,
//!             profile: None,
//!             rim_validity: None,
//!             entities: None,
//!             extension: None
//!         }
//!     )
//! );
//! ```
//!
//! ## CBOR Tags
//!
//! This implementation uses the following CBOR tags:
//! - 501: Unsigned CoRIM manifest
//! - 18: COSE_Sign1 signed manifest
//!
//! ## Specification Compliance
//!
//! This implementation adheres to the CoRIM specification and supports all mandatory
//! and optional fields defined in the standard.

use crate::{
    comid::ConciseMidTag, core::Bytes, coswid::ConciseSwidTag, cotl::ConciseTlTag, generate_tagged,
    Digest, ExtensionMap, Int, OidType, OneOrMany, TaggedBytes, TaggedConciseMidTag,
    TaggedConciseSwidTag, TaggedConciseTlTag, Text, Time, Tstr, Uri, UuidType,
};

use derive_more::{Constructor, From, TryFrom};
use serde::{Deserialize, Serialize};
/// Represents a Concise Reference Integrity Manifest (CoRIM)
pub type Corim<'a> = ConciseRimTypeChoice<'a>;

pub type SignedCorim<'a> = TaggedCOSESign1Corim<'a>;

pub type UnsignedCorimMap<'a> = CorimMap<'a>;

/// A type choice representing either a signed or unsigned CoRIM manifest
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom)]
pub enum ConciseRimTypeChoice<'a> {
    /// An unprotected CoRIM with CBOR tag 501
    TaggedUnsignedCorimMap(TaggedUnsignedCorimMap<'a>),
    /// A COSE Sign1 protected CoRIM
    SignedCorim(SignedCorim<'a>),
}

generate_tagged!(
    (
        501,
        TaggedUnsignedCorimMap,
        CorimMap<'a>,
        'a,
        "A CBOR tagged, unsigned CoRIM Map."
    ),
    (
        18,
        TaggedCOSESign1Corim,
        COSESign1Corim<'a>,
        'a,
        "A CBOR tagged, signed CoRIM."
    )
);

/// The main CoRIM manifest structure containing all reference integrity data
/// and associated metadata. Tagged with CBOR tag 501.#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, Constructor)]
pub struct CorimMap<'a> {
    /// Unique identifier for the CoRIM
    pub id: CorimIdTypeChoice<'a>,
    /// Collection of tags contained in this CoRIM
    pub tags: OneOrMany<ConciseTagTypeChoice<'a>>,
    /// Optional references to other CoRIMs this one depends on
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dependent-rims")]
    pub dependent_rims: Option<Vec<CorimLocatorMap<'a>>>,
    /// Optional profile information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileTypeChoice<'a>>,
    /// Optional validity period for the CoRIM
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "rim-validity")]
    pub rim_validity: Option<ValidityMap>,
    /// Optional list of entities associated with this CoRIM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<OneOrMany<CorimEntityMap<'a>>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<CorimMapExtension>,
}

/// Represents either a string or UUID identifier for a CoRIM
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom)]
pub enum CorimIdTypeChoice<'a> {
    /// Text string identifier
    Tstr(Tstr<'a>),
    /// UUID identifier
    Uuid(UuidType),
}

impl<'a> From<&'a str> for CorimIdTypeChoice<'a> {
    fn from(s: &'a str) -> Self {
        CorimIdTypeChoice::Tstr(s.into())
    }
}

/// Types of tags that can be included in a CoRIM
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom)]
pub enum ConciseTagTypeChoice<'a> {
    /// A Concise Software Identity (CoSWID) tag
    Swid(TaggedConciseSwidTag<'a>),
    /// A Concise Module Identity (CoMID) tag
    Mid(TaggedConciseMidTag<'a>),
    /// A Concise Trust List (CoTL) tag
    Tl(TaggedConciseTlTag<'a>),
}

impl<'a> From<ConciseSwidTag<'a>> for ConciseTagTypeChoice<'a> {
    fn from(value: ConciseSwidTag<'a>) -> Self {
        Self::Swid(value.into())
    }
}
impl<'a> From<ConciseMidTag<'a>> for ConciseTagTypeChoice<'a> {
    fn from(value: ConciseMidTag<'a>) -> Self {
        Self::Mid(value.into())
    }
}
impl<'a> From<ConciseTlTag<'a>> for ConciseTagTypeChoice<'a> {
    fn from(value: ConciseTlTag<'a>) -> Self {
        Self::Tl(value.into())
    }
}

/// Location and optional thumbprint of a dependent CoRIM
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, Constructor)]
pub struct CorimLocatorMap<'a> {
    /// URI(s) where the dependent CoRIM can be found
    pub href: OneOrMany<Uri<'a>>,
    /// Optional cryptographic thumbprint for verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<Digest<'a>>,
}

/// Profile identifier that can be either a URI or OID
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom)]
pub enum ProfileTypeChoice<'a> {
    /// URI-based profile identifier
    Uri(Uri<'a>),
    /// OID-based profile identifier
    OidType(OidType),
}

/// Defines the validity period for a CoRIM or signature
#[repr(C)]
#[derive(Default, Debug, Serialize, Deserialize, From, Constructor)]
pub struct ValidityMap {
    /// Optional start time of the validity period
    #[serde(rename = "not-before")]
    pub not_before: Option<Time>,
    /// Required end time of the validity period
    #[serde(rename = "not-after")]
    pub not_after: Time,
}

/// Information about an entity associated with the CoRIM
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, Constructor)]
pub struct CorimEntityMap<'a> {
    /// Name of the entity
    #[serde(rename = "entity-name")]
    pub entity_name: Text<'a>,
    /// Optional registration identifier for the entity
    #[serde(rename = "reg-id")]
    pub reg_id: Option<Uri<'a>>,
    /// Role of the entity in relation to the CoRIM
    pub role: CorimRoleTypeChoice,
    /// Optional extensible attributes
    pub extension: Option<ExtensionMap<'a>>,
}

/// Roles that entities can have in relation to a CoRIM manifest
#[derive(Debug, Serialize, Deserialize, From, TryFrom)]
#[repr(u8)]
pub enum CorimRoleTypeChoice {
    /// Entity that created the manifest content
    ManifestCreator = 1,

    /// Entity that cryptographically signed the manifest
    ManifestSigner = 2,
}

/// Extension map for CoRIM-specific extensions
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, Constructor)]
pub struct CorimMapExtension {
    /// Raw bytes containing the extension data
    #[serde(flatten)]
    pub bytes: TaggedBytes,
}

/// COSE_Sign1 structure for a signed CoRIM with CBOR tag 18
#[derive(Debug, Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct COSESign1Corim<'a> {
    /// Protected header containing signing metadata (must be integrity protected)
    pub protected: ProtectedCorimHeaderMap<'a>,
    /// Unprotected header attributes (not integrity protected)
    pub unprotected: Option<ExtensionMap<'a>>,
    /// The actual CoRIM payload being signed
    pub payload: TaggedUnsignedCorimMap<'a>,
    /// Cryptographic signature over the protected header and payload
    pub signature: TaggedBytes,
}

/// Protected header for a signed CoRIM
#[derive(Default, Debug, Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct ProtectedCorimHeaderMap<'a> {
    /// Algorithm identifier for the signature
    pub alg: Int,
    /// Content type indicator (should be "application/rim+cbor")
    #[serde(rename = "content-type")]
    pub content_type: Text<'a>,
    /// Key identifier for the signing key
    pub kid: Bytes,
    /// CoRIM-specific metadata
    #[serde(rename = "corim-meta")]
    pub corim_meta: CorimMetaMap<'a>,
    /// Optional COSE header parameters
    #[serde(flatten)]
    #[serde(rename = "cose-map")]
    pub cose_map: Option<CoseMap<'a>>,
}

/// Metadata about the CoRIM signing operation
#[derive(Default, Debug, Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct CorimMetaMap<'a> {
    /// Information about the signer
    pub signer: CorimSignerMap<'a>,
    /// Optional validity period for the signature
    #[serde(rename = "signature-validity")]
    pub signature_validity: Option<ValidityMap>,
}

/// Information about the entity that signed the CoRIM
#[derive(Default, Debug, Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct CorimSignerMap<'a> {
    /// Name of the signing entity
    #[serde(rename = "signer-name")]
    pub signer_name: EntityNameTypeChoice<'a>,
    /// Optional URI identifying the signer
    #[serde(rename = "signer-uri")]
    pub signer_uri: Option<Uri<'a>>,
    /// Optional COSE-specific extensions
    pub extension: Option<CoseMap<'a>>,
}

/// Type alias for entity names using text strings
pub type EntityNameTypeChoice<'a> = Text<'a>;

/// Type alias for COSE map extensions
pub type CoseMap<'a> = ExtensionMap<'a>;
