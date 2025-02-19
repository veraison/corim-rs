// SPDX-License-Identifier: MIT

//! Module for handling Concise Reference Integrity Manifest (CoRIM) structures.
//!
//! This module implements the core CoRIM structures as defined in the specification.
//! CoRIM provides a way to express reference integrity measurements for software
//! and hardware components in a concise format using CBOR encoding.
//!
//! # Key Components
//!
//! - [`Corim`]: The top-level manifest type
//! - [`CorimMap`]: Main manifest content (CBOR tag 501)
//! - [`COSESign1Corim`]: Signed manifest wrapper (CBOR tag 18)
//! - [`ValidityMap`]: Validity periods for manifests and signatures
//!
//! # Tag Support
//!
//! CoRIM can include several types of tags:
//! - CoSWID tags: Software identity information
//! - CoMID tags: Module identity information  
//! - CoTL tags: Trust list information
//!
//! # Signing Support
//!
//! CoRIMs can be:
//! - Unprotected (using [`CorimMap`])
//! - COSE Sign1 protected (using [`COSESign1Corim`])
//!
//! # Example
//!
//! ```rust
//! use corim_rs::corim::{Corim, CorimMap, CorimIdTypeChoice};
//!
//! // Create an unprotected CoRIM
//! let rim = Corim::Tagged(CorimMap {
//!     id: CorimIdTypeChoice::Tstr("example-rim".into()),
//!     tags: vec![].into(),  // Add tags here
//!     dependent_rims: None,
//!     profile: None,
//!     rim_validity: None,
//!     entities: None,
//!     extension: None,
//! });
//! ```

use crate::{
    Bytes, ConciseMidTag, ConciseSwidTag, ConciseTlTag, Digest, ExtensionMap, Int, OidType,
    OneOrMore, Role, Text, Time, Tstr, Uri, UuidType,
};

use serde::{Deserialize, Serialize};

/// Represents a Concise Reference Integrity Manifest (CoRIM)
pub type Corim = ConciseRimTypeChoice;

/// Represents the possible forms a CoRIM can take - either tagged or signed
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub enum ConciseRimTypeChoice {
    /// An unprotected CoRIM with CBOR tag 501
    Tagged(CorimMap),
    /// A COSE Sign1 protected CoRIM
    Signed(COSESign1Corim),
}

/// CoRIM structure tagged with CBOR tag 501 containing the main manifest content
#[repr(C)]
#[derive(Serialize, Deserialize)]
#[serde(tag = "501")]
pub struct CorimMap {
    /// Unique identifier for the CoRIM
    pub id: CorimIdTypeChoice,
    /// Collection of tags contained in this CoRIM
    pub tags: OneOrMore<ConciseTagTypeChoice>,
    /// Optional references to other CoRIMs this one depends on
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dependent-rims")]
    pub dependent_rims: Option<Vec<CorimLocatorMap>>,
    /// Optional profile information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileTypeChoice>,
    /// Optional validity period for the CoRIM
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "rim-validity")]
    pub rim_validity: Option<ValidityMap>,
    /// Optional list of entities associated with this CoRIM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<OneOrMore<CorimEntityMap>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<CorimMapExtension>,
}

/// Represents either a string or UUID identifier for a CoRIM
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub enum CorimIdTypeChoice {
    /// Text string identifier
    Tstr(Tstr),
    /// UUID identifier
    Uuid(UuidType),
}

/// Types of tags that can be included in a CoRIM
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub enum ConciseTagTypeChoice {
    /// A Concise Software Identity (CoSWID) tag
    Swid(ConciseSwidTag),
    /// A Concise Module Identity (CoMID) tag
    Mid(ConciseMidTag),
    /// A Concise Trust List (CoTL) tag
    Tl(ConciseTlTag),
}

/// Location and optional thumbprint of a dependent CoRIM
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct CorimLocatorMap {
    /// URI(s) where the dependent CoRIM can be found
    pub href: OneOrMore<Uri>,
    /// Optional cryptographic thumbprint for verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<Digest>,
}

/// Profile identifier that can be either a URI or OID
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub enum ProfileTypeChoice {
    /// URI-based profile identifier
    Uri(Uri),
    /// OID-based profile identifier
    OidType(OidType),
}

/// Defines the validity period for a CoRIM or signature
#[repr(C)]
#[derive(Serialize, Deserialize)]
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
#[derive(Serialize, Deserialize)]
pub struct CorimEntityMap {
    /// Name of the entity
    #[serde(rename = "entity-name")]
    pub entity_name: Text,
    /// Optional registration identifier for the entity
    #[serde(rename = "reg-id")]
    pub reg_id: Option<Uri>,
    /// Role of the entity in relation to the CoRIM
    pub role: Role,
    /// Optional extensible attributes
    pub extension: Option<ExtensionMap>,
}

/// Extension map for CoRIM-specific extensions
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct CorimMapExtension {
    /// Raw bytes containing the extension data
    #[serde(flatten)]
    pub bytes: Bytes,
}

/// COSE_Sign1 structure for a signed CoRIM with CBOR tag 18
#[derive(Serialize, Deserialize)]
#[serde(tag = "18")]
#[repr(C)]
pub struct COSESign1Corim {
    /// Protected header containing signing metadata
    pub protected: ProtectedCorimHeaderMap,
    /// Optional unprotected header attributes
    pub unprotected: Option<ExtensionMap>,
    /// The CoRIM payload being signed
    pub payload: CorimMap,
    /// The cryptographic signature
    pub signature: Bytes,
}

/// Protected header for a signed CoRIM
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ProtectedCorimHeaderMap {
    /// Algorithm identifier for the signature
    pub alg: Int,
    /// Content type indicator (should be "application/rim+cbor")
    #[serde(rename = "content-type")]
    pub content_type: String,
    /// Key identifier for the signing key
    pub kid: Bytes,
    /// CoRIM-specific metadata
    #[serde(rename = "corim-meta")]
    pub corim_meta: CorimMetaMap,
    /// Optional COSE header parameters
    #[serde(flatten)]
    #[serde(rename = "cose-map")]
    pub cose_map: Option<CoseMap>,
}

/// Metadata about the CoRIM signing operation
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct CorimMetaMap {
    /// Information about the signer
    pub signer: CorimSignerMap,
    /// Optional validity period for the signature
    #[serde(rename = "signature-validity")]
    pub signature_validity: Option<ValidityMap>,
}

/// Information about the entity that signed the CoRIM
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct CorimSignerMap {
    /// Name of the signing entity
    #[serde(rename = "signer-name")]
    pub signer_name: EntityNameTypeChoice,
    /// Optional URI identifying the signer
    #[serde(rename = "signer-uri")]
    pub signer_uri: Option<Uri>,
    /// Optional COSE-specific extensions
    pub extension: Option<CoseMap>,
}

/// Type alias for entity names using text strings
pub type EntityNameTypeChoice = Text;
/// Type alias for COSE map extensions
pub type CoseMap = ExtensionMap;
