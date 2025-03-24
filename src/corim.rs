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
//!             id: "Corim-Unique-Identifier-01".into(),
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

use std::{collections::BTreeMap, fmt};

use crate::{
    comid::ConciseMidTag,
    core::{Bytes, Label},
    coswid::ConciseSwidTag,
    cotl::ConciseTlTag,
    generate_tagged, Digest, ExtensionMap, Int, OidType, TaggedBytes, TaggedConciseMidTag,
    TaggedConciseSwidTag, TaggedConciseTlTag, Text, Time, Tstr, Uri, UuidType,
};

use derive_more::{Constructor, From, TryFrom};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
/// Represents a Concise Reference Integrity Manifest (CoRIM)
pub type Corim<'a> = ConciseRimTypeChoice<'a>;

pub type SignedCorim<'a> = TaggedCOSESign1Corim<'a>;

pub type UnsignedCorimMap<'a> = CorimMap<'a>;

/// A type choice representing either a signed or unsigned CoRIM manifest
#[repr(C)]
#[derive(Debug, From, TryFrom)]
pub enum ConciseRimTypeChoice<'a> {
    /// An unprotected CoRIM with CBOR tag 501
    TaggedUnsignedCorimMap(TaggedUnsignedCorimMap<'a>),
    /// A COSE Sign1 protected CoRIM
    SignedCorim(SignedCorim<'a>),
}

impl<'a> ConciseRimTypeChoice<'a> {
    pub fn as_unsigned_corim_map(&self) -> Option<CorimMap> {
        match self {
            Self::TaggedUnsignedCorimMap(val) => Some(val.as_ref().clone()),
            _ => None,
        }
    }

    pub fn as_signed_corim(&self) -> Option<COSESign1Corim> {
        match self {
            Self::SignedCorim(val) => Some(val.as_ref().clone()),
            _ => None,
        }
    }
}

impl<'a> Serialize for ConciseRimTypeChoice<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::TaggedUnsignedCorimMap(tagged) => tagged.serialize(serializer),
            Self::SignedCorim(tagged) => tagged.serialize(serializer),
        }
    }
}

impl<'de, 'a> Deserialize<'de> for ConciseRimTypeChoice<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagVisitor<'a>(std::marker::PhantomData<&'a ()>);

        impl<'de, 'a> Visitor<'de> for TagVisitor<'a> {
            type Value = ConciseRimTypeChoice<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter
                    .write_str("a ConciseRimTypeChoice variant distinguished by CBOR tag (501, 18)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let tag: u16 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("missing tag"))?;
                match tag {
                    501 => {
                        let value: TaggedUnsignedCorimMap<'a> = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(ConciseRimTypeChoice::TaggedUnsignedCorimMap(value))
                    }
                    18 => {
                        let value: SignedCorim<'a> = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(ConciseRimTypeChoice::SignedCorim(value))
                    }
                    _ => Err(de::Error::custom(format!("unsupported CBOR tag: {}", tag))),
                }
            }
        }

        deserializer.deserialize_any(TagVisitor(std::marker::PhantomData))
    }
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
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct CorimMap<'a> {
    /// Unique identifier for the CoRIM
    #[serde(rename = "0")]
    pub id: CorimIdTypeChoice<'a>,
    /// Collection of tags contained in this CoRIM
    #[serde(rename = "1")]
    pub tags: Vec<ConciseTagTypeChoice<'a>>,
    /// Optional references to other CoRIMs this one depends on
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "2")]
    pub dependent_rims: Option<Vec<CorimLocatorMap<'a>>>,
    /// Optional profile information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "3")]
    pub profile: Option<ProfileTypeChoice<'a>>,
    /// Optional validity period for the CoRIM
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "4")]
    pub rim_validity: Option<ValidityMap>,
    /// Optional list of entities associated with this CoRIM
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "5")]
    pub entities: Option<Vec<CorimEntityMap<'a>>>,
    /// Optional extensible attributes
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<CorimMapExtension>,
}

/// Represents either a string or UUID identifier for a CoRIM
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]

pub enum CorimIdTypeChoice<'a> {
    /// Text string identifier
    Tstr(Tstr<'a>),
    /// UUID identifier
    Uuid(UuidType),
}

impl<'a> CorimIdTypeChoice<'a> {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Tstr(cow) => Some(cow),
            _ => None,
        }
    }

    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(val) => Some(val.as_ref().as_ref()),
            _ => None,
        }
    }
}

impl<'a> From<&'a str> for CorimIdTypeChoice<'a> {
    fn from(s: &'a str) -> Self {
        CorimIdTypeChoice::Tstr(s.into())
    }
}

/// Types of tags that can be included in a CoRIM
#[repr(C)]
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ConciseTagTypeChoice<'a> {
    /// A Concise Software Identity (CoSWID) tag
    Swid(TaggedConciseSwidTag<'a>),
    /// A Concise Module Identity (CoMID) tag
    Mid(TaggedConciseMidTag<'a>),
    /// A Concise Trust List (CoTL) tag
    Tl(TaggedConciseTlTag<'a>),
}

impl<'a> ConciseTagTypeChoice<'a> {
    pub fn as_coswid(&self) -> Option<ConciseSwidTag> {
        match self {
            Self::Swid(coswid) => Some(coswid.as_ref().clone()),
            _ => None,
        }
    }

    pub fn as_comid(&self) -> Option<ConciseMidTag> {
        match self {
            Self::Mid(comid) => Some(comid.as_ref().clone()),
            _ => None,
        }
    }

    pub fn as_cotl(&self) -> Option<ConciseTlTag> {
        match self {
            Self::Tl(cotl) => Some(cotl.as_ref().clone()),
            _ => None,
        }
    }

    pub fn as_ref_coswid(&self) -> Option<&ConciseSwidTag> {
        match self {
            Self::Swid(coswid) => Some(coswid.as_ref()),
            _ => None,
        }
    }

    pub fn as_ref_comid(&self) -> Option<&ConciseMidTag> {
        match self {
            Self::Mid(comid) => Some(comid.as_ref()),
            _ => None,
        }
    }

    pub fn as_ref_cotl(&self) -> Option<&ConciseTlTag> {
        match self {
            Self::Tl(cotl) => Some(cotl.as_ref()),
            _ => None,
        }
    }
}

impl<'a> Serialize for ConciseTagTypeChoice<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Swid(tagged_concise_swid_tag) => tagged_concise_swid_tag.serialize(serializer),
            Self::Mid(tagged_concise_mid_tag) => tagged_concise_mid_tag.serialize(serializer),
            Self::Tl(tagged_concise_tl_tag) => tagged_concise_tl_tag.serialize(serializer),
        }
    }
}
impl<'de, 'a> Deserialize<'de> for ConciseTagTypeChoice<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagVisitor<'a>(std::marker::PhantomData<&'a ()>);

        impl<'de, 'a> Visitor<'de> for TagVisitor<'a> {
            type Value = ConciseTagTypeChoice<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a ConciseTagTypeChoice variant distinguished by CBOR tag (505, 506, 507)",
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let tag: u16 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("missing tag"))?;
                match tag {
                    505 => {
                        let value: ConciseSwidTag<'a> = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(ConciseTagTypeChoice::Swid(TaggedConciseSwidTag::new(value)))
                    }
                    506 => {
                        let value: ConciseMidTag<'a> = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(ConciseTagTypeChoice::Mid(TaggedConciseMidTag::new(value)))
                    }
                    507 => {
                        let value: ConciseTlTag<'a> = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(ConciseTagTypeChoice::Tl(TaggedConciseTlTag::new(value)))
                    }
                    _ => Err(de::Error::custom(format!("unsupported CBOR tag: {}", tag))),
                }
            }
        }

        deserializer.deserialize_any(TagVisitor(std::marker::PhantomData))
    }
}

impl<'a> From<ConciseSwidTag<'a>> for ConciseTagTypeChoice<'a> {
    #[inline]
    fn from(value: ConciseSwidTag<'a>) -> Self {
        Self::Swid(value.into())
    }
}

impl<'a> From<ConciseMidTag<'a>> for ConciseTagTypeChoice<'a> {
    #[inline]
    fn from(value: ConciseMidTag<'a>) -> Self {
        Self::Mid(value.into())
    }
}

impl<'a> From<ConciseTlTag<'a>> for ConciseTagTypeChoice<'a> {
    #[inline]
    fn from(value: ConciseTlTag<'a>) -> Self {
        Self::Tl(value.into())
    }
}

/// Location and optional thumbprint of a dependent CoRIM
#[repr(C)]
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct CorimLocatorMap<'a> {
    /// URI(s) where the dependent CoRIM can be found
    #[serde(rename = "0")]
    pub href: Vec<Uri<'a>>,
    /// Optional cryptographic thumbprint for verification
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "1")]
    pub thumbprint: Option<Digest<'a>>,
}

/// Profile identifier that can be either a URI or OID
#[repr(C)]
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ProfileTypeChoice<'a> {
    /// URI-based profile identifier
    Uri(Uri<'a>),
    /// OID-based profile identifier
    OidType(OidType),
}

impl<'a> ProfileTypeChoice<'a> {
    pub fn as_uri(&self) -> Option<Uri> {
        match self {
            Self::Uri(uri) => Some(uri.clone()),
            _ => None,
        }
    }

    pub fn as_ref_uri(&self) -> Option<&Uri> {
        match self {
            Self::Uri(uri) => Some(uri),
            _ => None,
        }
    }

    pub fn as_oid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::OidType(oid) => Some(oid.as_ref().as_ref()),
            _ => None,
        }
    }
}

impl<'a> Serialize for ProfileTypeChoice<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Uri(uri) => uri.serialize(serializer),
            Self::OidType(oid) => oid.serialize(serializer),
        }
    }
}

impl<'de, 'a> Deserialize<'de> for ProfileTypeChoice<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagVisitor<'a>(std::marker::PhantomData<&'a ()>);
        impl<'de, 'a> Visitor<'de> for TagVisitor<'a> {
            type Value = ProfileTypeChoice<'a>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter
                    .write_str("a ProfileTypeChoice variant distinguished by CBOR tag (32, 111)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let tag: u16 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("missing tag"))?;

                match tag {
                    32 => {
                        let value: Uri<'a> = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(ProfileTypeChoice::Uri(value))
                    }
                    111 => {
                        let value: OidType = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(ProfileTypeChoice::OidType(value))
                    }
                    _ => Err(de::Error::custom(format!("unsupported CBOR tag: {}", tag))),
                }
            }
        }

        deserializer.deserialize_any(TagVisitor(std::marker::PhantomData))
    }
}

/// Defines the validity period for a CoRIM or signature
#[repr(C)]
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct ValidityMap {
    /// Optional start time of the validity period
    #[serde(rename = "0")]
    pub not_before: Option<Time>,
    /// Required end time of the validity period
    #[serde(rename = "1")]
    pub not_after: Time,
}

/// Information about an entity associated with the CoRIM
#[repr(C)]
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct CorimEntityMap<'a> {
    /// Name of the entity
    #[serde(rename = "0")]
    pub entity_name: Text<'a>,
    /// Optional registration identifier for the entity
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "1")]
    pub reg_id: Option<Uri<'a>>,
    /// Role of the entity in relation to the CoRIM
    #[serde(rename = "2")]
    pub role: Vec<CorimRoleTypeChoice>,
    /// Optional extensible attributes
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionMap<'a>>,
}

/// Roles that entities can have in relation to a CoRIM manifest
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
#[serde(untagged)]
pub enum CorimRoleTypeChoice {
    /// Entity that created the manifest content
    ManifestCreator = 1,

    /// Entity that cryptographically signed the manifest
    ManifestSigner = 2,
}

/// Extension map for CoRIM-specific extensions
#[repr(C)]
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct CorimMapExtension(pub TaggedBytes);

/*
COSE-Sign1-corim = [
  protected: bstr .cbor protected-corim-header-map
  unprotected: unprotected-corim-header-map
  payload: bstr .cbor tagged-unsigned-corim-map
  signature: bstr
]
*/
/// COSE_Sign1 structure for a signed CoRIM with CBOR tag 18
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct COSESign1Corim<'a> {
    /// Protected header containing signing metadata (must be integrity protected)
    pub protected: ProtectedCorimHeaderMap<'a>,
    /// Unprotected header attributes (not integrity protected)
    pub unprotected: UnprotectedCorimHeaderMap<'a>,
    /// The actual CoRIM payload being signed
    pub payload: TaggedUnsignedCorimMap<'a>,
    /// Cryptographic signature over the protected header and payload
    pub signature: TaggedBytes,
}

/// Unprotected header for a signed CoRIM
pub type UnprotectedCorimHeaderMap<'a> = BTreeMap<Label<'a>, ExtensionMap<'a>>;

impl<'a> Serialize for COSESign1Corim<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        use serde::ser::SerializeSeq;

        // COSE_Sign1 is a 4-element array, all elements must be present
        let mut seq = serializer.serialize_seq(Some(4))?;

        // 1. Convert protected header to CBOR bytes
        let mut protected_cbor = vec![];
        ciborium::ser::into_writer(&self.protected, &mut protected_cbor).map_err(|e| {
            S::Error::custom(format!("Failed to serialize protected header: {}", e))
        })?;
        seq.serialize_element(&Bytes::from(protected_cbor))?;

        // 2. Unprotected header - must be present (empty map if None)
        // Per RFC 8152, this must be present even if empty
        // let mut unprotected_cbor = Vec::new();
        // ciborium::ser::into_writer(&self.unprotected, &mut unprotected_cbor).map_err(|e| {
        //     S::Error::custom(format!("Failed to serialize unprotected header: {}", e))
        // })?;

        // seq.serialize_element(&Bytes::from(unprotected_cbor))?;
        seq.serialize_element(&self.unprotected)?;

        // 3. Payload as CBOR bytes
        let mut payload_cbor = Vec::new();
        ciborium::ser::into_writer(&self.payload, &mut payload_cbor)
            .map_err(|e| S::Error::custom(format!("Failed to serialize payload: {}", e)))?;
        seq.serialize_element(&Bytes::from(payload_cbor))?;

        // 4. Signature as bytes
        seq.serialize_element(&self.signature)?;

        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for COSESign1Corim<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, SeqAccess, Visitor};
        use std::fmt;
        use std::marker::PhantomData;

        struct COSESign1Visitor<'a>(PhantomData<&'a ()>);

        impl<'de, 'a> Visitor<'de> for COSESign1Visitor<'a> {
            type Value = COSESign1Corim<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a COSE_Sign1 structure as a 4-element array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // 1. Protected header as CBOR bytes
                let protected_bytes: Bytes = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing protected header"))?;

                // 2. Unprotected header
                let unprotected: BTreeMap<Label<'a>, ExtensionMap<'a>> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing unprotected header"))?;

                // 3. Payload as CBOR bytes
                let payload_bytes: Bytes = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing payload"))?;

                // 4. Signature as bytes
                let signature: TaggedBytes = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing signature"))?;

                // Deserialize protected header from bytes
                let protected: ProtectedCorimHeaderMap<'a> =
                    ciborium::de::from_reader(protected_bytes.as_ref()).map_err(|e| {
                        A::Error::custom(format!("Failed to deserialize protected header: {}", e))
                    })?;

                // Deserialize the payload directly
                // First, deserialize the raw CorimMap
                let corim_map: CorimMap<'a> = ciborium::de::from_reader(payload_bytes.as_ref())
                    .map_err(|e| {
                        A::Error::custom(format!("Failed to deserialize payload: {}", e))
                    })?;

                // Then wrap it in the tagged container
                let payload = TaggedUnsignedCorimMap::new(corim_map);

                Ok(COSESign1Corim {
                    protected,
                    unprotected,
                    payload,
                    signature,
                })
            }
        }

        deserializer.deserialize_seq(COSESign1Visitor(PhantomData))
    }
}

/// Protected header for a signed CoRIM
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ProtectedCorimHeaderMap<'a> {
    /// Algorithm identifier for the signature
    #[serde(rename = "1")]
    pub alg: Int,
    /// Content type indicator (should be "application/rim+cbor")
    #[serde(rename = "3")]
    pub content_type: Text<'a>,
    /// Key identifier for the signing key
    #[serde(rename = "4")]
    pub kid: Bytes,
    /// CoRIM-specific metadata
    #[serde(rename = "8")]
    pub corim_meta: CorimMetaMap<'a>,
    /// Optional COSE header parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub cose_map: Option<CoseMap<'a>>,
}

/// Metadata about the CoRIM signing operation
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct CorimMetaMap<'a> {
    /// Information about the signer
    #[serde(rename = "0")]
    pub signer: CorimSignerMap<'a>,
    /// Optional validity period for the signature
    #[serde(rename = "1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_validity: Option<ValidityMap>,
}

/// Information about the entity that signed the CoRIM
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct CorimSignerMap<'a> {
    /// Name of the signing entity
    #[serde(rename = "0")]
    pub signer_name: EntityNameTypeChoice<'a>,
    /// Optional URI identifying the signer
    #[serde(rename = "1")]
    pub signer_uri: Option<Uri<'a>>,
    /// Optional COSE-specific extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<CoseMap<'a>>,
}

/// Type alias for entity names using text strings
pub type EntityNameTypeChoice<'a> = Text<'a>;

/// Type alias for COSE map extensions
pub type CoseMap<'a> = ExtensionMap<'a>;

#[cfg(test)]
mod tests {

    use crate::core::Bytes;
    use crate::corim::{
        COSESign1Corim, ConciseTagTypeChoice, CorimMetaMap, CorimSignerMap, ProtectedCorimHeaderMap,
    };
    use crate::coswid::{ConciseSwidTag, EntityEntry};
    use std::collections::BTreeMap;

    use super::UnsignedCorimMap;

    #[test]
    /// ```text
    /// COSE-Sign1-corim = [
    ///     protected: bstr .cbor protected-corim-header-map
    ///     unprotected: unprotected-corim-header-map
    ///     payload: bstr .cbor tagged-unsigned-corim-map
    ///     signature: bstr
    /// ]
    /// ```
    ///
    /// ```text
    ///  // TOP Level
    ///  132  // Array of 4 elements (COSE_Sign1 structure)
    ///
    ///  // Protected Header (CBOR Bytes)
    ///  88, 65  // Byte string of length 65
    ///    191  // Start of map (indefinite length)
    ///        97, 49  // Text string "1" (map key)
    ///        38      // -7 (ECDSA with SHA-256, alg value)
    ///        97, 51  // Text string "3" (map key)
    ///        116, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 114, 105, 109, 43, 99, 98, 111, 114  // "application/rim+cbor" (content_type)
    ///        97, 52  // Text string "4" (map key)
    ///        71, 107, 101, 121, 45, 48, 48, 49  // Byte string "key-001" (kid)
    ///        97, 56  // Text string "8" (map key)
    ///        161  // Map of 1 element (corim_meta)
    ///        97, 48  // Text string "0" (map key)
    ///        191  // Start of map (indefinite length, signer)
    ///            97, 48  // Text string "0" (map key)
    ///            110, 69, 120, 97, 109, 112, 108, 101, 32, 83, 105, 103, 110, 101, 114  // "Example Signer" (signer_name)
    ///            97, 49  // Text string "1" (map key)
    ///            246  // Null value (signer_uri is None)
    ///        255  // End of indefinite length map
    ///    255  // End of indefinite length map
    ///
    ///  // Unprotected Header (Empty Map)
    ///  160  // Empty map
    ///
    ///  // Payload (CBOR Bytes)
    ///  88, 87  // Byte string of length 87
    ///   217, 1, 245  // Tag 501 (UnsignedCorimMap)
    ///   191  // Start of map (indefinite length)
    ///       97, 48  // Text string "0" (map key)
    ///       105, 99, 111, 114, 105, 109, 45, 48, 48, 49  // "corim-001" (id)
    ///       97, 49  // Text string "1" (map key)
    ///       129  // Array of 1 element (tags)
    ///       130  // Array of 2 elements (tag structure with CBOR tag)
    ///           25, 1, 249  // Tag 505 (CoSWID)
    ///           191  // Start of map (indefinite length)
    ///           97, 48  // Text string "0" (map key)
    ///           104, 115, 119, 105, 100, 45, 49, 50, 51  // "swid-123" (tag_id)
    ///           98, 49, 50  // Text string "12" (map key)
    ///           0  // 0 (tag_version)
    ///           97, 49  // Text string "1" (map key)
    ///           112, 69, 120, 97, 109, 112, 108, 101, 32, 83, 111, 102, 116, 119, 97, 114, 101  // "Example Software" (software_name)
    ///           97, 50  // Text string "2" (map key)
    ///           191  // Start of map (indefinite length, entity)
    ///               98, 51, 49  // Text string "31" (map key)
    ///               110, 69, 120, 97, 109, 112, 108, 101, 32, 69, 110, 116, 105, 116, 121  // "Example Entity" (entity_name)
    ///               98, 51, 51  // Text string "33" (map key)
    ///               129, 1  // Array of 1 element with value 1 (role)
    ///           255  // End of indefinite length map
    ///           255  // End of indefinite length map
    ///   255  // End of indefinite length map
    ///
    ///  // Signature Bytes
    ///  217, 2, 48  // Tag 592 (indicating a tagged byte string)
    ///  65, 0  // Byte string of length 1 with value 0
    /// ```
    fn test_cose_sign1_corim_serialization() {
        let expected: [u8; 163] = [
            132, 88, 65, 191, 97, 49, 38, 97, 51, 116, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 47, 114, 105, 109, 43, 99, 98, 111, 114, 97, 52, 71, 107, 101, 121, 45, 48,
            48, 49, 97, 56, 161, 97, 48, 191, 97, 48, 110, 69, 120, 97, 109, 112, 108, 101, 32, 83,
            105, 103, 110, 101, 114, 97, 49, 246, 255, 255, 160, 88, 87, 217, 1, 245, 191, 97, 48,
            105, 99, 111, 114, 105, 109, 45, 48, 48, 49, 97, 49, 129, 130, 25, 1, 249, 191, 97, 48,
            104, 115, 119, 105, 100, 45, 49, 50, 51, 98, 49, 50, 0, 97, 49, 112, 69, 120, 97, 109,
            112, 108, 101, 32, 83, 111, 102, 116, 119, 97, 114, 101, 97, 50, 191, 98, 51, 49, 110,
            69, 120, 97, 109, 112, 108, 101, 32, 69, 110, 116, 105, 116, 121, 98, 51, 51, 129, 1,
            255, 255, 255, 217, 2, 48, 65, 0,
        ];

        let cose_corim = COSESign1Corim {
            protected: ProtectedCorimHeaderMap {
                alg: -7,
                content_type: "application/rim+cbor".into(),
                kid: vec![0x6B, 0x65, 0x79, 0x2D, 0x30, 0x30, 0x31].into(),
                corim_meta: CorimMetaMap {
                    signer: CorimSignerMap {
                        signer_name: "Example Signer".into(),
                        ..Default::default()
                    },
                    signature_validity: None,
                },
                cose_map: None,
            },
            unprotected: BTreeMap::new(),
            payload: UnsignedCorimMap {
                id: "corim-001".into(),
                tags: vec![ConciseSwidTag {
                    tag_id: "swid-123".into(),
                    tag_version: 0.into(),
                    software_name: "Example Software".into(),
                    entity: EntityEntry {
                        entity_name: "Example Entity".into(),
                        reg_id: None,
                        role: 1.into(),
                        thumbprint: None,
                        extensions: None,
                        global_attributes: None,
                    }
                    .into(),
                    corpus: None,
                    patch: None,
                    supplemental: None,
                    software_version: None,
                    version_scheme: None,
                    media: None,
                    software_meta: None,
                    link: None,
                    payload_or_evidence: None,
                    extensions: None,
                    global_attributes: None,
                }
                .into()]
                .into(),
                dependent_rims: None,
                profile: None,
                rim_validity: None,
                entities: None,
                extension: None,
            }
            .into(),
            signature: Bytes::from(vec![0]).into(),
        };

        let mut actual: Vec<u8> = vec![];

        ciborium::into_writer(&cose_corim, &mut actual).unwrap();

        println!("Hex Bytes: {:02X?}", &actual);

        assert_eq!(expected.as_slice(), &actual);
    }

    #[test]
    fn test_cose_sign1_corim_deserialization() {
        let serialized_bytes: [u8; 163] = [
            132, 88, 65, 191, 97, 49, 38, 97, 51, 116, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 47, 114, 105, 109, 43, 99, 98, 111, 114, 97, 52, 71, 107, 101, 121, 45, 48,
            48, 49, 97, 56, 161, 97, 48, 191, 97, 48, 110, 69, 120, 97, 109, 112, 108, 101, 32, 83,
            105, 103, 110, 101, 114, 97, 49, 246, 255, 255, 160, 88, 87, 217, 1, 245, 191, 97, 48,
            105, 99, 111, 114, 105, 109, 45, 48, 48, 49, 97, 49, 129, 130, 25, 1, 249, 191, 97, 48,
            104, 115, 119, 105, 100, 45, 49, 50, 51, 98, 49, 50, 0, 97, 49, 112, 69, 120, 97, 109,
            112, 108, 101, 32, 83, 111, 102, 116, 119, 97, 114, 101, 97, 50, 191, 98, 51, 49, 110,
            69, 120, 97, 109, 112, 108, 101, 32, 69, 110, 116, 105, 116, 121, 98, 51, 51, 129, 1,
            255, 255, 255, 217, 2, 48, 65, 0,
        ];

        // Deserialize the byte array
        let deserialized: COSESign1Corim = ciborium::de::from_reader(&serialized_bytes[..])
            .expect("Failed to deserialize COSE_Sign1 CoRIM");

        // Verify the deserialized object has the expected structure
        assert_eq!(deserialized.protected.alg, -7);
        assert_eq!(
            deserialized.protected.content_type,
            std::borrow::Cow::Borrowed("application/rim+cbor"),
        );
        assert_eq!(
            deserialized.protected.kid,
            Bytes::from(vec![0x6B, 0x65, 0x79, 0x2D, 0x30, 0x30, 0x31])
        );
        assert_eq!(
            deserialized.protected.corim_meta.signer.signer_name,
            std::borrow::Cow::Borrowed("Example Signer")
        );
        assert!(deserialized
            .protected
            .corim_meta
            .signature_validity
            .is_none());
        assert!(deserialized.protected.cose_map.is_some());

        // Check the unprotected header is empty
        assert!(deserialized.unprotected.is_empty());

        // Verify payload
        let payload = &deserialized.payload.0;
        assert_eq!(payload.0.id, "corim-001".into());

        // Verify tags
        assert_eq!(payload.0.tags.len(), 1);
        if let ConciseTagTypeChoice::Swid(swid_tag) = &payload.0.tags[0] {
            let tag = &swid_tag.0;
            assert_eq!(tag.0.tag_id, "swid-123".into());
            assert_eq!(tag.0.tag_version, 0.into());
            assert_eq!(
                tag.0.software_name,
                std::borrow::Cow::Borrowed("Example Software")
            );

            // Check entity
            let entity = match &tag.0.entity {
                crate::core::OneOrMore::One(entity) => entity,
                crate::core::OneOrMore::More(items) => &items[0],
            };

            assert_eq!(
                entity.entity_name,
                std::borrow::Cow::Borrowed("Example Entity")
            );
            assert!(entity.reg_id.is_none());
            assert_eq!(entity.role.len(), 1);
            assert_eq!(*entity.role.get(0).unwrap(), 1);
        } else {
            panic!("Expected a CoSWID tag");
        }

        // Verify signature
        assert_eq!(deserialized.signature, Bytes::from(vec![0]).into());

        // Round-trip test: Serialize, then deserialize again
        let mut reserialize_buffer: Vec<u8> = vec![];
        ciborium::into_writer(&deserialized, &mut reserialize_buffer).unwrap();

        // Verify the reserialized bytes match the original
        assert_eq!(serialized_bytes.as_slice(), &reserialize_buffer);
    }
}
