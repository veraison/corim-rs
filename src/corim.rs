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
    empty_map_as_none, generate_tagged, Digest, ExtensionMap, Int, OidType, TaggedBytes,
    TaggedConciseMidTag, TaggedConciseSwidTag, TaggedConciseTlTag, Text, Time, Tstr, Uri, UuidType,
};

use derive_more::{Constructor, From, TryFrom};
use serde::{
    de::{self, Visitor},
    ser::SerializeMap,
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

impl ConciseRimTypeChoice<'_> {
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

impl Serialize for ConciseRimTypeChoice<'_> {
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

impl<'de> Deserialize<'de> for ConciseRimTypeChoice<'_> {
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
        "unsigned-corim",
        "A CBOR tagged, unsigned CoRIM Map."
    ),
    (
        18,
        TaggedCOSESign1Corim,
        COSESign1Corim<'a>,
        'a,
        "signed-corim",
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

impl CorimIdTypeChoice<'_> {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Tstr(cow) => Some(cow),
            _ => None,
        }
    }

    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(val) => Some(val.as_ref()),
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
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
pub enum ConciseTagTypeChoice<'a> {
    /// A Concise Software Identity (CoSWID) tag
    Swid(TaggedConciseSwidTag<'a>),
    /// A Concise Module Identity (CoMID) tag
    Mid(TaggedConciseMidTag<'a>),
    /// A Concise Trust List (CoTL) tag
    Tl(TaggedConciseTlTag<'a>),
}

impl<'de> Deserialize<'de> for ConciseTagTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagVisitor<'a>(std::marker::PhantomData<&'a ()>);
        impl<'de, 'a> Visitor<'de> for TagVisitor<'a> {
            type Value = ConciseTagTypeChoice<'a>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tagged CBOR value (505, 506, 508)")
            }
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let tagged_value = ciborium::value::Value::deserialize(deserializer)?;
                match tagged_value {
                    ciborium::value::Value::Tag(tag, inner) => match tag {
                        505 => {
                            let mut bytes: Vec<u8> = Vec::new();
                            ciborium::ser::into_writer(&inner, &mut bytes).map_err(|_| {
                                serde::de::Error::custom("Failed to serialize the map")
                            })?;
                            let swid: ConciseSwidTag<'a> = ciborium::from_reader(&bytes[..])
                                .map_err(|_| {
                                    serde::de::Error::custom("Failed to deserialize bytes")
                                })?;
                            Ok(ConciseTagTypeChoice::Swid(TaggedConciseSwidTag::new(swid)))
                        }
                        506 => {
                            let mut bytes = Vec::new();
                            ciborium::ser::into_writer(&inner, &mut bytes).map_err(|_| {
                                serde::de::Error::custom("Failure to serialize the map")
                            })?;
                            let mid: ConciseMidTag<'a> = ciborium::from_reader(&bytes[..])
                                .map_err(|_| {
                                    serde::de::Error::custom("Failed to deserialize bytes")
                                })?;
                            Ok(ConciseTagTypeChoice::Mid(TaggedConciseMidTag::new(mid)))
                        }
                        508 => {
                            let mut bytes = Vec::new();
                            ciborium::ser::into_writer(&inner, &mut bytes).map_err(|_| {
                                serde::de::Error::custom("Failure to serialize the map")
                            })?;
                            let tl: ConciseTlTag<'a> =
                                ciborium::from_reader(&bytes[..]).map_err(|_| {
                                    serde::de::Error::custom("Failed to deserialize bytes")
                                })?;
                            Ok(ConciseTagTypeChoice::Tl(TaggedConciseTlTag::new(tl)))
                        }
                        other => Err(serde::de::Error::custom(format!(
                            "Unsupported tag: {}, expected 505, 506, or 508",
                            other
                        ))),
                    },
                    _ => Err(serde::de::Error::custom("Expected a tagged CBOR value")),
                }
            }
        }
        deserializer.deserialize_newtype_struct(
            "ConciseTagTypeChoice",
            TagVisitor(std::marker::PhantomData),
        )
    }
}

impl ConciseTagTypeChoice<'_> {
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
    pub thumbprint: Option<Digest>,
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

impl ProfileTypeChoice<'_> {
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

impl Serialize for ProfileTypeChoice<'_> {
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

impl<'de> Deserialize<'de> for ProfileTypeChoice<'_> {
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
    #[serde(deserialize_with = "empty_map_as_none")]
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

impl Serialize for COSESign1Corim<'_> {
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
impl<'de> Deserialize<'de> for COSESign1Corim<'_> {
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
                let unprotected: UnprotectedCorimHeaderMap<'a> = seq
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

                // Deserialize payload directly into TaggedUnsignedCorimMap
                let payload: TaggedUnsignedCorimMap<'a> =
                    ciborium::de::from_reader(payload_bytes.as_ref()).map_err(|e| {
                        A::Error::custom(format!("Failed to deserialize payload: {}", e))
                    })?;

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
    #[serde(deserialize_with = "empty_map_as_none")]
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
    #[serde(deserialize_with = "empty_map_as_none")]
    #[serde(flatten)]
    pub extension: Option<CoseMap<'a>>,
}

/// Type alias for entity names using text strings
pub type EntityNameTypeChoice<'a> = Text<'a>;

/// Type alias for COSE map extensions
pub type CoseMap<'a> = ExtensionMap<'a>;

#[cfg(test)]
mod tests {

    use crate::comid::{
        ComidEntityMap, ComidRoleTypeChoice, ConciseMidTag, TagIdentityMap, TriplesMapBuilder,
    };
    use crate::core::Bytes;
    use crate::corim::{COSESign1Corim, CorimMetaMap, CorimSignerMap, ProtectedCorimHeaderMap};
    use crate::coswid::{ConciseSwidTag, EntityEntry};
    use crate::triples::{
        ClassMap, EnvironmentMap, MeasurementMap, MeasurementValuesMap, ReferenceTripleRecord,
    };
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
    fn test_cose_sign1_corim_serialize_deserialize() {
        let expected: [u8; 276] = [
            132, 88, 65, 191, 97, 49, 38, 97, 51, 116, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 47, 114, 105, 109, 43, 99, 98, 111, 114, 97, 52, 71, 107, 101, 121, 45, 48,
            48, 49, 97, 56, 161, 97, 48, 191, 97, 48, 110, 69, 120, 97, 109, 112, 108, 101, 32, 83,
            105, 103, 110, 101, 114, 97, 49, 246, 255, 255, 160, 88, 200, 217, 1, 245, 191, 97, 48,
            105, 99, 111, 114, 105, 109, 45, 48, 48, 49, 97, 49, 130, 217, 1, 249, 191, 97, 48,
            104, 115, 119, 105, 100, 45, 49, 50, 51, 98, 49, 50, 0, 97, 49, 112, 69, 120, 97, 109,
            112, 108, 101, 32, 83, 111, 102, 116, 119, 97, 114, 101, 97, 50, 191, 98, 51, 49, 110,
            69, 120, 97, 109, 112, 108, 101, 32, 69, 110, 116, 105, 116, 121, 98, 51, 51, 1, 255,
            255, 217, 1, 250, 191, 97, 48, 101, 101, 110, 95, 85, 83, 97, 49, 161, 97, 48, 107, 83,
            111, 109, 101, 32, 84, 97, 103, 32, 73, 68, 97, 50, 129, 191, 98, 51, 49, 111, 83, 111,
            109, 101, 32, 67, 111, 77, 73, 68, 32, 78, 97, 109, 101, 98, 51, 51, 129, 246, 255, 97,
            52, 191, 97, 48, 129, 130, 161, 97, 48, 161, 97, 49, 107, 83, 111, 109, 101, 32, 86,
            101, 110, 100, 111, 114, 129, 162, 97, 48, 104, 83, 111, 109, 101, 32, 75, 101, 121,
            97, 49, 191, 98, 49, 49, 105, 83, 111, 109, 101, 32, 78, 97, 109, 101, 255, 255, 255,
            255, 217, 2, 48, 65, 0,
        ];

        let triples = TriplesMapBuilder::default()
            .reference_triples(vec![ReferenceTripleRecord {
                ref_env: EnvironmentMap {
                    class: Some(ClassMap {
                        class_id: None,
                        vendor: Some("Some Vendor".into()),
                        ..Default::default()
                    }),
                    instance: None,
                    group: None,
                },
                ref_claims: vec![MeasurementMap {
                    mkey: Some("Some Key".into()),
                    mval: MeasurementValuesMap {
                        name: Some("Some Name".into()),
                        version: None,
                        svn: None,
                        digest: None,
                        flags: None,
                        raw: None,
                        mac_addr: None,
                        ip_addr: None,
                        serial_number: None,
                        ueid: None,
                        uuid: None,
                        cryptokeys: None,
                        integrity_registers: None,
                        extensions: None,
                    },
                    authorized_by: None,
                }],
            }])
            .build()
            .unwrap();

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
                tags: vec![
                    ConciseSwidTag {
                        tag_id: "swid-123".into(),
                        tag_version: 0,
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
                    .into(),
                    ConciseMidTag {
                        language: Some("en_US".into()),
                        tag_identity: TagIdentityMap {
                            tag_id: "Some Tag ID".into(),
                            tag_version: None,
                        },
                        entities: Some(vec![ComidEntityMap {
                            entity_name: "Some CoMID Name".into(),
                            reg_id: None,
                            role: vec![ComidRoleTypeChoice::TagCreator],
                            extension: None,
                        }]),
                        linked_tags: None,
                        triples,
                        extension: None,
                    }
                    .into(),
                ],
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

        println!("{actual:02X?}");

        assert_eq!(expected.as_slice(), &actual);

        let deserialized: COSESign1Corim = ciborium::de::from_reader(actual.as_slice())
            .expect("Failed to deserialize COSE_Sign1 CoRIM");

        assert_eq!(cose_corim, deserialized);
    }
}
