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

use std::{collections::BTreeMap, fmt, marker::PhantomData};

use crate::{
    comid::ConciseMidTag,
    core::{Bytes, Label, ObjectIdentifier, TaggedJsonValue},
    coswid::ConciseSwidTag,
    cotl::ConciseTlTag,
    empty_map_as_none,
    error::CorimError,
    generate_tagged,
    numbers::Integer,
    Digest, ExtensionMap, ExtensionValue, Int, OidType, TaggedBytes, TaggedConciseMidTag,
    TaggedConciseSwidTag, TaggedConciseTlTag, Text, Time, Tstr, Uri, UuidType,
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
#[allow(clippy::large_enum_variant)]
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
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
pub enum CorimIdTypeChoice<'a> {
    /// Text string identifier
    Tstr(Tstr<'a>),
    /// UUID identifier
    Uuid(UuidType),
    /// Type extension
    Extension(ExtensionValue<'a>),
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

impl<'de> Deserialize<'de> for CorimIdTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            match serde_json::Value::deserialize(deserializer)? {
                serde_json::Value::String(s) => match UuidType::try_from(s.as_str()) {
                    Ok(uuid) => Ok(CorimIdTypeChoice::Uuid(uuid)),
                    Err(_) => Ok(CorimIdTypeChoice::Tstr(s.into())),
                },
                value => Ok(CorimIdTypeChoice::Extension(
                    ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                )),
            }
        } else {
            match ciborium::Value::deserialize(deserializer)? {
                ciborium::Value::Text(s) => Ok(CorimIdTypeChoice::Tstr(s.into())),
                ciborium::Value::Bytes(b) => Ok(CorimIdTypeChoice::Uuid(
                    UuidType::try_from(b.as_slice()).map_err(de::Error::custom)?,
                )),
                value => Ok(CorimIdTypeChoice::Extension(
                    ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                )),
            }
        }
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
        if deserializer.is_human_readable() {
            let tagged_value = TaggedJsonValue::deserialize(deserializer)?;

            match tagged_value.typ {
                "oid" => {
                    let oid: ObjectIdentifier = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(ProfileTypeChoice::OidType(oid.into()))
                }
                "uri" => {
                    let uri: Text = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(ProfileTypeChoice::Uri(uri.into()))
                }
                s => Err(de::Error::custom(format!(
                    "unexpected ProfileTypeChoice type \"{s}\""
                ))),
            }
        } else {
            match ciborium::Value::deserialize(deserializer)? {
                ciborium::Value::Tag(tag, inner) => {
                    // Re-serializing the inner Value so that we can deserialize it
                    // into an appropriate type, once we figure out what that is
                    // based on the tag.
                    let mut buf: Vec<u8> = Vec::new();
                    ciborium::into_writer(&inner, &mut buf).unwrap();

                    match tag {
                        111 => {
                            let oid: ObjectIdentifier =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(ProfileTypeChoice::OidType(oid.into()))
                        }
                        37 => {
                            let uri: Text =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(ProfileTypeChoice::Uri(uri.into()))
                        }
                        n => Err(de::Error::custom(format!(
                            "unexpected ProfileTypeChoice tag {n}"
                        ))),
                    }
                }
                _ => Err(de::Error::custom("did not see a tag for ProfileTypeChoice")),
            }
        }
    }
}

/// Defines the validity period for a CoRIM or signature
#[repr(C)]
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ValidityMap {
    /// Optional start time of the validity period
    pub not_before: Option<Time>,
    /// Required end time of the validity period
    pub not_after: Time,
}

impl Serialize for ValidityMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(not_before) = &self.not_before {
                map.serialize_entry("not-before", not_before)?;
            }

            map.serialize_entry("not-after", &self.not_after)?;
        } else {
            if let Some(not_before) = &self.not_before {
                map.serialize_entry(&0, not_before)?;
            }

            map.serialize_entry(&1, &self.not_after)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ValidityMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValidityMapVisitor {
            is_human_readable: bool,
        }

        impl<'de> Visitor<'de> for ValidityMapVisitor {
            type Value = ValidityMap;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map containing Validity map fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut not_before: Option<Time> = None;
                let mut not_after: Option<Time> = None;

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("not-before") => {
                                not_before = Some(map.next_value()?);
                            }
                            Some("not-after") => {
                                not_after = Some(map.next_value()?);
                            }
                            Some(s) => {
                                return Err(de::Error::unknown_field(
                                    s,
                                    &["not-before", "not-after"],
                                ))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                not_before = Some(map.next_value()?);
                            }
                            Some(1) => {
                                not_after = Some(map.next_value()?);
                            }
                            Some(n) => {
                                return Err(de::Error::unknown_field(
                                    n.to_string().as_str(),
                                    &["0-1"],
                                ))
                            }
                            None => break,
                        }
                    }
                }

                if not_after.is_none() {
                    return Err(de::Error::missing_field("not-after"));
                }

                Ok(ValidityMap {
                    not_before,
                    not_after: not_after.unwrap(),
                })
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(ValidityMapVisitor {
            is_human_readable: is_hr,
        })
    }
}

/// Information about an entity associated with the CoRIM
#[repr(C)]
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct CorimEntityMap<'a> {
    /// Name of the entity
    pub entity_name: Text<'a>,
    /// Optional registration identifier for the entity
    pub reg_id: Option<Uri<'a>>,
    /// Role of the entity in relation to the CoRIM
    pub role: Vec<CorimRoleTypeChoice>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Serialize for CorimEntityMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("entity-name", &self.entity_name)?;

            if let Some(reg_id) = &self.reg_id {
                map.serialize_entry("reg-id", reg_id)?;
            }

            map.serialize_entry("role", &self.role)?;
        } else {
            map.serialize_entry(&0, &self.entity_name)?;

            if let Some(reg_id) = &self.reg_id {
                map.serialize_entry(&1, reg_id)?;
            }

            map.serialize_entry(&2, &self.role)?;
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for CorimEntityMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct CorimEntityMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CorimEntityMapVisitor<'a> {
            type Value = CorimEntityMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing CorimEntityMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = CorimEntityMapBuilder::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("entity-name") => {
                                builder = builder.entity_name(map.next_value::<Text>()?);
                            }
                            Some("reg-id") => {
                                builder = builder.reg_id(map.next_value::<Uri>()?);
                            }
                            Some("role") => {
                                builder =
                                    builder.role(map.next_value::<Vec<CorimRoleTypeChoice>>()?);
                            }
                            Some(s) => {
                                let ext_field: i128 = s.parse().map_err(|_| {
                                    de::Error::unknown_field(
                                        s,
                                        &["entity-name", "reg-id", "role", "any integer"],
                                    )
                                })?;
                                builder = builder
                                    .add_extension(ext_field, map.next_value::<ExtensionValue>()?);
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                builder = builder.entity_name(map.next_value::<Text>()?);
                            }
                            Some(1) => {
                                builder = builder.reg_id(map.next_value::<Uri>()?);
                            }
                            Some(2) => {
                                builder =
                                    builder.role(map.next_value::<Vec<CorimRoleTypeChoice>>()?);
                            }
                            Some(n) => {
                                builder = builder
                                    .add_extension(n.into(), map.next_value::<ExtensionValue>()?);
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(CorimEntityMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

pub struct CorimEntityMapBuilder<'a> {
    entity_name: Option<Text<'a>>,
    reg_id: Option<Uri<'a>>,
    role: Option<Vec<CorimRoleTypeChoice>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> CorimEntityMapBuilder<'a> {
    pub fn new() -> Self {
        CorimEntityMapBuilder {
            entity_name: None,
            reg_id: None,
            role: None,
            extensions: None,
        }
    }

    pub fn entity_name(mut self, name: Text<'a>) -> Self {
        self.entity_name = Some(name);
        self
    }

    pub fn reg_id(mut self, reg_id: Uri<'a>) -> Self {
        self.reg_id = Some(reg_id);
        self
    }

    pub fn role(mut self, roles: Vec<CorimRoleTypeChoice>) -> Self {
        self.role = Some(roles);
        self
    }

    pub fn add_role(mut self, role: CorimRoleTypeChoice) -> Self {
        if let Some(ref mut roles) = self.role {
            roles.push(role)
        } else {
            self.role = Some(vec![role])
        }
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(ref mut extensions) = self.extensions {
            extensions.insert(Integer(key), value);
        } else {
            let mut extensions = ExtensionMap::default();
            extensions.insert(Integer(key), value);
            self.extensions = Some(extensions);
        }
        self
    }

    pub fn build(self) -> crate::Result<CorimEntityMap<'a>> {
        if self.entity_name.is_none()
            || self.role.is_none()
            || self.role.as_ref().unwrap().is_empty()
        {
            return Err(CorimError::UnsetMandatoryField(
                "CorimEntityMap".to_string(),
                "entity_name and role".to_string(),
            ))?;
        }

        Ok(CorimEntityMap {
            entity_name: self.entity_name.unwrap(),
            reg_id: self.reg_id,
            role: self.role.unwrap(),
            extensions: self.extensions,
        })
    }
}

impl Default for CorimEntityMapBuilder<'_> {
    fn default() -> Self {
        CorimEntityMapBuilder::new()
    }
}

/// Roles that entities can have in relation to a CoRIM manifest
#[derive(Debug, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(i64)]
pub enum CorimRoleTypeChoice {
    /// Entity that created the manifest content
    ManifestCreator = 1,

    /// Entity that cryptographically signed the manifest
    ManifestSigner = 2,

    /// Roles not difined by CoRIM specification
    Extension(i64),
}

impl From<&CorimRoleTypeChoice> for i64 {
    fn from(value: &CorimRoleTypeChoice) -> Self {
        match value {
            CorimRoleTypeChoice::ManifestCreator => 1,
            CorimRoleTypeChoice::ManifestSigner => 2,
            CorimRoleTypeChoice::Extension(value) => *value,
        }
    }
}

impl From<i64> for CorimRoleTypeChoice {
    fn from(value: i64) -> Self {
        match value {
            1 => CorimRoleTypeChoice::ManifestCreator,
            2 => CorimRoleTypeChoice::ManifestSigner,
            value => CorimRoleTypeChoice::Extension(value),
        }
    }
}

impl TryFrom<&str> for CorimRoleTypeChoice {
    type Error = CorimError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "manifest-creator" => Ok(CorimRoleTypeChoice::ManifestCreator),
            "manifest-signer" => Ok(CorimRoleTypeChoice::ManifestSigner),
            value => {
                if value.starts_with("Role(") && value.len() > 6 {
                    match value[5..value.len() - 1].parse::<i64>() {
                        Ok(i) => Ok(CorimRoleTypeChoice::Extension(i)),
                        Err(_) => Err(CorimError::InvalidCorimRole(value.to_string())),
                    }
                } else {
                    Err(CorimError::InvalidCorimRole(value.to_string()))
                }
            }
        }
    }
}

impl fmt::Display for CorimRoleTypeChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let role: String;

        f.write_str(match self {
            CorimRoleTypeChoice::ManifestCreator => "manifest-creator",
            CorimRoleTypeChoice::ManifestSigner => "manifest-signer",
            CorimRoleTypeChoice::Extension(i) => {
                role = format!("Role({i})");
                role.as_str()
            }
        })
    }
}

impl Serialize for CorimRoleTypeChoice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            i64::from(self).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for CorimRoleTypeChoice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .as_str()
                .try_into()
                .map_err(de::Error::custom)
        } else {
            Ok(i64::deserialize(deserializer)?.into())
        }
    }
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
#[rustfmt::skip::macros(vec)]
mod tests {

    use crate::comid::{
        ComidEntityMap, ComidRoleTypeChoice, ConciseMidTag, TagIdentityMap, TriplesMapBuilder,
    };
    use crate::core::Bytes;
    use crate::corim::{COSESign1Corim, CorimMetaMap, CorimSignerMap, ProtectedCorimHeaderMap};
    use crate::coswid::{ConciseSwidTag, EntityEntry};
    use crate::numbers::Integer;
    use crate::test::SerdeTestCase;
    use crate::triples::{
        ClassMap, EnvironmentMap, MeasurementMap, MeasurementValuesMap, ReferenceTripleRecord,
    };
    use std::collections::BTreeMap;

    use super::*;

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
        let expected = vec![
            0x84, // array(4)
              0x58, 0x41, // bstr(65) -- COSE protected header
                0xbf, // map(indef)
                  0x61, // key: tstr(1)
                    0x31, // "1"
                  0x26, // value: -7
                  0x61, // key: tstr(1)
                    0x33, // "3"
                  0x74, // value: tstr(20)
                    0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, // "applicat"
                    0x69, 0x6f, 0x6e, 0x2f, 0x72, 0x69, 0x6d, 0x2b, // "ion/rim+"
                    0x63, 0x62, 0x6f, 0x72,                         // "cbor"
                  0x61, // key: tstr(1)
                    0x34, // "4"
                  0x47, // value: bstr(7)
                    0x6b, 0x65, 0x79, 0x2d, 0x30, 0x30, 0x31,
                  0x61, // key: tstr(1)
                    0x38, // "8"
                  0xa1, // value: map(1)
                    0x61, // key: tstr(1)
                      0x30, // "0"
                    0xbf, // value: map(indef)
                      0x61, // key: tstr(1)
                        0x30, // "1"
                      0x6e, // value: tstr(14)
                        0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, // "Example "
                        0x53, 0x69, 0x67, 0x6e, 0x65, 0x72,             // "Signer"
                      0x61, // key: tstr(1)
                        0x31, // "1"
                      0xf6, // value: null
                    0xff, // break
                0xff, // break
              0xa0, // map(0) -- COSE unprotected header
              0x58, 0xbc, // bstr(188) -- COSE payload
                0xd9, 0x01, 0xf5, // tag(501) -- CoRIM
                  0xbf, // map(indef)
                    0x61, // key: tstr(1)
                      0x30, // "0"
                    0x69, // value: tstr(9)
                      0x63, 0x6f, 0x72, 0x69, 0x6d, 0x2d, 0x30, 0x30, // "corim-00"
                      0x31,                                           // "1"
                    0x61, // key: tstr(1)
                      0x31, // "1"
                    0x82, // value: array(2)
                      0xd9, 0x01, 0xf9, // tag(505) -- CoSWID
                        0xbf, // map(indef)
                          0x61, // key: tstr(1)
                            0x30, // "0"
                          0x68, // value: tstr(8)
                            0x73, 0x77, 0x69, 0x64, 0x2d, 0x31, 0x32, 0x33,  // "swid-123"
                          0x62,  // key: tstr(2)
                            0x31, 0x32, // "12"
                          0x00, // value: 0
                          0x61, // key: tstr(1)
                            0x31, // "1"
                          0x70, // value: tstr(16)
                            0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, // "Example "
                            0x53, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, // "Software"
                          0x61, // key: tstr(1)
                            0x32, // "2"
                          0xbf, // value: map(indef)
                            0x62, // key: tstr(2)
                              0x33, 0x31, // "31"
                            0x6e, // value: tstr(14)
                              0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, // "Example "
                              0x45, 0x6e, 0x74, 0x69, 0x74, 0x79,             // "Entity"
                            0x62, // key: tstr(2)
                              0x33, 0x33, // "33"
                            0x01, // value: 1
                          0xff,  // break(map)
                        0xff,  // break(map)
                      0xd9, 0x01, 0xfa, // tag (506) -- CoMID
                        0xbf, // map(indef)
                          0x00, // key: 0
                          0x65, // value: tstr(5)
                            0x65, 0x6e, 0x5f, 0x55, 0x53, // "en_US"
                          0x01, // key: 1
                          0xbf, // value: map(1)
                            0x00, // key: 0 [tag-id]
                            0x6b, // value: tstr(11)
                              0x53, 0x6f, 0x6d, 0x65, 0x20, 0x54, 0x61, 0x67, // "Some Tag"
                              0x20, 0x49, 0x44,                               // " ID"
                          0xff, // break
                          0x02, // key: 2
                          0x81, // value: array(1)
                            0xbf, // map(indef)
                              0x00, // key: 0
                              0x6f, // value: tstr(15)
                                0x53, 0x6f, 0x6d, 0x65, 0x20, 0x43, 0x6f, 0x4d,
                                0x49, 0x44, 0x20, 0x4e, 0x61, 0x6d, 0x65,
                              0x02, // key: 2
                              0x81, // value: array(1)
                                0x00, // 0 [tag-creator]
                            0xff, // break(map)
                          0x04, // key: 4
                          0xbf, // value: map(indef)
                            0x00, // key: 0
                            0x81, // value: array(1)
                              0x82, // array(2)
                                0xbf, //  map(indef)
                                  0x00, // 0
                                  0xbf, // value: map(indef)
                                    0x01, // key: 1
                                    0x6b, // value: tstr(11)
                                      0x53, 0x6f, 0x6d, 0x65, 0x20, 0x56, 0x65, 0x6e, // "Some Ven"
                                      0x64, 0x6f, 0x72,                               // "dor"
                                  0xff,
                                0xff,
                                0x81, // array(1)
                                  0xbf, // map(indef)
                                    0x00, // key: 0
                                    0x68, // value: str(8)
                                      0x53, 0x6f, 0x6d, 0x65, 0x20, 0x4b, 0x65, 0x79, // "Some Key"
                                    0x01, // key: 1
                                    0xbf, // value: map(indef)
                                      0x0b, // key: 11
                                      0x69, // value: tstr(9)
                                        0x53, 0x6f, 0x6d, 0x65, 0x20, 0x4e, 0x61, 0x6d, // "Some Nam"
                                        0x65,                                           // "e"
                                    0xff, // break
                                  0xff, // break
                          0xff, // break
                        0xff, // break
                  0xff, // break
              0xd9, 0x02, 0x30, // tag(560) -- COSE signature
                0x41, // bstr(1)
                  0x00
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
                        digests: None,
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
                alg: Integer(-7),
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
                        tag_version: Integer(0),
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
                            extensions: None,
                        }]),
                        linked_tags: None,
                        triples,
                        extensions: None,
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

    #[test]
    fn test_profile_type_choice() {
        let profile = ProfileTypeChoice::OidType(OidType::from(
            ObjectIdentifier::try_from("1.2.3.4").unwrap(),
        ));

        let mut actual: Vec<u8> = vec![];

        ciborium::into_writer(&profile, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xd8, 0x6f, // tag(111)
              0x43, // bstr(3)
                0x2a, 0x03, 0x04
        ];

        assert_eq!(actual, expected);

        let profile_de: ProfileTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(profile_de, profile);

        let actual = serde_json::to_string(&profile).unwrap();

        let expected = r#"{"type":"oid","value":"1.2.3.4"}"#;

        assert_eq!(actual, expected);

        let profile_de: ProfileTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(profile_de, profile);
    }

    #[test]
    fn test_corim_id_type_choice_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: CorimIdTypeChoice::Tstr("foo".into()),
                expected_cbor: vec![
                    0x63, // tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                ],
                expected_json: "\"foo\"",
            },
            SerdeTestCase {
                value: CorimIdTypeChoice::Uuid(
                   UuidType::try_from("550e8400-e29b-41d4-a716-446655440000").unwrap(),
                ),
                expected_cbor: vec![
                    0x50, // bstr(16)
                      0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
                      0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
                ],
                expected_json: "\"550e8400-e29b-41d4-a716-446655440000\"",
            },
            SerdeTestCase {
                value: CorimIdTypeChoice::Extension(
                   ExtensionValue::Bool(true)
                ),
                expected_cbor: vec![
                    0xf5, // true
                ],
                expected_json: "true",
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_corim_role_type_choice() {
        let test_cases = vec![
            SerdeTestCase {
                value: CorimRoleTypeChoice::ManifestCreator,
                expected_json: "\"manifest-creator\"",
                expected_cbor: vec![ 0x01 ],
            },
            SerdeTestCase {
                value: CorimRoleTypeChoice::ManifestSigner,
                expected_json: "\"manifest-signer\"",
                expected_cbor: vec![ 0x02 ],
            },
            SerdeTestCase {
                value: CorimRoleTypeChoice::Extension(-1),
                expected_json: "\"Role(-1)\"",
                expected_cbor: vec![ 0x20 ],
            },
            SerdeTestCase {
                value: CorimRoleTypeChoice::Extension(1337),
                expected_json: "\"Role(1337)\"",
                expected_cbor: vec![ 0x19, 0x05, 0x39 ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_corim_entity_map_serde() {
        let entity_map = CorimEntityMapBuilder::default()
            .entity_name("foo".into())
            .reg_id("https://example.com".into())
            .add_role(CorimRoleTypeChoice::ManifestSigner)
            .add_extension(-1, ExtensionValue::Text("test value".into()))
            .build()
            .unwrap();

        let mut actual_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&entity_map, &mut actual_cbor).unwrap();

        let expected_cbor: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [entity-name]
              0x63, // value: tstr(3)
                0x66, 0x6f, 0x6f, // "foo"
              0x01, // key: 1 [reg-id]
              0xd8, 0x20, // value: tag(32)
                0x73, // tstr(19)
                  0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, // "https://"
                  0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, // "example."
                  0x63, 0x6f, 0x6d,                               // "com"
              0x02, // key: 2 [role]
              0x81, // value: array(1)
                0x02, // 2 [manifest-signer]
              0x20, // key: -1 [extension]
              0x6a, // value: tstr(10)
                0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x61, 0x6c, // "test val"
                0x75, 0x65,                                     // "ue"
            0xff, // break
        ];

        assert_eq!(actual_cbor, expected_cbor);

        let entity_map_de: CorimEntityMap = ciborium::from_reader(actual_cbor.as_slice()).unwrap();

        assert_eq!(entity_map_de, entity_map);

        let actual_json = serde_json::to_string(&entity_map).unwrap();

        let expected_json = r#"{"entity-name":"foo","reg-id":{"type":"uri","value":"https://example.com"},"role":["manifest-signer"],"-1":"test value"}"#;

        assert_eq!(actual_json, expected_json);

        let entity_map_de: CorimEntityMap = serde_json::from_str(actual_json.as_str()).unwrap();

        assert_eq!(entity_map_de, entity_map);
    }

    #[test]
    fn test_validity_map_serde() {
        let validity_map = ValidityMap {
            not_before: Some(1.into()),
            not_after: 2.into(),
        };

        let mut actual_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&validity_map, &mut actual_cbor).unwrap();

        let expected_cbor = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [not-before]
              0x01, // value: 1
              0x01, // key: 1 [not-after]
              0x02,// value: 2
            0xff, // break
        ];

        assert_eq!(actual_cbor, expected_cbor);

        let validity_map_de: ValidityMap = ciborium::from_reader(actual_cbor.as_slice()).unwrap();

        assert_eq!(validity_map_de, validity_map);

        let actual_json = serde_json::to_string(&validity_map).unwrap();

        let expected_json = r#"{"not-before":1,"not-after":2}"#;

        assert_eq!(actual_json, expected_json);

        let validity_map_de: ValidityMap = serde_json::from_str(actual_json.as_str()).unwrap();

        assert_eq!(validity_map_de, validity_map);
    }
}
