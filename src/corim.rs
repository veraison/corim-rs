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
//! - [`SignedCorim`] - A signed manifest wrapper using COSE_Sign1 (CBOR tag 18)
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
//! └── SignedCorim (signed)
//!     ├── alg
//!     ├── kid
//!     ├── corim_meta
//!     └── corim_map (CorimMap, as above)
//! ```
//!
//! ## Example Usage
//!
//! ```rust
//! use corim_rs::{
//!     ConciseMidTagBuilder, Corim, CorimEntityMapBuilder, CorimError, CorimMapBuilder,
//!     CorimMetaMapBuilder, CorimRoleTypeChoice, CoseAlgorithm, CoseKey, CoseKeyOwner, CoseSigner,
//!     CoseVerifier, EndorsedTripleRecord, EnvironmentMapBuilder, MeasurementMap,
//!     MeasurementValuesMapBuilder, SignedCorimBuilder, TagIdentityMap, TriplesMapBuilder,
//! };
//!
//! let corim: Corim = CorimMapBuilder::new()
//!     .id("foo".into())
//!     .add_tag(
//!         ConciseMidTagBuilder::new()
//!             .tag_identity(TagIdentityMap {
//!                 tag_id: "bar".into(),
//!                 tag_version: None,
//!             })
//!             .triples(
//!                 TriplesMapBuilder::new()
//!                     .endorsed_triples(vec![EndorsedTripleRecord {
//!                         condition: EnvironmentMapBuilder::default()
//!                             .instance([0x01, 0x02, 0x03].as_slice().into())
//!                             .build()
//!                             .unwrap(),
//!                         endorsement: vec![MeasurementMap {
//!                             mkey: None,
//!                             mval: MeasurementValuesMapBuilder::default()
//!                                 .svn(1.into())
//!                                 .build()
//!                                 .unwrap(),
//!                             authorized_by: None,
//!                         }],
//!                     }])
//!                     .build()
//!                     .unwrap(),
//!             )
//!             .build()
//!             .unwrap()
//!             .into(),
//!     )
//!     .add_entity(
//!         CorimEntityMapBuilder::new()
//!             .entity_name("baz".into())
//!             .add_role(CorimRoleTypeChoice::ManifestCreator)
//!             .build()
//!             .unwrap(),
//!     )
//!     .build()
//!     .unwrap()
//!     .into();
//!
//!     let output = corim.to_cbor().unwrap();
//!
//! // Signing
//!
//! // A fake signer to avoid pulling additional dependencies
//! struct FakeSigner {}
//!
//! impl CoseKeyOwner for FakeSigner {
//!     fn to_cose_key(&self) -> CoseKey {
//!         CoseKey {
//!             kty: corim_rs::core::CoseKty::Ec2,
//!             kid: None,
//!             alg: Some(corim_rs::core::CoseAlgorithm::ES256),
//!             key_ops: Some(vec![
//!                 corim_rs::core::CoseKeyOperation::Sign,
//!                 corim_rs::core::CoseKeyOperation::Verify,
//!             ]),
//!             base_iv: None,
//!             crv: None,
//!             x: None,
//!             y: None,
//!             d: None,
//!             k: None,
//!         }
//!     }
//! }
//!
//! impl CoseSigner for FakeSigner {
//!     fn sign(&self, _: CoseAlgorithm, _: &[u8]) -> Result<Vec<u8>, CorimError> {
//!         Ok(vec![0xde, 0xad, 0xbe, 0xef])
//!     }
//! }
//!
//! impl CoseVerifier for FakeSigner {
//!     fn verify_signature(&self, _: CoseAlgorithm, _: &[u8], _: &[u8]) -> Result<(), CorimError> {
//!         Ok(())
//!     }
//! }
//!
//! let signer = FakeSigner {};
//!
//! let signed: Corim = SignedCorimBuilder::new()
//!     .alg(CoseAlgorithm::ES256)
//!     .kid(vec![0x01, 0x02, 0x03])
//!     .meta(CorimMetaMapBuilder::new()
//!         .signer_name("fake signer".into())
//!         .build()
//!         .unwrap()
//!     )
//!     .corim_map(corim.into()) // CorimMap unpacked from the unsigned CoRIM
//!     .build_and_sign(signer)
//!     .unwrap()
//!     .into();
//!
//! let output = signed.to_cbor().unwrap();
//!
//! // Siganture verfication
//!
//! let verifier = FakeSigner {};
//! let corim = Corim::from_cbor(output.as_slice()).unwrap();
//!
//! corim.as_signed().unwrap().verify_signature(verifier).unwrap();
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

use std::{
    fmt::{self, Display},
    marker::PhantomData,
    ops::Deref,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    comid::ConciseMidTag,
    core::{CoseAlgorithm, CoseKey, CoseKeyOperation, IntegerTime, ObjectIdentifier, OneOrMore},
    coswid::ConciseSwidTag,
    cotl::ConciseTlTag,
    error::CorimError,
    generate_tagged,
    numbers::Integer,
    Digest, Empty, ExtensionMap, ExtensionValue, OidType, TaggedBytes, TaggedConciseMidTag,
    TaggedConciseSwidTag, TaggedConciseTlTag, Text, Tstr, Uri, UuidType,
};

use coset::{iana::EnumI64 as _, AsCborValue as _, CoseSign1};
use derive_more::{Constructor, From, TryFrom};
use serde::{
    de::{self, Visitor},
    ser::{self, SerializeMap},
    Deserialize, Deserializer, Serialize, Serializer,
};
/// Represents a Concise Reference Integrity Manifest (CoRIM)
pub type Corim<'a> = ConciseRimTypeChoice<'a>;

pub type UnsignedCorimMap<'a> = CorimMap<'a>;

/// A type choice representing either a signed or unsigned CoRIM manifest
#[repr(C)]
#[derive(Debug, From, TryFrom)]
#[allow(clippy::large_enum_variant)]
pub enum ConciseRimTypeChoice<'a> {
    /// An unprotected CoRIM with CBOR tag 501
    Unsigned(TaggedUnsignedCorim<'a>),
    /// A COSE Sign1 protected CoRIM with CBOR tag 18
    Signed(TaggedSignedCorim<'a>),
}

impl<'a> ConciseRimTypeChoice<'a> {
    pub fn is_signed(self) -> bool {
        match self {
            ConciseRimTypeChoice::Signed(_) => true,
            ConciseRimTypeChoice::Unsigned(_) => false,
        }
    }

    pub fn as_signed(self) -> Option<SignedCorim<'a>> {
        match self {
            ConciseRimTypeChoice::Signed(signed) => Some(signed.0 .0),
            ConciseRimTypeChoice::Unsigned(_) => None,
        }
    }

    pub fn as_signed_ref(&self) -> Option<&SignedCorim<'a>> {
        match self {
            ConciseRimTypeChoice::Signed(signed) => Some(&signed.0 .0),
            ConciseRimTypeChoice::Unsigned(_) => None,
        }
    }

    pub fn as_signed_mut(&mut self) -> Option<&mut SignedCorim<'a>> {
        match self {
            ConciseRimTypeChoice::Signed(signed) => Some(&mut signed.0 .0),
            ConciseRimTypeChoice::Unsigned(_) => None,
        }
    }

    pub fn as_unsigned(self) -> Option<CorimMap<'a>> {
        match self {
            ConciseRimTypeChoice::Signed(_) => None,
            ConciseRimTypeChoice::Unsigned(unsigned) => Some(unsigned.0 .0),
        }
    }

    pub fn as_unsigned_ref(&self) -> Option<&CorimMap<'a>> {
        match self {
            ConciseRimTypeChoice::Signed(_) => None,
            ConciseRimTypeChoice::Unsigned(unsigned) => Some(&unsigned.0 .0),
        }
    }

    pub fn as_unsigned_mut(&mut self) -> Option<&mut CorimMap<'a>> {
        match self {
            ConciseRimTypeChoice::Signed(_) => None,
            ConciseRimTypeChoice::Unsigned(unsigned) => Some(&mut unsigned.0 .0),
        }
    }

    pub fn as_map_ref(&self) -> &CorimMap<'a> {
        match self {
            ConciseRimTypeChoice::Signed(signed) => &signed.corim_map,
            ConciseRimTypeChoice::Unsigned(unsigned) => &unsigned.0 .0,
        }
    }

    pub fn as_map_mut(&mut self) -> &mut CorimMap<'a> {
        match self {
            ConciseRimTypeChoice::Signed(signed) => &mut signed.corim_map,
            ConciseRimTypeChoice::Unsigned(unsigned) => &mut unsigned.0 .0,
        }
    }

    pub fn into_map(self) -> CorimMap<'a> {
        match self {
            ConciseRimTypeChoice::Signed(signed) => signed.0 .0.corim_map,
            ConciseRimTypeChoice::Unsigned(unsigned) => unsigned.0 .0,
        }
    }

    pub fn from_json<R: std::io::Read>(src: R) -> Result<Self, CorimError> {
        Ok(TaggedUnsignedCorim::from_json(src)?.into())
    }

    pub fn from_cbor<R: std::io::Read>(src: R) -> Result<Self, CorimError> {
        ciborium::from_reader(src).map_err(CorimError::custom)
    }

    pub fn to_json(&self) -> Result<String, CorimError> {
        match self {
            Self::Signed(_) => Err(CorimError::custom("cannot encode SignedCorim to JSON")),
            Self::Unsigned(val) => val.to_json(),
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CorimError> {
        let mut buf: Vec<u8> = vec![];
        ciborium::into_writer(&self, &mut buf).map_err(CorimError::custom)?;
        Ok(buf)
    }
}

impl<'a> From<ConciseRimTypeChoice<'a>> for CorimMap<'a> {
    fn from(value: ConciseRimTypeChoice<'a>) -> Self {
        match value {
            ConciseRimTypeChoice::Signed(val) => val.unwrap().corim_map,
            ConciseRimTypeChoice::Unsigned(val) => val.unwrap(),
        }
    }
}

impl<'a> From<CorimMap<'a>> for ConciseRimTypeChoice<'a> {
    fn from(value: CorimMap<'a>) -> Self {
        Self::Unsigned(value.into())
    }
}

impl<'a> From<SignedCorim<'a>> for ConciseRimTypeChoice<'a> {
    fn from(value: SignedCorim<'a>) -> Self {
        Self::Signed(value.into())
    }
}

impl Serialize for ConciseRimTypeChoice<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Unsigned(tagged) => tagged.serialize(serializer),
            Self::Signed(tagged) => tagged.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ConciseRimTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match ciborium::Value::deserialize(deserializer)? {
            ciborium::Value::Tag(tag, inner) => {
                // Re-serializing the inner Value so that we can deserialize it
                // into an appropriate type, once we figure out what that is
                // based on the tag.
                let mut buf: Vec<u8> = Vec::new();
                ciborium::into_writer(&inner, &mut buf).unwrap();

                match tag {
                    18 => {
                        let signed: SignedCorim =
                            ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                        Ok(Self::Signed(signed.into()))
                    }
                    501 => {
                        let corim_map: CorimMap =
                            ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                        Ok(Self::Unsigned(corim_map.into()))
                    }
                    n => Err(de::Error::custom(format!(
                        "unexpected ConciseRimTypeChoice tag {n}"
                    ))),
                }
            }
            _ => Err(de::Error::custom(
                "did not see a tag for ConciseRimTypeChoice",
            )),
        }
    }
}

generate_tagged!(
    (
        501,
        TaggedUnsignedCorim,
        CorimMap<'a>,
        'a,
        "unsigned-corim",
        "A CBOR tagged, unsigned CoRIM Map."
    ),
    (
        18,
        TaggedSignedCorim,
        SignedCorim<'a>,
        'a,
        "signed-corim",
        "A CBOR tagged, signed CoRIM."
    )
);

impl TaggedSignedCorim<'_> {
    pub fn from_cbor<R: std::io::Read>(src: R) -> Result<Self, CorimError> {
        ciborium::from_reader(src).map_err(CorimError::custom)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CorimError> {
        let mut buf: Vec<u8> = vec![];
        ciborium::into_writer(&self, &mut buf).map_err(CorimError::custom)?;
        Ok(buf)
    }
}

impl TaggedUnsignedCorim<'_> {
    pub fn from_json<R: std::io::Read>(mut src: R) -> Result<Self, CorimError> {
        let mut buf = String::new();
        src.read_to_string(&mut buf).map_err(CorimError::custom)?;
        serde_json::from_str(&buf).map_err(CorimError::custom)
    }

    pub fn from_cbor<R: std::io::Read>(src: R) -> Result<Self, CorimError> {
        ciborium::from_reader(src).map_err(CorimError::custom)
    }

    pub fn to_json(&self) -> Result<String, CorimError> {
        serde_json::to_string(&self).map_err(CorimError::custom)
    }

    pub fn to_json_pretty(&self) -> Result<String, CorimError> {
        serde_json::to_string_pretty(&self).map_err(CorimError::custom)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CorimError> {
        let mut buf: Vec<u8> = vec![];
        ciborium::into_writer(&self, &mut buf).map_err(CorimError::custom)?;
        Ok(buf)
    }
}

/// The main CoRIM manifest structure containing all reference integrity data
/// and associated metadata. Tagged with CBOR tag 501.#[repr(C)]
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct CorimMap<'a> {
    /// Unique identifier for the CoRIM
    pub id: CorimIdTypeChoice<'a>,
    /// Collection of tags contained in this CoRIM
    pub tags: Vec<ConciseTagTypeChoice<'a>>,
    /// Optional references to other CoRIMs this one depends on
    pub dependent_rims: Option<Vec<CorimLocatorMap<'a>>>,
    /// Optional profile information
    pub profile: Option<ProfileTypeChoice<'a>>,
    /// Optional validity period for the CoRIM
    pub rim_validity: Option<ValidityMap>,
    /// Optional list of entities associated with this CoRIM
    pub entities: Option<Vec<CorimEntityMap<'a>>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl CorimMap<'_> {
    pub fn from_json<R: std::io::Read>(mut src: R) -> Result<Self, CorimError> {
        let mut buf = String::new();
        src.read_to_string(&mut buf).map_err(CorimError::custom)?;
        serde_json::from_str(&buf).map_err(CorimError::custom)
    }

    pub fn to_json(&self) -> Result<String, CorimError> {
        serde_json::to_string(&self).map_err(CorimError::custom)
    }

    pub fn to_json_pretty(&self) -> Result<String, CorimError> {
        serde_json::to_string_pretty(&self).map_err(CorimError::custom)
    }
}

impl Serialize for CorimMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("id", &self.id)?;
            map.serialize_entry("tags", &self.tags)?;

            if let Some(dependent_rims) = &self.dependent_rims {
                map.serialize_entry("dependent-rims", dependent_rims)?;
            }

            if let Some(profile) = &self.profile {
                map.serialize_entry("profile", profile)?;
            }

            if let Some(rim_validity) = &self.rim_validity {
                map.serialize_entry("rim-validity", rim_validity)?;
            }

            if let Some(entities) = &self.entities {
                map.serialize_entry("entities", entities)?;
            }
        } else {
            map.serialize_entry(&0, &self.id)?;
            map.serialize_entry(&1, &self.tags)?;

            if let Some(dependent_rims) = &self.dependent_rims {
                map.serialize_entry(&2, dependent_rims)?;
            }

            if let Some(profile) = &self.profile {
                map.serialize_entry(&3, profile)?;
            }

            if let Some(rim_validity) = &self.rim_validity {
                map.serialize_entry(&4, rim_validity)?;
            }

            if let Some(entities) = &self.entities {
                map.serialize_entry(&5, entities)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for CorimMap<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CorimMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CorimMapVisitor<'a> {
            type Value = CorimMap<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map containing CorimMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = CorimMapBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("id") => {
                                builder = builder.id(map.next_value::<CorimIdTypeChoice>()?);
                            }
                            Some("tags") => {
                                builder =
                                    builder.tags(map.next_value::<Vec<ConciseTagTypeChoice>>()?);
                            }
                            Some("dependent-rims") => {
                                builder = builder
                                    .dependent_rims(map.next_value::<Vec<CorimLocatorMap>>()?);
                            }
                            Some("profile") => {
                                builder = builder.profile(map.next_value::<ProfileTypeChoice>()?);
                            }
                            Some("rim-validity") => {
                                builder = builder.rim_validity(map.next_value::<ValidityMap>()?);
                            }
                            Some("entities") => {
                                builder =
                                    builder.entities(map.next_value::<Vec<CorimEntityMap>>()?);
                            }
                            Some(s) => {
                                let ext_field: i128 = s.parse().map_err(|_| {
                                    de::Error::unknown_field(
                                        s,
                                        &[
                                            "id",
                                            "tags",
                                            "dependent-rims",
                                            "profile",
                                            "rim-validity",
                                            "entities",
                                            "any integer",
                                        ],
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
                                builder = builder.id(map.next_value::<CorimIdTypeChoice>()?);
                            }
                            Some(1) => {
                                builder =
                                    builder.tags(map.next_value::<Vec<ConciseTagTypeChoice>>()?);
                            }
                            Some(2) => {
                                builder = builder
                                    .dependent_rims(map.next_value::<Vec<CorimLocatorMap>>()?);
                            }
                            Some(3) => {
                                builder = builder.profile(map.next_value::<ProfileTypeChoice>()?);
                            }
                            Some(4) => {
                                builder = builder.rim_validity(map.next_value::<ValidityMap>()?);
                            }
                            Some(5) => {
                                builder =
                                    builder.entities(map.next_value::<Vec<CorimEntityMap>>()?);
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
        deserializer.deserialize_map(CorimMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct CorimMapBuilder<'a> {
    id: Option<CorimIdTypeChoice<'a>>,
    tags: Option<Vec<ConciseTagTypeChoice<'a>>>,
    dependent_rims: Option<Vec<CorimLocatorMap<'a>>>,
    profile: Option<ProfileTypeChoice<'a>>,
    rim_validity: Option<ValidityMap>,
    entities: Option<Vec<CorimEntityMap<'a>>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> CorimMapBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn id(mut self, value: CorimIdTypeChoice<'a>) -> Self {
        self.id = Some(value);
        self
    }

    pub fn tags(mut self, value: Vec<ConciseTagTypeChoice<'a>>) -> Self {
        self.tags = Some(value);
        self
    }

    pub fn add_tag(mut self, value: ConciseTagTypeChoice<'a>) -> Self {
        if let Some(ref mut tags) = self.tags {
            tags.push(value);
        } else {
            self.tags = Some(vec![value]);
        }
        self
    }

    pub fn dependent_rims(mut self, value: Vec<CorimLocatorMap<'a>>) -> Self {
        self.dependent_rims = Some(value);
        self
    }

    pub fn add_dependent_rim(mut self, value: CorimLocatorMap<'a>) -> Self {
        if let Some(ref mut dependent_rims) = self.dependent_rims {
            dependent_rims.push(value);
        } else {
            self.dependent_rims = Some(vec![value]);
        }
        self
    }

    pub fn profile(mut self, value: ProfileTypeChoice<'a>) -> Self {
        self.profile = Some(value);
        self
    }

    pub fn rim_validity(mut self, value: ValidityMap) -> Self {
        self.rim_validity = Some(value);
        self
    }

    pub fn entities(mut self, value: Vec<CorimEntityMap<'a>>) -> Self {
        self.entities = Some(value);
        self
    }

    pub fn add_entity(mut self, value: CorimEntityMap<'a>) -> Self {
        if let Some(ref mut entities) = self.entities {
            entities.push(value);
        } else {
            self.entities = Some(vec![value]);
        }
        self
    }

    pub fn extensions(mut self, value: ExtensionMap<'a>) -> Self {
        self.extensions = Some(value);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(ref mut extensions) = self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::default();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions);
        }
        self
    }

    pub fn build(self) -> crate::Result<CorimMap<'a>> {
        if self.id.is_none() {
            return Err(CorimError::UnsetMandatoryField(
                "CorimMap".to_string(),
                "id".to_string(),
            ))?;
        }

        if self.tags.is_none() {
            return Err(CorimError::UnsetMandatoryField(
                "CorimMap".to_string(),
                "tags".to_string(),
            ))?;
        } else if self.tags.as_ref().unwrap().is_empty() {
            return Err(CorimError::InvalidFieldValue(
                "CorimMap".to_string(),
                "tags".to_string(),
                "must not be empty".to_string(),
            ))?;
        }

        if self.dependent_rims.is_some() && self.dependent_rims.as_ref().unwrap().is_empty() {
            return Err(CorimError::InvalidFieldValue(
                "CorimMap".to_string(),
                "dependent_rims".to_string(),
                "must not be empty".to_string(),
            ))?;
        }

        if self.entities.is_some() && self.entities.as_ref().unwrap().is_empty() {
            return Err(CorimError::InvalidFieldValue(
                "CorimMap".to_string(),
                "entities".to_string(),
                "must not be empty".to_string(),
            ))?;
        }

        Ok(CorimMap {
            id: self.id.unwrap(),
            tags: self.tags.unwrap(),
            dependent_rims: self.dependent_rims,
            profile: self.profile,
            rim_validity: self.rim_validity,
            entities: self.entities,
            extensions: self.extensions,
        })
    }
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

impl Display for CorimIdTypeChoice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s;

        f.write_str(match self {
            Self::Tstr(tstr) => tstr,
            Self::Uuid(uuid) => {
                s = uuid.to_string();
                s.as_str()
            }
            Self::Extension(ext) => {
                s = format!("{:?}", ext);
                s.as_str()
            }
        })
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
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ConciseTagTypeChoice<'a> {
    /// A Concise Software Identity (CoSWID) tag
    Swid(TaggedConciseSwidTag<'a>),
    /// A Concise Module Identity (CoMID) tag
    Mid(TaggedConciseMidTag<'a>),
    /// A Concise Trust List (CoTL) tag
    Tl(TaggedConciseTlTag<'a>),
    /// Extension value for tags not defined by the spec
    Extension(ExtensionValue<'a>),
}

impl Serialize for ConciseTagTypeChoice<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();

        if is_human_readable {
            match self {
                Self::Swid(tagged_coswid) => tagged_coswid.serialize(serializer),
                Self::Mid(tagged_comid) => tagged_comid.serialize(serializer),
                Self::Tl(tagged_cotl) => tagged_cotl.serialize(serializer),
                Self::Extension(ext) => ext.serialize(serializer),
            }
        } else {
            let mut bytes: Vec<u8> = vec![];
            let tag_number: u64;

            match self {
                Self::Swid(tagged_coswid) => {
                    tag_number = 505;
                    ciborium::into_writer(&tagged_coswid.0 .0, &mut bytes)
                        .map_err(ser::Error::custom)?;
                }
                Self::Mid(tagged_comid) => {
                    tag_number = 506;
                    ciborium::into_writer(&tagged_comid.0 .0, &mut bytes)
                        .map_err(ser::Error::custom)?;
                }
                Self::Tl(tagged_cotl) => {
                    tag_number = 508;
                    ciborium::into_writer(&tagged_cotl.0 .0, &mut bytes)
                        .map_err(ser::Error::custom)?;
                }
                Self::Extension(ext) => {
                    return ext.serialize(serializer);
                }
            }

            ciborium::value::Value::Tag(tag_number, Box::new(ciborium::value::Value::Bytes(bytes)))
                .serialize(serializer)
        }
    }
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
                if deserializer.is_human_readable() {
                    match serde_json::Value::deserialize(deserializer)? {
                        serde_json::Value::Object(map) => {
                            if map.contains_key("type")
                                && map.contains_key("value")
                                && map.len() == 2
                            {
                                let value = serde_json::to_string(&map["value"]).unwrap();

                                match &map["type"] {
                                    serde_json::Value::String(typ) => match typ.as_str() {
                                        "coswid" => {
                                            let swid: ConciseSwidTag<'a> =
                                                serde_json::from_str(value.as_str())
                                                    .map_err(de::Error::custom)?;
                                            Ok(ConciseTagTypeChoice::Swid(
                                                TaggedConciseSwidTag::new(swid),
                                            ))
                                        }
                                        "comid" => {
                                            let mid: ConciseMidTag<'a> =
                                                serde_json::from_str(value.as_str())
                                                    .map_err(de::Error::custom)?;
                                            Ok(ConciseTagTypeChoice::Mid(TaggedConciseMidTag::new(
                                                mid,
                                            )))
                                        }
                                        "cotl" => {
                                            let tl: ConciseTlTag<'a> =
                                                serde_json::from_str(value.as_str())
                                                    .map_err(de::Error::custom)?;
                                            Ok(ConciseTagTypeChoice::Tl(TaggedConciseTlTag::new(
                                                tl,
                                            )))
                                        }
                                        s => Err(de::Error::custom(format!(
                                            "unexpected type {s} for ClassIdTypeChoice"
                                        ))),
                                    },
                                    v => Err(de::Error::custom(format!(
                                        "type must be as string, got {v:?}"
                                    ))),
                                }
                            } else if map.contains_key("tag")
                                && map.contains_key("value")
                                && map.len() == 2
                            {
                                match &map["tag"] {
                                    serde_json::Value::Number(n) => match n.as_u64() {
                                        Some(u) => Ok(ConciseTagTypeChoice::Extension(
                                            ExtensionValue::Tag(
                                                u,
                                                Box::new(
                                                    ExtensionValue::try_from(map["value"].clone())
                                                        .map_err(de::Error::custom)?,
                                                ),
                                            ),
                                        )),
                                        None => Err(de::Error::custom(format!(
                                            "a number must be an unsinged integer, got {n:?}"
                                        ))),
                                    },
                                    v => Err(de::Error::custom(format!("invalid tag {v:?}"))),
                                }
                            } else {
                                Ok(ConciseTagTypeChoice::Extension(
                                    ExtensionValue::try_from(serde_json::Value::Object(map))
                                        .map_err(de::Error::custom)?,
                                ))
                            }
                        }
                        value => Ok(ConciseTagTypeChoice::Extension(
                            ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                        )),
                    }
                } else {
                    let tagged_value = ciborium::value::Value::deserialize(deserializer)?;
                    match tagged_value {
                        ciborium::Value::Tag(tag, inner) => match tag {
                            known_tag @ (505 | 506 | 508) => {
                                let bytes: Vec<u8> = match *inner {
                                    ciborium::Value::Bytes(b) => b,
                                    _ => {
                                        return Err(de::Error::custom(
                                            "CoRIM tag must be a byte string",
                                        ))
                                    }
                                };

                                match known_tag {
                                    505 => {
                                        let swid: ConciseSwidTag<'a> =
                                            ciborium::from_reader(&bytes[..]).map_err(|_| {
                                                serde::de::Error::custom(
                                                    "Failed to deserialize bytes",
                                                )
                                            })?;
                                        Ok(ConciseTagTypeChoice::Swid(TaggedConciseSwidTag::new(
                                            swid,
                                        )))
                                    }
                                    506 => {
                                        let mid: ConciseMidTag<'a> =
                                            ciborium::from_reader(&bytes[..]).map_err(|_| {
                                                serde::de::Error::custom(
                                                    "Failed to deserialize bytes",
                                                )
                                            })?;
                                        Ok(ConciseTagTypeChoice::Mid(TaggedConciseMidTag::new(mid)))
                                    }
                                    508 => {
                                        let tl: ConciseTlTag<'a> =
                                            ciborium::from_reader(&bytes[..]).map_err(|_| {
                                                serde::de::Error::custom(
                                                    "Failed to deserialize bytes",
                                                )
                                            })?;
                                        Ok(ConciseTagTypeChoice::Tl(TaggedConciseTlTag::new(tl)))
                                    }
                                    _ => panic!("should never get here"),
                                }
                            }
                            other_tag => Ok(ConciseTagTypeChoice::Extension(
                                ExtensionValue::try_from(ciborium::Value::Tag(other_tag, inner))
                                    .map_err(de::Error::custom)?,
                            )),
                        },
                        value => Ok(ConciseTagTypeChoice::Extension(
                            ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                        )),
                    }
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
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct CorimLocatorMap<'a> {
    /// URI(s) where the dependent CoRIM can be found
    pub href: OneOrMore<Uri<'a>>,
    /// Optional cryptographic thumbprint for verification
    pub thumbprint: Option<Digest>,
}

impl Serialize for CorimLocatorMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None).unwrap();

        if is_human_readable {
            map.serialize_entry("href", &self.href)?;

            if let Some(thumbprint) = &self.thumbprint {
                map.serialize_entry("thumbprint", thumbprint)?;
            }
        } else {
            map.serialize_entry(&0, &self.href)?;

            if let Some(thumbprint) = &self.thumbprint {
                map.serialize_entry(&1, thumbprint)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for CorimLocatorMap<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CorimLocatorMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CorimLocatorMapVisitor<'a> {
            type Value = CorimLocatorMap<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map containing CorimLocatorMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut href: Option<OneOrMore<Uri<'a>>> = None;
                let mut thumbprint: Option<Digest> = None;

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("href") => {
                                href = map.next_value()?;
                            }
                            Some("thumbprint") => {
                                thumbprint = map.next_value()?;
                            }
                            Some(s) => {
                                return Err(de::Error::unknown_field(s, &["href", "thumbprint"]))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                href = map.next_value()?;
                            }
                            Some(1) => {
                                thumbprint = map.next_value()?;
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

                if href.is_none() {
                    return Err(de::Error::missing_field("href"));
                }

                Ok(CorimLocatorMap {
                    href: href.unwrap(),
                    thumbprint,
                })
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(CorimLocatorMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

/// Profile identifier that can be either a URI or OID
#[repr(C)]
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum ProfileTypeChoice<'a> {
    /// URI-based profile identifier
    Uri(Uri<'a>),
    /// OID-based profile identifier
    Oid(OidType),
    /// Type extension
    Extension(ExtensionValue<'a>),
}

#[allow(clippy::needless_lifetimes)]
impl<'a, 'b> ProfileTypeChoice<'a> {
    pub fn to_fully_owned(&self) -> ProfileTypeChoice<'b> {
        match self {
            ProfileTypeChoice::Uri(uri) => ProfileTypeChoice::Uri(uri.to_string().into()),
            ProfileTypeChoice::Oid(oid) => ProfileTypeChoice::Oid(oid.clone()),
            ProfileTypeChoice::Extension(ext) => ProfileTypeChoice::Extension(ext.to_fully_owned()),
        }
    }
}

impl<'a> ProfileTypeChoice<'a> {
    pub fn is_uri(&self) -> bool {
        matches!(self, Self::Uri(_))
    }

    pub fn is_oid(&self) -> bool {
        matches!(self, Self::Oid(_))
    }

    pub fn is_extension(&self) -> bool {
        matches!(self, Self::Extension(_))
    }

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
            Self::Oid(oid) => Some(oid.as_ref().as_ref()),
            _ => None,
        }
    }

    pub fn as_ref_extension(&self) -> Option<&ExtensionValue<'a>> {
        match self {
            Self::Extension(ext) => Some(ext),
            _ => None,
        }
    }

    pub fn as_extension(&self) -> Option<ExtensionValue<'a>> {
        match self {
            Self::Extension(ext) => Some(ext.clone()),
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
            Self::Oid(oid) => oid.serialize(serializer),
            Self::Extension(ext) => ext.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ProfileTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            match serde_json::Value::deserialize(deserializer)? {
                serde_json::Value::Object(map) => {
                    if map.contains_key("type") && map.contains_key("value") && map.len() == 2 {
                        let value = match &map["value"] {
                            serde_json::Value::String(s) => Ok(s),
                            v => Err(de::Error::custom(format!(
                                "value must be a string, got {v:?}"
                            ))),
                        }?;

                        match &map["type"] {
                            serde_json::Value::String(typ) => match typ.as_str() {
                                "oid" => {
                                    let oid = ObjectIdentifier::try_from(value.as_str())
                                        .map_err(|e| de::Error::custom(format!("{:?}", e)))?;
                                    Ok(ProfileTypeChoice::Oid(oid.into()))
                                }
                                "uri" => {
                                    Ok(ProfileTypeChoice::Uri(Text::from(value.clone()).into()))
                                }
                                s => Err(de::Error::custom(format!(
                                    "unexpected ProfileTypeChoice type \"{s}\""
                                ))),
                            },
                            v => Err(de::Error::custom(format!(
                                "type must be as string, got {v:?}"
                            ))),
                        }
                    } else if map.contains_key("tag") && map.contains_key("value") && map.len() == 2
                    {
                        match &map["tag"] {
                            serde_json::Value::Number(n) => match n.as_u64() {
                                Some(u) => Ok(ProfileTypeChoice::Extension(ExtensionValue::Tag(
                                    u,
                                    Box::new(
                                        ExtensionValue::try_from(map["value"].clone())
                                            .map_err(de::Error::custom)?,
                                    ),
                                ))),
                                None => Err(de::Error::custom(format!(
                                    "a number must be an unsinged integer, got {n:?}"
                                ))),
                            },
                            v => Err(de::Error::custom(format!("invalid tag {v:?}"))),
                        }
                    } else {
                        Ok(ProfileTypeChoice::Extension(
                            ExtensionValue::try_from(serde_json::Value::Object(map))
                                .map_err(de::Error::custom)?,
                        ))
                    }
                }
                other => Ok(ProfileTypeChoice::Extension(
                    other.try_into().map_err(de::Error::custom)?,
                )),
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
                            Ok(ProfileTypeChoice::Oid(oid.into()))
                        }
                        32 => {
                            let uri: Text =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(ProfileTypeChoice::Uri(uri.into()))
                        }
                        n => Ok(ProfileTypeChoice::Extension(ExtensionValue::Tag(
                            n,
                            Box::new(
                                ExtensionValue::try_from(inner.deref().to_owned())
                                    .map_err(de::Error::custom)?,
                            ),
                        ))),
                    }
                }
                other => Ok(ProfileTypeChoice::Extension(
                    other.try_into().map_err(de::Error::custom)?,
                )),
            }
        }
    }
}

/// Defines the validity period for a CoRIM or signature
#[repr(C)]
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ValidityMap {
    /// Optional start time of the validity period
    pub not_before: Option<IntegerTime>,
    /// Required end time of the validity period
    pub not_after: IntegerTime,
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
                let mut not_before: Option<IntegerTime> = None;
                let mut not_after: Option<IntegerTime> = None;

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
                let mut builder = CorimEntityMapBuilder::new();

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

///  Trait implemented by entities that own key material that may be used to sign and/or verify
///  signatures of [SignedCorim]s.
pub trait CoseKeyOwner {
    /// Convert owned key material into a [CoseKey].
    fn to_cose_key(&self) -> CoseKey;
}

pub trait CoseSigner: CoseKeyOwner {
    // Sign provided data returning a buffer containing the signature.
    fn sign(&self, alg: CoseAlgorithm, data: &[u8]) -> Result<Vec<u8>, CorimError>;
}

pub trait CoseVerifier: CoseKeyOwner {
    /// Verify porivided signature against provided data using owned key material.
    fn verify_signature(
        &self,
        alg: CoseAlgorithm,
        sig: &[u8],
        data: &[u8],
    ) -> Result<(), CorimError>;

    /// Verify that the values in the signed CoRIM's COSE header are valid and compatible with the
    /// key owned by this verifier, and that the key iself is suitable for
    fn verify_header_and_key(&self, signed: &SignedCorim) -> Result<(), CorimError> {
        if let Some(validity) = &signed.meta.signature_validity {
            let current_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let not_after = validity.not_after.as_i128();
            if not_after < 0 {
                return Err(CorimError::custom("nagative validity period bound"));
            }

            if current_ts > not_after as u64 {
                return Err(CorimError::OutsideValidityPeriod);
            }

            if let Some(not_before) = &validity.not_before {
                let not_before = not_before.as_i128();
                if not_before < 0 {
                    return Err(CorimError::custom("nagative validity period bound"));
                }

                if current_ts < not_before as u64 {
                    return Err(CorimError::OutsideValidityPeriod);
                }
            }
        }

        let cose_key = self.to_cose_key();

        if let Some(key_ops) = &cose_key.key_ops {
            if !key_ops.contains(&CoseKeyOperation::Verify) {
                return Err(CorimError::InvalidCoseKey(
                    "key ops do not contain verify".to_string(),
                ));
            }
        }

        if let Some(key_alg) = &cose_key.alg {
            if key_alg != &signed.alg {
                return Err(CorimError::InvalidCoseKey(
                    "key algorithm does not match CoRIM header".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Extension map for CoRIM-specific extensions
#[repr(C)]
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct CorimMapExtension(pub TaggedBytes);

/// [SignedCorim] wraps a tagged [CorimMap] in an COSE_Sign1 message with appropriate header
/// values.
#[derive(Clone, Debug)]
pub struct SignedCorim<'a> {
    pub alg: CoseAlgorithm,
    pub kid: Vec<u8>,
    pub meta: CorimMetaMap<'a>,
    pub corim_map: CorimMap<'a>,

    sign1: CoseSign1,
}

impl SignedCorim<'_> {
    pub fn verify_signature<V: CoseVerifier>(&self, verifier: V) -> Result<(), CorimError> {
        verifier.verify_header_and_key(self)?;

        let aad: Vec<u8> = vec![];
        self.sign1.verify_signature(aad.as_slice(), |sig, data| {
            verifier.verify_signature(self.alg, sig, data)
        })
    }
}

impl From<SignedCorim<'_>> for CoseSign1 {
    fn from(value: SignedCorim<'_>) -> Self {
        value.sign1
    }
}

impl TryFrom<CoseSign1> for SignedCorim<'_> {
    type Error = CorimError;

    fn try_from(value: CoseSign1) -> Result<Self, Self::Error> {
        if value.payload.is_none() {
            return Err(CorimError::custom("CoseSign1 does not contain a payload"));
        }

        sign1_check_content_type(&value).map_err(CorimError::custom)?;

        let alg = sign1_extract_alg(&value).map_err(CorimError::custom)?;

        let kid = value.protected.header.key_id.clone();

        let meta = sign1_extract_meta(&value).map_err(CorimError::custom)?;

        let unsigned: TaggedUnsignedCorim =
            ciborium::from_reader(value.payload.as_ref().unwrap().as_slice())
                .map_err(CorimError::custom)?;

        Ok(SignedCorim {
            alg,
            kid,
            meta,
            corim_map: unsigned.unwrap(),
            sign1: value,
        })
    }
}

impl PartialEq for SignedCorim<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.corim_map.eq(&other.corim_map)
    }
}

impl Eq for SignedCorim<'_> {}

impl PartialOrd for SignedCorim<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SignedCorim<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.corim_map.cmp(&other.corim_map)
    }
}

impl Serialize for SignedCorim<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.sign1
            .clone()
            .to_cbor_value()
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedCorim<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = ciborium::value::Value::deserialize(deserializer)?;
        let sign1 = CoseSign1::from_cbor_value(val).map_err(de::Error::custom)?;
        sign1.try_into().map_err(de::Error::custom)
    }
}

fn sign1_extract_alg(sign1: &CoseSign1) -> Result<CoseAlgorithm, CorimError> {
    if let Some(header) = &sign1.protected.header.alg {
        let value = match header {
            coset::RegisteredLabelWithPrivate::PrivateUse(i) => Ok(*i),
            coset::RegisteredLabelWithPrivate::Assigned(i) => Ok(i.to_i64()),
            coset::RegisteredLabelWithPrivate::Text(s) => Err(CorimError::InvalidCoseHeader(
                1,
                "alg".to_string(),
                format!("invalid algorithm value \"{s}\" (must be an int)"),
            )),
        }?;

        CoseAlgorithm::try_from(value)
            .map_err(|e| CorimError::InvalidCoseHeader(1, "alg".to_string(), e.to_string()))
    } else {
        Err(CorimError::CoseHeaderNotSet(1, "alg".to_string()))
    }
}

fn sign1_check_content_type(sign1: &CoseSign1) -> Result<(), CorimError> {
    if let Some(header) = &sign1.protected.header.content_type {
        match header {
            coset::RegisteredLabel::Assigned(v) => Err(CorimError::InvalidCoseHeader(
                3,
                "content-type".to_string(),
                v.to_i64().to_string(),
            )),
            coset::RegisteredLabel::Text(s) => {
                if s.as_str() == "application/rim+cbor" {
                    Ok(())
                } else {
                    Err(CorimError::InvalidCoseHeader(
                        3,
                        "content-type".to_string(),
                        format!("\"{}\"", s),
                    ))
                }
            }
        }
    } else {
        Err(CorimError::CoseHeaderNotSet(3, "content-type".to_string()))
    }
}

fn sign1_extract_meta<'a>(sign1: &CoseSign1) -> Result<CorimMetaMap<'a>, CorimError> {
    for (label, value) in sign1.protected.header.rest.iter() {
        match label {
            coset::Label::Int(8) => match value {
                ciborium::Value::Bytes(bytes) => {
                    return ciborium::from_reader::<CorimMetaMap, _>(bytes.as_slice()).map_err(
                        |e| {
                            CorimError::InvalidCoseHeader(
                                8,
                                "corim-meta".to_string(),
                                format!("{:?}", e.to_string()),
                            )
                        },
                    )
                }
                value => {
                    return Err(CorimError::InvalidCoseHeader(
                        8,
                        "corim-meta".to_string(),
                        format!("{:?}", value),
                    ))
                }
            },
            coset::Label::Int(_) => (),
            coset::Label::Text(_) => (),
        }
    }

    Err(CorimError::CoseHeaderNotSet(8, "corim-meta".to_string()))
}

#[derive(Debug, Default)]
pub struct SignedCorimBuilder<'a> {
    alg: Option<CoseAlgorithm>,
    kid: Option<Vec<u8>>,
    meta: Option<CorimMetaMap<'a>>,
    corim_map: Option<CorimMap<'a>>,
}

impl<'a> SignedCorimBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn alg(mut self, alg: CoseAlgorithm) -> Self {
        self.alg = Some(alg);
        self
    }

    pub fn kid(mut self, kid: Vec<u8>) -> Self {
        self.kid = Some(kid);
        self
    }

    pub fn meta(mut self, meta: CorimMetaMap<'a>) -> Self {
        self.meta = Some(meta);
        self
    }

    pub fn corim_map(mut self, corim_map: CorimMap<'a>) -> Self {
        self.corim_map = Some(corim_map);
        self
    }

    pub fn build_and_sign<S: CoseSigner>(self, signer: S) -> Result<SignedCorim<'a>, CorimError> {
        if self.alg.is_none() {
            return Err(CorimError::unset_mandatory_field("SignedCorim", "alg"));
        }

        let coset_alg = coset::iana::Algorithm::from_i64(i64::from(self.alg.unwrap()));
        if coset_alg.is_none() {
            return Err(CorimError::custom("unsupported algorithm"));
        }

        if self.kid.is_none() {
            return Err(CorimError::unset_mandatory_field("SignedCorim", "kid"));
        }

        if self.meta.is_none() {
            return Err(CorimError::unset_mandatory_field("SignedCorim", "meta"));
        }

        let mut encoded_meta: Vec<u8> = vec![];
        ciborium::into_writer(&self.meta.as_ref().unwrap(), &mut encoded_meta)
            .map_err(CorimError::custom)?;

        if self.corim_map.is_none() {
            return Err(CorimError::unset_mandatory_field(
                "SignedCorim",
                "corim_map",
            ));
        }

        let tagged_unsigned = TaggedUnsignedCorim::from(self.corim_map.clone().unwrap());
        let mut payload: Vec<u8> = vec![];
        ciborium::into_writer(&tagged_unsigned, &mut payload).map_err(CorimError::custom)?;

        let key = signer.to_cose_key();

        if let Some(key_alg) = key.alg {
            if key_alg != self.alg.unwrap() {
                return Err(CorimError::custom(
                    "key algorithm doen't match CoRIM header",
                ));
            }
        }

        if let Some(key_ops) = &key.key_ops {
            if !key_ops.contains(&CoseKeyOperation::Sign) {
                return Err(CorimError::custom("key ops do not contain sign"));
            }
        }

        let header = coset::HeaderBuilder::new()
            .algorithm(coset_alg.unwrap())
            .content_type("application/rim+cbor".to_string())
            .key_id(self.kid.clone().unwrap())
            .value(8, ciborium::Value::Bytes(encoded_meta))
            .build();

        let aad: Vec<u8> = vec![];
        let sign1 = coset::CoseSign1Builder::new()
            .protected(header)
            .payload(payload)
            .try_create_signature(aad.as_slice(), |pt| signer.sign(self.alg.unwrap(), pt))?
            .build();

        Ok(SignedCorim {
            alg: self.alg.unwrap(),
            kid: self.kid.unwrap(),
            meta: self.meta.unwrap(),
            corim_map: self.corim_map.unwrap(),
            sign1,
        })
    }
}

/// Metadata about the CoRIM signing operation
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct CorimMetaMap<'a> {
    /// Information about the signer
    pub signer: CorimSignerMap<'a>,
    /// Optional validity period for the signature
    pub signature_validity: Option<ValidityMap>,
    /// Signer map extensions
    pub extensions: Option<ExtensionMap<'a>>,
}

impl CorimMetaMap<'_> {
    pub fn from_json<R: std::io::Read>(mut src: R) -> Result<Self, CorimError> {
        let mut buf = String::new();
        src.read_to_string(&mut buf).map_err(CorimError::custom)?;
        serde_json::from_str(&buf).map_err(CorimError::custom)
    }

    pub fn to_json(&self) -> Result<String, CorimError> {
        serde_json::to_string(&self).map_err(CorimError::custom)
    }

    pub fn to_json_pretty(&self) -> Result<String, CorimError> {
        serde_json::to_string_pretty(&self).map_err(CorimError::custom)
    }
}

impl Serialize for CorimMetaMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("signer", &self.signer)?;

            if let Some(signature_validity) = &self.signature_validity {
                map.serialize_entry("signature-validity", signature_validity)?;
            }
        } else {
            map.serialize_entry(&0, &self.signer)?;

            if let Some(signature_validity) = &self.signature_validity {
                map.serialize_entry(&1, signature_validity)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for CorimMetaMap<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CorimMetaMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CorimMetaMapVisitor<'a> {
            type Value = CorimMetaMap<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map containing CorimMetaMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut signer: Option<CorimSignerMap> = None;
                let mut signature_validity: Option<ValidityMap> = None;
                let mut extensions = ExtensionMap::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("signer") => {
                                signer = Some(map.next_value::<CorimSignerMap>()?);
                            }
                            Some("signature-validity") => {
                                signature_validity = Some(map.next_value::<ValidityMap>()?);
                            }
                            Some(s) => {
                                let ext_field: i128 = s.parse().map_err(|_| {
                                    de::Error::unknown_field(
                                        s,
                                        &["signer", "signature-validity", "any integer"],
                                    )
                                })?;
                                extensions
                                    .insert(ext_field.into(), map.next_value::<ExtensionValue>()?);
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                signer = Some(map.next_value::<CorimSignerMap>()?);
                            }
                            Some(1) => {
                                signature_validity = Some(map.next_value::<ValidityMap>()?);
                            }
                            Some(n) => {
                                extensions.insert(n.into(), map.next_value::<ExtensionValue>()?);
                            }
                            None => break,
                        }
                    }
                }

                if signer.is_none() {
                    return Err(de::Error::missing_field("signer"));
                }

                Ok(CorimMetaMap {
                    signer: signer.unwrap(),
                    signature_validity,
                    extensions: if extensions.is_empty() {
                        None
                    } else {
                        Some(extensions)
                    },
                })
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(CorimMetaMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct CorimMetaMapBuilder<'a> {
    signer_name: Option<EntityNameTypeChoice<'a>>,
    signer_uri: Option<Uri<'a>>,
    not_before: Option<IntegerTime>,
    not_after: Option<IntegerTime>,
    signer_extensions: Option<ExtensionMap<'a>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> CorimMetaMapBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn signer_name(mut self, signer_name: EntityNameTypeChoice<'a>) -> Self {
        self.signer_name = Some(signer_name);
        self
    }

    pub fn signer_uri(mut self, signer_uri: Uri<'a>) -> Self {
        self.signer_uri = Some(signer_uri);
        self
    }

    pub fn not_before(mut self, not_before: IntegerTime) -> Self {
        self.not_before = Some(not_before);
        self
    }

    pub fn not_after(mut self, not_after: IntegerTime) -> Self {
        self.not_after = Some(not_after);
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

    pub fn signer_extensions(mut self, signer_extensions: ExtensionMap<'a>) -> Self {
        self.signer_extensions = Some(signer_extensions);
        self
    }

    pub fn add_signer_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(ref mut extensions) = self.signer_extensions {
            extensions.insert(Integer(key), value);
        } else {
            let mut extensions = ExtensionMap::default();
            extensions.insert(Integer(key), value);
            self.signer_extensions = Some(extensions);
        }
        self
    }

    pub fn build(self) -> Result<CorimMetaMap<'a>, CorimError> {
        if self.signer_name.is_none() {
            return Err(CorimError::unset_mandatory_field(
                "CorimSignerMap",
                "signer_name",
            ));
        }

        let validity: Option<ValidityMap> = match self.not_after {
            Some(not_after) => Some(ValidityMap {
                not_before: self.not_before,
                not_after,
            }),
            None => {
                if self.not_before.is_some() {
                    return Err(CorimError::custom("not_before is set but not_after is not"));
                }
                None
            }
        };

        Ok(CorimMetaMap {
            signer: CorimSignerMap {
                signer_name: self.signer_name.unwrap(),
                signer_uri: self.signer_uri,
                extensions: self.signer_extensions,
            },
            signature_validity: validity,
            extensions: self.extensions,
        })
    }
}

/// Information about the entity that signed the CoRIM
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct CorimSignerMap<'a> {
    /// Name of the signing entity
    pub signer_name: EntityNameTypeChoice<'a>,
    /// Optional URI identifying the signer
    pub signer_uri: Option<Uri<'a>>,
    /// Signer extensions
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Serialize for CorimSignerMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("signer-name", &self.signer_name)?;

            if let Some(signer_uri) = &self.signer_uri {
                map.serialize_entry("signer-uri", signer_uri)?;
            }
        } else {
            map.serialize_entry(&0, &self.signer_name)?;

            if let Some(signer_uri) = &self.signer_uri {
                map.serialize_entry(&1, signer_uri)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for CorimSignerMap<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CorimSignerMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CorimSignerMapVisitor<'a> {
            type Value = CorimSignerMap<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map containing CorimSignerMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut signer_name: Option<EntityNameTypeChoice> = None;
                let mut signer_uri: Option<Uri> = None;
                let mut extensions = ExtensionMap::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("signer-name") => {
                                signer_name = Some(map.next_value::<EntityNameTypeChoice>()?);
                            }
                            Some("signer-uri") => {
                                signer_uri = Some(map.next_value::<Uri>()?);
                            }
                            Some(s) => {
                                let ext_field: i128 = s.parse().map_err(|_| {
                                    de::Error::unknown_field(
                                        s,
                                        &["entity-name", "reg-id", "role", "any integer"],
                                    )
                                })?;
                                extensions
                                    .insert(ext_field.into(), map.next_value::<ExtensionValue>()?);
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                signer_name = Some(map.next_value::<EntityNameTypeChoice>()?);
                            }
                            Some(1) => {
                                signer_uri = Some(map.next_value::<Uri>()?);
                            }
                            Some(n) => {
                                extensions.insert(n.into(), map.next_value::<ExtensionValue>()?);
                            }
                            None => break,
                        }
                    }
                }

                if signer_name.is_none() {
                    return Err(de::Error::missing_field("signer-name"));
                }

                Ok(CorimSignerMap {
                    signer_name: signer_name.unwrap(),
                    signer_uri,
                    extensions: if extensions.is_empty() {
                        None
                    } else {
                        Some(extensions)
                    },
                })
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(CorimSignerMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

/// Type alias for entity names using text strings
#[repr(C)]
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
pub enum EntityNameTypeChoice<'a> {
    Text(Text<'a>),
    Extension(ExtensionValue<'a>),
}

impl EntityNameTypeChoice<'_> {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Extension(ext) => ext.as_str(),
        }
    }
}

impl Default for EntityNameTypeChoice<'_> {
    fn default() -> Self {
        Self::Text("".into())
    }
}

impl<'a> From<&'a str> for EntityNameTypeChoice<'a> {
    fn from(value: &'a str) -> Self {
        EntityNameTypeChoice::Text(value.into())
    }
}

impl<'de> Deserialize<'de> for EntityNameTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            match serde_json::Value::deserialize(deserializer)? {
                serde_json::Value::String(s) => Ok(EntityNameTypeChoice::Text(s.into())),
                value => Ok(EntityNameTypeChoice::Extension(
                    ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                )),
            }
        } else {
            match ciborium::Value::deserialize(deserializer)? {
                ciborium::Value::Text(s) => Ok(EntityNameTypeChoice::Text(s.into())),
                value => Ok(EntityNameTypeChoice::Extension(
                    ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                )),
            }
        }
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(vec)]
mod tests {

    use crate::comid::{ConciseMidTagBuilder, TagIdTypeChoice, TagIdentityMap, TriplesMapBuilder};
    use crate::core::HashAlgorithm;
    use crate::corim::{CorimMetaMap, CorimSignerMap};
    use crate::numbers::Integer;
    use crate::test::SerdeTestCase;
    use crate::triples::{
        EndorsedTripleRecord, EnvironmentMapBuilder, InstanceIdTypeChoice, MeasurementMap,
        MeasurementValuesMapBuilder, SvnTypeChoice,
    };

    use super::*;
    #[test]
    fn test_profile_type_choice() {
        let test_cases = vec![
            SerdeTestCase {
                value: ProfileTypeChoice::Oid(OidType::from(
                    ObjectIdentifier::try_from("1.2.3.4").unwrap(),
                )),
                expected_json: r#"{"type":"oid","value":"1.2.3.4"}"#,
                expected_cbor: vec![
                    0xd8, 0x6f, // tag(111)
                      0x43, // bstr(3)
                        0x2a, 0x03, 0x04
                ],
            },
            SerdeTestCase {
                value: ProfileTypeChoice::Uri(Uri::from("foo")),
                expected_json: r#"{"type":"uri","value":"foo"}"#,
                expected_cbor: vec![
                    0xd8, 0x20, // tag(32)
                      0x63, // tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                ],
            },
            SerdeTestCase {
                value: ProfileTypeChoice::Extension("bar".into()),
                expected_json: r#""bar""#,
                expected_cbor: vec![
                  0x63, // tstr(3)
                    0x62, 0x61, 0x72, // "bar"
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
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
              0xc1, // value: tag(1)
                0x01, // 1
              0x01, // key: 1 [not-after]
              0xc1, // value: tag(1)
                0x02,// 2
            0xff, // break
        ];

        assert_eq!(actual_cbor, expected_cbor);

        let validity_map_de: ValidityMap = ciborium::from_reader(actual_cbor.as_slice()).unwrap();

        assert_eq!(validity_map_de, validity_map);

        let actual_json = serde_json::to_string(&validity_map).unwrap();

        let expected_json =
            r#"{"not-before":{"type":"time","value":1},"not-after":{"type":"time","value":2}}"#;

        assert_eq!(actual_json, expected_json);

        let validity_map_de: ValidityMap = serde_json::from_str(actual_json.as_str()).unwrap();

        assert_eq!(validity_map_de, validity_map);
    }

    #[test]
    fn test_corim_locator_map_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: CorimLocatorMap {
                    href: OneOrMore::One("foo".into()),
                    thumbprint: Some(Digest{
                        alg: HashAlgorithm::Sha256,
                        val: vec![0x01, 0x02, 0x03].into(),
                    }),
                },
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x00, // key: 0 [href]
                      0xd8, 0x20, // value: tag(32) [uri]
                        0x63, // tstr(3)
                          0x66, 0x6f, 0x6f, // "foo"
                      0x01, // key: 1 [thumbprint]
                      0x82, // value: array(2) [digest]
                        0x01, // [0: alg]1 [sha256]
                        0x43,//  [1: val] bstr(3)
                          0x01, 0x02, 0x03,
                    0xff, // break
                ],
                expected_json: r#"{"href":{"type":"uri","value":"foo"},"thumbprint":"sha-256;AQID"}"#,
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_corim_map_serde() {
        let env = EnvironmentMapBuilder::default()
            .instance(InstanceIdTypeChoice::Bytes(
                [0x01, 0x02, 0x03].as_slice().into(),
            ))
            .build()
            .unwrap();

        let mvals = MeasurementValuesMapBuilder::default()
            .svn(SvnTypeChoice::Svn(1.into()))
            .build()
            .unwrap();

        let measurement_map = MeasurementMap {
            mkey: None,
            mval: mvals,
            authorized_by: None,
        };

        let test_cases = vec![
            SerdeTestCase {
                value: CorimMapBuilder::default()
                    .id(CorimIdTypeChoice::Tstr("foo".into()))
                    .add_tag(ConciseTagTypeChoice::Mid(
                        ConciseMidTagBuilder::default()
                            .tag_identity(TagIdentityMap{
                                tag_id: TagIdTypeChoice::Tstr("bar".into()),
                                tag_version: None,
                            })
                            .triples(TriplesMapBuilder::default()
                                .endorsed_triples(vec![
                                    EndorsedTripleRecord{
                                        condition: env.clone(),
                                        endorsement: vec![measurement_map.clone()],
                                    }
                                ])
                                .build()
                                .unwrap()
                            )
                            .build()
                            .unwrap()
                            .into()
                    ))
                    .add_dependent_rim(CorimLocatorMap{
                        href: OneOrMore::One("buzz".into()),
                        thumbprint: None,
                    })
                    .profile(ProfileTypeChoice::Uri("qux".into()))
                    .rim_validity(ValidityMap {
                        not_before: None,
                        not_after: 1.into(),
                    })
                    .add_entity(CorimEntityMapBuilder::default()
                        .entity_name("zot".into())
                        .add_role(CorimRoleTypeChoice::ManifestCreator)
                        .build()
                        .unwrap()
                    )
                    .add_extension(-1, ExtensionValue::Bool(false))
                    .build()
                    .unwrap(),
                expected_cbor: vec![
                    0xbf, // map(indef) [corim-map]
                      0x00, // key: 0 [id]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x01, // key: 1 [tags]
                        0x81, // value: array(1)
                          0xd9, 0x01, 0xfa, // [0]tag(506) [tagged-concise-mid-tag]
                            0x58, 0x22, // bstr(34)
                              0xbf, // map(indef) [concise-mid-tag]
                                0x01, // key: 1 [tag-identity]
                                0xbf, // map(indef) [tag-identity-map]
                                  0x00, // key: 0 [tag-id]
                                  0x63, // value: tstr(3)
                                    0x62, 0x61, 0x72, // "bar"
                                0xff, // break
                                0x04, // key: 4 [triples]
                                0xbf, // value: map(indef) [triples-map]
                                  0x01, // key: 1 [endorsed-triples]
                                  0x81, // value: array(1)
                                    0x82, // [0]value: array(2) [endorsed-triple-record]
                                      0xbf, // [0]value: map(indef) [condition: environment-map]
                                        0x01, // key: 1 [instance]
                                        0xd9, 0x02, 0x30,  // value: tag(560) [tagged-bytes]
                                          0x43, // bstr(3)
                                            0x01, 0x02, 0x03,
                                      0xff, // break
                                      0x81, // [1]array(1) [endorsement]
                                        0xbf, // [0]map(indef) [measurement-map]
                                          0x01, // key: 1 [mval]
                                          0xbf, // value: map(indef) [measurement-values-map]
                                            0x01, // key: 1 [svn]
                                            0x01, // value: 1
                                          0xff, // break
                                        0xff, // break
                                0xff, // break
                              0xff, // break
                      0x02, // key: 2 [dependent-rims]
                        0x81,// value: array(1)
                          0xbf, // [0]map(indef) [corim-locator-map]
                            0x00, // key: 0 [href]
                            0xd8, 0x20, // value: tag(32) [uri]
                              0x64, // tstr(4)
                                0x62, 0x75, 0x7a, 0x7a, // "buzz"
                          0xff, // break
                      0x03, // key: 3 [profile]
                      0xd8, 0x20, // value: tag(32) [uri]
                        0x63, // tstr(3)
                          0x71, 0x75, 0x78, // "qux"
                      0x04, // key: 4 [rim-validity]
                      0xbf, // value: map(indef) [validity-map]
                        0x01, // key: 1 [not-after]
                        0xc1, // value: tag(1)
                          0x01, // 1
                      0xff, // break
                      0x05, // key: 5 [entities]
                      0x81, // value: array(1)
                        0xbf, // [0]map(indef) [corim-entity-map]
                          0x00, // key: 0 [entity-name]
                          0x63, // value: tstr(3)
                            0x7a, 0x6f, 0x74, // "zot"
                          0x02, // key: 2 [role]
                          0x81, // value: array(1)
                            0x01, // [0]1 [manifest-creator]
                        0xff, // break
                      0x20, // key: -1 [extension(-1)]
                      0xf4, //  value: false
                    0xff, //break
                ],
                expected_json: r#"{"id":"foo","tags":[{"type":"comid","value":{"tag-identity":{"tag-id":"bar"},"triples":{"endorsed-triples":[[{"instance":{"type":"bytes","value":"AQID"}},[{"mval":{"svn":1}}]]]}}}],"dependent-rims":[{"href":{"type":"uri","value":"buzz"}}],"profile":{"type":"uri","value":"qux"},"rim-validity":{"not-after":{"type":"time","value":1}},"entities":[{"entity-name":"zot","role":["manifest-creator"]}],"-1":false}"#,
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_entity_name_type_choice_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: EntityNameTypeChoice::Text("foo".into()),
                expected_json: "\"foo\"",
                expected_cbor: vec![
                    0x63, // tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                ],
            },

            SerdeTestCase {
                value: EntityNameTypeChoice::Extension(ExtensionValue::Bool(true)),
                expected_json: "true",
                expected_cbor: vec![
                    0xf5, // true
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_corim_meta_map_serde() {
        let mut extensions = ExtensionMap::default();
        extensions.insert(Integer(-1), ExtensionValue::Bool(true));

        let test_cases = vec![
            SerdeTestCase {
                value: CorimMetaMap {
                    signer: CorimSignerMap {
                        signer_name: "foo".into(),
                        signer_uri: Some("bar".into()),
                        extensions: Some(extensions.clone()),
                    },
                    signature_validity: Some(ValidityMap {
                        not_before: None,
                        not_after: 1.into(),
                    }),
                    extensions: Some(extensions),
                },
                expected_json: r#"{"signer":{"signer-name":"foo","signer-uri":{"type":"uri","value":"bar"},"-1":true},"signature-validity":{"not-after":{"type":"time","value":1}},"-1":true}"#,
                expected_cbor: vec![
                    0xbf, // map(indef) [corim-meta-map]
                      0x00, // key: 0 [signer]
                      0xbf, // value: map(indef) [corim-signer-map]
                        0x00, // key: 0 [signer-name]
                        0x63, // value: tstr(3)
                          0x66, 0x6f, 0x6f, // "foo"
                        0x01, // key: 1 [signer-uri]
                        0xd8, 0x20, // value: tag(32)
                          0x63, // tstr(3)
                            0x62, 0x61, 0x72, // "bar"
                        0x20, // key: -1 [extension(-1)]
                        0xf5, // value: true
                      0xff, // break
                      0x01, // key: 1 [signature-validity]
                      0xbf, // value: map(indef) [validity-map]
                        0x01, // key: 1 [not-after]
                        0xc1, // value: tag(1)
                          0x01, // 1
                      0xff, // break
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: bool
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_signed_deserialize_and_verify() {
        struct FakeSigner {}

        impl CoseKeyOwner for FakeSigner {
            fn to_cose_key(&self) -> CoseKey {
                CoseKey {
                    kty: crate::core::CoseKty::Ec2,
                    kid: None,
                    alg: Some(crate::core::CoseAlgorithm::ES256),
                    key_ops: Some(vec![
                        crate::core::CoseKeyOperation::Sign,
                        crate::core::CoseKeyOperation::Verify,
                    ]),
                    base_iv: None,
                    crv: None,
                    x: None,
                    y: None,
                    d: None,
                    k: None,
                }
            }
        }

        impl CoseSigner for FakeSigner {
            fn sign(&self, _: CoseAlgorithm, _: &[u8]) -> Result<Vec<u8>, CorimError> {
                Ok(vec![0xde, 0xad, 0xbe, 0xef])
            }
        }

        impl CoseVerifier for FakeSigner {
            fn verify_signature(
                &self,
                _: CoseAlgorithm,
                _: &[u8],
                _: &[u8],
            ) -> Result<(), CorimError> {
                Ok(())
            }
        }

        let env = EnvironmentMapBuilder::default()
            .instance(InstanceIdTypeChoice::Bytes(
                [0x01, 0x02, 0x03].as_slice().into(),
            ))
            .build()
            .unwrap();

        let mvals = MeasurementValuesMapBuilder::default()
            .svn(SvnTypeChoice::Svn(1.into()))
            .build()
            .unwrap();

        let measurement_map = MeasurementMap {
            mkey: None,
            mval: mvals,
            authorized_by: None,
        };

        let corim_map = CorimMapBuilder::default()
            .id(CorimIdTypeChoice::Tstr("foo".into()))
            .add_tag(ConciseTagTypeChoice::Mid(
                ConciseMidTagBuilder::default()
                    .tag_identity(TagIdentityMap {
                        tag_id: TagIdTypeChoice::Tstr("bar".into()),
                        tag_version: None,
                    })
                    .triples(
                        TriplesMapBuilder::default()
                            .endorsed_triples(vec![
                                    EndorsedTripleRecord{
                                        condition: env.clone(),
                                        endorsement: vec![measurement_map.clone()],
                                    }
                                ])
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap()
                    .into(),
            ))
            .add_entity(
                CorimEntityMapBuilder::default()
                    .entity_name("zot".into())
                    .add_role(CorimRoleTypeChoice::ManifestCreator)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let meta = CorimMetaMap {
            signer: CorimSignerMap {
                signer_name: "signer name".into(),
                signer_uri: Some("signer_uri".into()),
                extensions: None,
            },
            signature_validity: Some(ValidityMap {
                not_before: None,
                not_after: 99999999999.into(),
            }),
            extensions: None,
        };

        let signer = FakeSigner {};

        let signed: Corim = SignedCorimBuilder::default()
            .alg(CoseAlgorithm::ES256)
            .kid(vec![0x01, 0x02, 0x03])
            .meta(meta)
            .corim_map(corim_map)
            .build_and_sign(signer)
            .unwrap()
            .into();

        let actual = signed.to_cbor().unwrap();

        let expected: Vec<u8> = vec![
            0xd2, // tag(18) [COSE_Sign1_message]
              0x84, // array(4) [COSE_Sign1]
                0x58, 0x4f, // [0]bstr(79) [protected-header]
                  0xa4, // map(4)
                    0x01, // key: 1 [alg]
                    0x26, // value: -7 [ES256]
                    0x03, // key: 3 [content-type]
                    0x74, // value: tstr(20)
                      0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, // "applicat"
                      0x69, 0x6f, 0x6e, 0x2f, 0x72, 0x69, 0x6d, 0x2b, // "ion/rim+"
                      0x63, 0x62, 0x6f, 0x72,                         // "cbor"
                    0x04, // key: 4 [key-id]
                    0x43, // bstr(3)
                      0x01, 0x02, 0x03,
                    0x08, // key: 8 [corim-meta]
                    0x58, 0x2e, // value: bstr(46)
                      0xbf, // map(indef) [corim-meta-map]
                        0x00, // key: 0 [signer]
                        0xbf, // value: map(indef) [corim-signer-map]
                          0x00, // key: 0 [signer-name]
                          0x6b, // value: tstr(10)
                            0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x20, 0x6e, // "signer n"
                            0x61, 0x6d, 0x65,                               // "ame"
                          0x01, // key: 1 [signer-uri]
                          0xd8, 0x20, //  value: tag(32) [uri]
                            0x6a, // tstr(10)
                              0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x5f, 0x75, // "signer u"
                              0x72, 0x69,                                     // "ri"
                        0xff, // break
                        0x01, // key: 1 [signature-validity]
                        0xbf, // value: map(indef) [validity-map]
                          0x01, // key: 1 [not-after]
                          0xc1, // value: tag(1) [time]
                            0x1b,  // int(8)
                              0x00, 0x00, 0x00, 0x17, 0x48, 0x76, 0xe7, 0xff, // 99999999999
                        0xff, // break
                      0xff, // break
                0xa0, // [1]map(0) [unprotected-header]
                0x58, 0x3f, // [2]bstr(63) [payload]
                  0xd9, 0x01, 0xf5, // tag(501) [unsigned-corim]
                    0xbf, // map(indef) [corim-map]
                      0x00, // key: 0 [id]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x01, // key: 1 [tags]
                        0x81, // value: array(1)
                          0xd9, 0x01, 0xfa, // [0]tag(506) [tagged-concise-mid-tag]
                      0x58, 0x22, // bstr(34)
                        0xbf, // map(indef) [concise-mid-tag]
                          0x01, // key: 1 [tag-identity]
                          0xbf, // value: map(indef) [tag-identity-map]
                            0x00, // key: 0 [tag-id]
                            0x63, // value: tstr(3)
                              0x62, 0x61, 0x72, // "bar"
                          0xff, // break
                          0x04, // key: 4 [triples]
                          0xbf, // value: map(indef) [triples-map]
                            0x01, // key: 1 [endorsed-triples]
                            0x81, // value: array(1)
                              0x82, // [0]value: array(2) [endorsed-triple-record]
                                0xbf, // [0]value: map(indef) [condition: environment-map]
                                  0x01, // key: 1 [instance]
                                  0xd9, 0x02, 0x30,  // value: tag(560) [tagged-bytes]
                                    0x43, // bstr(3)
                                      0x01, 0x02, 0x03,
                                0xff, // break
                                0x81, // [1]array(1) [endorsement]
                                  0xbf, // [0]map(indef) [measurement-map]
                                    0x01, // key: 1 [mval]
                                    0xbf, // value: map(indef) [measurement-values-map]
                                      0x01, // key: 1 [svn]
                                      0x01, // value: 1
                                    0xff, // break
                                  0xff, // break
                          0xff, // break
                        0xff, // break
                        0x05, // key: 5 [entities]
                        0x81, // value: array(1)
                          0xbf, // [0]map(indef) [corim-entity-map]
                            0x00, // key: 0 [entity-name]
                            0x63, // value: tstr(3)
                              0x7a, 0x6f, 0x74, // "zot"
                            0x02, // key: 2 [role]
                            0x81, // value: array(1)
                              0x01, // [0]1 [manifest-creator]
                          0xff, // break
                    0xff, // break
                0x44, // [3]bstr(4) [signature]
                  0xde, 0xad, 0xbe, 0xef
        ];

        assert_eq!(actual, expected);

        let tagged_signed = TaggedSignedCorim::from_cbor(actual.as_slice()).unwrap();

        let signed_de = tagged_signed.as_ref();
        let verifier = FakeSigner {};

        assert_eq!(signed_de.alg, crate::core::CoseAlgorithm::ES256);
        assert_eq!(signed_de.kid, vec![0x01, 0x02, 0x03]);
        assert_eq!(signed_de.corim_map.id.as_str().unwrap(), "foo");

        signed_de.verify_signature(verifier).unwrap();
    }

    #[test]
    fn test_display_corim_id_type_choice() {
        let cid: CorimIdTypeChoice = "test".into();
        assert_eq!(cid.to_string(), "test");

        let cid: CorimIdTypeChoice = UuidType::from([
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ])
        .into();
        assert_eq!(cid.to_string(), "550e8400-e29b-41d4-a716-446655440000");

        let cid: CorimIdTypeChoice = ExtensionValue::Bool(true).into();
        assert_eq!(cid.to_string(), "Bool(true)");
    }
}
