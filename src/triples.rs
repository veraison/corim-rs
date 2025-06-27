// SPDX-License-Identifier: MIT

//! Module for handling triple records used in CoMID tags.
//!
//! Triple records are used to express relationships between environments, measurements,
//! and various security properties. This module implements the different types of triples
//! defined in the CoRIM specification.
//!
//! # Triple Record Types
//!
//! - Reference triples ([`ReferenceTripleRecord`]): Link environments to measurements
//! - Identity triples ([`IdentityTripleRecord`]): Associate keys with environments
//! - Endorsement triples ([`EndorsedTripleRecord`]): Express verification requirements
//! - Attestation key triples ([`AttestKeyTripleRecord`]): Define keys for attestation
//! - Domain dependency triples ([`DomainDependencyTripleRecord`]): Express domain relationships
//! - Domain membership triples ([`DomainMembershipTripleRecord`]): Define domain membership
//! - CoSWID triples ([`CoswidTripleRecord`]): Link to software identification tags
//! - Conditional endorsement triples ([`ConditionalEndorsementTripleRecord`]): Complex verification
//!
//! # Key Types
//!
//! The module supports various cryptographic key and certificate formats through [`CryptoKeyTypeChoice`]:
//! - PKIX certificates (base64 encoded)
//! - PKIX certificate paths
//! - COSE keys
//! - Cryptographic thumbprints
//! - ASN.1 DER encoded certificates
//!
//! # Networking Support
//!
//! Network identification is handled through:
//! - [`MacAddrTypeChoice`]: Supports both EUI-48 and EUI-64 MAC addresses
//! - [`IpAddrTypeChoice`]: Supports both IPv4 and IPv6 addresses
//!
//! # Measurement Values
//!
//! The [`MeasurementValuesMap`] structure contains comprehensive measurement data including:
//! - Version information
//! - Security version numbers (SVN)
//! - Cryptographic digests
//! - Security state flags
//! - Network addressing
//! - Serial numbers
//! - UUIDs and UEIDs
//! - Cryptographic keys
//! - Integrity register values
//!
//! # Status Flags
//!
//! The [`FlagsMap`] structure provides detailed security and configuration state including:
//! - Configuration state
//! - Security state
//! - Recovery mode
//! - Debug status
//! - Replay protection
//! - Integrity protection
//! - Runtime measurement status
//! - Immutability
//! - TCB inclusion
//! - Confidentiality protection
//!
//! # Example Usage
//!
//! ```rust
//! use corim_rs::triples::{ReferenceTripleRecord, EnvironmentMap, MeasurementMap};
//!
//! // Create a reference triple
//! let triple = ReferenceTripleRecord {
//!     ref_env: EnvironmentMap {
//!         class: None,
//!         instance: None,
//!         group: None,
//!     },
//!     ref_claims: vec![
//!         MeasurementMap {
//!             mkey: None,
//!             mval: Default::default(),
//!             authorized_by: None,
//!         }
//!     ].into(),
//! };
//! ```
//!
//! # Conditional Endorsements
//!
//! The module supports complex conditional endorsement scenarios through:
//! - [`ConditionalEndorsementTripleRecord`]: For single condition endorsements
//! - [`ConditionalEndorsementSeriesTripleRecord`]: For series-based conditional changes
//! - [`StatefulEnvironmentRecord`]: For tracking environment state
//! - [`ConditionalSeriesRecord`]: For defining measurement changes

use std::{
    collections::{btree_map::Iter, BTreeMap},
    fmt::Display,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut, Index},
};

use crate::{
    core::{
        ExtensionValue, PkixBase64CertPathType, RawValueMaskType, RawValueTypeChoice,
        TaggedJsonValue,
    },
    empty::Empty as _,
    Bytes, CertPathThumbprintType, CertThumbprintType, ConciseSwidTagId, CoseKeySetOrKey,
    CoseKeyType, Digest, ExtensionMap, Integer, MinSvnType, ObjectIdentifier, OidType,
    PkixAsn1DerCertType, PkixBase64CertType, PkixBase64KeyType, RawValueType, Result, SvnType,
    TaggedBytes, TaggedUeidType, TaggedUuidType, Text, ThumbprintType, TriplesError, Tstr,
    UeidType, Uint, Ulabel, UuidType, VersionScheme,
};
use derive_more::{Constructor, From, TryFrom};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::{self, SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A reference triple record containing environment and measurement claims
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ReferenceTripleRecord<'a> {
    /// The environment being referenced
    pub ref_env: EnvironmentMap<'a>,
    /// One or more measurement claims about the environment
    pub ref_claims: Vec<MeasurementMap<'a>>,
}

impl Serialize for ReferenceTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.ref_env)?;
        seq.serialize_element(&self.ref_claims)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ReferenceTripleRecord<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReferenceTripleRecordVisitor<'a>(std::marker::PhantomData<&'a ()>);

        impl<'de, 'a> serde::de::Visitor<'de> for ReferenceTripleRecordVisitor<'a> {
            type Value = ReferenceTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a reference triple record")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let ref_env = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let ref_claims = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ReferenceTripleRecord {
                    ref_env,
                    ref_claims,
                })
            }
        }

        deserializer.deserialize_seq(ReferenceTripleRecordVisitor(std::marker::PhantomData))
    }
}
/// Map describing an environment's characteristics
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct EnvironmentMap<'a> {
    /// Optional classification information
    pub class: Option<ClassMap<'a>>,
    /// Optional instance identifier
    pub instance: Option<InstanceIdTypeChoice<'a>>,
    /// Optional group identifier
    pub group: Option<GroupIdTypeChoice>,
}

impl Serialize for EnvironmentMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(class) = &self.class {
                map.serialize_entry("class", class)?;
            }
            if let Some(instance) = &self.instance {
                map.serialize_entry("instance", instance)?;
            }
            if let Some(group) = &self.group {
                map.serialize_entry("group", group)?;
            }
        } else {
            if let Some(class) = &self.class {
                map.serialize_entry(&0, class)?;
            }
            if let Some(instance) = &self.instance {
                map.serialize_entry(&1, instance)?;
            }
            if let Some(group) = &self.group {
                map.serialize_entry(&2, group)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for EnvironmentMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EnvironmentMapVisitor<'a> {
            pub is_human_readable: bool,
            data: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for EnvironmentMapVisitor<'a> {
            type Value = EnvironmentMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map contianing EnvironmentMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut builder = EnvironmentMapBuilder::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("class") => {
                                builder = builder.class(map.next_value::<ClassMap<'a>>()?);
                            }
                            Some("instance") => {
                                builder =
                                    builder.instance(map.next_value::<InstanceIdTypeChoice<'a>>()?);
                            }
                            Some("group") => {
                                builder = builder.group(map.next_value::<GroupIdTypeChoice>()?);
                            }
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected EnvironmentMap field \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                builder = builder.class(map.next_value::<ClassMap<'a>>()?);
                            }
                            Some(1) => {
                                builder =
                                    builder.instance(map.next_value::<InstanceIdTypeChoice<'a>>()?);
                            }
                            Some(2) => {
                                builder = builder.group(map.next_value::<GroupIdTypeChoice>()?);
                            }
                            Some(key) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected EnvironmentMap field {key}"
                                )))
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(EnvironmentMapVisitor {
            is_human_readable: is_hr,
            data: PhantomData {},
        })
    }
}

#[derive(Default)]
pub struct EnvironmentMapBuilder<'a> {
    /// Optional classification information
    pub class: Option<ClassMap<'a>>,
    /// Optional instance identifier
    pub instance: Option<InstanceIdTypeChoice<'a>>,
    /// Optional group identifier
    pub group: Option<GroupIdTypeChoice>,
}

impl<'a> EnvironmentMapBuilder<'a> {
    pub fn class(mut self, values: ClassMap<'a>) -> Self {
        self.class = Some(values);
        self
    }

    pub fn instance(mut self, instance: InstanceIdTypeChoice<'a>) -> Self {
        self.instance = Some(instance);
        self
    }

    pub fn group(mut self, group: GroupIdTypeChoice) -> Self {
        self.group = Some(group);
        self
    }

    pub fn build(self) -> Result<EnvironmentMap<'a>> {
        if self.class.is_none() && self.instance.is_none() && self.group.is_none() {
            return Err(TriplesError::EmptyEnvironmentMap)?;
        }
        Ok(EnvironmentMap {
            class: self.class,
            instance: self.instance,
            group: self.group,
        })
    }
}
/// Classification information for an environment. It is **HIGHLY** recommend to use ClassMapBuilder to ensure the CDDL enforcement of
/// at least one field being present.
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ClassMap<'a> {
    /// Optional class identifier
    pub class_id: Option<ClassIdTypeChoice<'a>>,
    /// Optional vendor name
    pub vendor: Option<Tstr<'a>>,
    /// Optional model identifier
    pub model: Option<Tstr<'a>>,
    /// Optional layer number
    pub layer: Option<Uint>,
    /// Optional index number
    pub index: Option<Uint>,
}

impl Serialize for ClassMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(class_id) = &self.class_id {
                map.serialize_entry("class-id", class_id)?;
            }
            if let Some(vendor) = &self.vendor {
                map.serialize_entry("vendor", vendor)?;
            }
            if let Some(model) = &self.model {
                map.serialize_entry("model", model)?;
            }
            if let Some(layer) = &self.layer {
                map.serialize_entry("layer", layer)?;
            }
            if let Some(index) = &self.index {
                map.serialize_entry("index", index)?;
            }
        } else {
            if let Some(class_id) = &self.class_id {
                map.serialize_entry(&0, class_id)?;
            }
            if let Some(vendor) = &self.vendor {
                map.serialize_entry(&1, vendor)?;
            }
            if let Some(model) = &self.model {
                map.serialize_entry(&2, model)?;
            }
            if let Some(layer) = &self.layer {
                map.serialize_entry(&3, layer)?;
            }
            if let Some(index) = &self.index {
                map.serialize_entry(&4, index)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ClassMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClassMapVisitor<'a> {
            pub is_human_readable: bool,
            data: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for ClassMapVisitor<'a> {
            type Value = ClassMap<'a>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map contianing ClassMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut class_map = ClassMap::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("class-id") => {
                                class_map.class_id = Some(map.next_value::<ClassIdTypeChoice>()?);
                            }
                            Some("vendor") => {
                                class_map.vendor = Some(map.next_value::<Tstr>()?);
                            }
                            Some("model") => {
                                class_map.model = Some(map.next_value::<Tstr>()?);
                            }
                            Some("layer") => {
                                class_map.layer = Some(map.next_value::<Uint>()?);
                            }
                            Some("index") => {
                                class_map.index = Some(map.next_value::<Uint>()?);
                            }
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field name \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                class_map.class_id = Some(map.next_value::<ClassIdTypeChoice>()?);
                            }
                            Some(1) => {
                                class_map.vendor = Some(map.next_value::<Tstr>()?);
                            }
                            Some(2) => {
                                class_map.model = Some(map.next_value::<Tstr>()?);
                            }
                            Some(3) => {
                                class_map.layer = Some(map.next_value::<Uint>()?);
                            }
                            Some(4) => {
                                class_map.index = Some(map.next_value::<Uint>()?);
                            }
                            Some(key) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field key \"{key}\""
                                )))
                            }
                            None => break,
                        }
                    }
                }

                Ok(class_map)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(ClassMapVisitor {
            is_human_readable: is_hr,
            data: PhantomData {},
        })
    }
}

#[derive(Default)]
pub struct ClassMapBuilder<'a> {
    /// Optional class identifier
    pub class_id: Option<ClassIdTypeChoice<'a>>,
    /// Optional vendor name
    pub vendor: Option<Tstr<'a>>,
    /// Optional model identifier
    pub model: Option<Tstr<'a>>,
    /// Optional layer number
    pub layer: Option<Uint>,
    /// Optional index number
    pub index: Option<Uint>,
}

impl<'a> ClassMapBuilder<'a> {
    pub fn class_id(mut self, value: ClassIdTypeChoice<'a>) -> Self {
        self.class_id = Some(value);
        self
    }

    pub fn vendor(mut self, value: Tstr<'a>) -> Self {
        self.vendor = Some(value);
        self
    }

    pub fn model(mut self, value: Tstr<'a>) -> Self {
        self.model = Some(value);
        self
    }

    pub fn layer(mut self, value: Uint) -> Self {
        self.layer = Some(value);
        self
    }

    pub fn index(mut self, value: Uint) -> Self {
        self.index = Some(value);
        self
    }

    pub fn build(self) -> Result<ClassMap<'a>> {
        if self.class_id.is_none()
            && self.vendor.is_none()
            && self.model.is_none()
            && self.layer.is_none()
            && self.index.is_none()
        {
            return Err(TriplesError::EmptyClassMap)?;
        }
        Ok(ClassMap {
            class_id: self.class_id,
            vendor: self.vendor,
            model: self.model,
            layer: self.layer,
            index: self.index,
        })
    }
}

/// Possible types for class identifiers
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum ClassIdTypeChoice<'a> {
    /// Object Identifier (OID)
    Oid(OidType),
    /// UUID identifier
    Uuid(TaggedUuidType),
    /// Raw bytes
    Bytes(TaggedBytes),
    /// Extensions
    Extension(ExtensionValue<'a>),
}

impl ClassIdTypeChoice<'_> {
    /// Returns a byte slice reference to the underlying data regardless of variant type
    ///
    /// This method provides uniform access to the internal bytes of a ClassIdTypeChoice,
    /// normalizing access across the different variant types.
    ///
    /// # Returns
    ///
    /// A slice of bytes (`&[u8]`) representing the raw data of the identifier
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::triples::ClassIdTypeChoice;
    /// use corim_rs::Bytes;
    ///
    /// let id = ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]));
    /// let bytes = id.as_bytes().unwrap();
    /// assert_eq!(bytes, &[1, 2, 3, 4]);
    /// ```
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Oid(oid_type) => Some(oid_type.as_ref()),
            Self::Uuid(uuid_type) => Some(uuid_type.as_ref().as_ref()),
            Self::Bytes(bytes) => Some(bytes.as_ref()),
            Self::Extension(ext) => ext.as_bytes(),
        }
    }

    /// Returns the byte representation if this is an OID variant, or None otherwise
    ///
    /// This method is useful when you specifically need to work with OID data
    /// and want to verify the variant type before accessing.
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` containing the OID bytes if this is an OID variant
    /// - `None` if this is any other variant
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::triples::ClassIdTypeChoice;
    /// use corim_rs::{OidType, Bytes};
    ///
    /// // An OID variant
    /// let oid_id = ClassIdTypeChoice::Oid(OidType::from(vec![1, 2, 840, 113741, 1, 2]));
    /// assert!(oid_id.as_oid_bytes().is_some());
    ///
    /// // Not an OID variant
    /// let bytes_id = ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]));
    /// assert!(bytes_id.as_oid_bytes().is_none());
    /// ```
    pub fn as_oid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Oid(_) => Self::as_bytes(self),
            _ => None,
        }
    }

    /// Returns the byte representation if this is a UUID variant, or None otherwise
    ///
    /// This method is useful when you specifically need to work with UUID data
    /// and want to verify the variant type before accessing.
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` containing the UUID bytes if this is a UUID variant
    /// - `None` if this is any other variant
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::triples::ClassIdTypeChoice;
    /// use corim_rs::{UuidType, FixedBytes, Bytes};
    ///
    /// // A UUID variant
    /// let uuid_bytes = [0; 16];
    /// let uuid_id = ClassIdTypeChoice::Uuid(UuidType(FixedBytes::from(uuid_bytes)));
    /// assert!(uuid_id.as_uuid_bytes().is_some());
    ///
    /// // Not a UUID variant
    /// let bytes_id = ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]));
    /// assert!(bytes_id.as_uuid_bytes().is_none());
    /// ```
    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(_) => Self::as_bytes(self),
            _ => None,
        }
    }

    /// Returns the byte representation if this is a raw Bytes variant, or None otherwise
    ///
    /// This method is useful when you specifically need to work with raw byte data
    /// and want to verify the variant type before accessing.
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` containing the raw bytes if this is a Bytes variant
    /// - `None` if this is any other variant
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::triples::ClassIdTypeChoice;
    /// use corim_rs::{OidType, Bytes};
    ///
    /// // A Bytes variant
    /// let bytes_id = ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]));
    /// assert!(bytes_id.as_raw_bytes().is_some());
    ///
    /// // Not a Bytes variant
    /// let oid_id = ClassIdTypeChoice::Oid(OidType::from(vec![1, 2, 840, 113741, 1, 2]));
    /// assert!(oid_id.as_raw_bytes().is_none());
    /// ```
    pub fn as_raw_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(_) => Self::as_bytes(self),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for ClassIdTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
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
                                "oid" => Ok(ClassIdTypeChoice::Oid(OidType::from(
                                    ObjectIdentifier::try_from(value.as_str())
                                        .map_err(|_| de::Error::custom("invalid OID bytes"))?,
                                ))),
                                "uuid" => Ok(ClassIdTypeChoice::Uuid(TaggedUuidType::from(
                                    UuidType::try_from(value.as_str())
                                        .map_err(|_| de::Error::custom("invalid UUID bytes"))?,
                                ))),
                                "bytes" => Ok(ClassIdTypeChoice::Bytes(TaggedBytes::from(
                                    Bytes::try_from(value.as_str())
                                        .map_err(|_| de::Error::custom("invalid UUID bytes"))?,
                                ))),
                                s => Err(de::Error::custom(format!(
                                    "unexpected type {s} for ClassIdTypeChoice"
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
                                Some(u) => Ok(ClassIdTypeChoice::Extension(ExtensionValue::Tag(
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
                        Ok(ClassIdTypeChoice::Extension(
                            ExtensionValue::try_from(serde_json::Value::Object(map))
                                .map_err(de::Error::custom)?,
                        ))
                    }
                }
                value => Ok(ClassIdTypeChoice::Extension(
                    ExtensionValue::try_from(value).map_err(de::Error::custom)?,
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
                            Ok(ClassIdTypeChoice::Oid(OidType::from(oid)))
                        }
                        37 => {
                            let uuid: UuidType =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(ClassIdTypeChoice::Uuid(TaggedUuidType::from(uuid)))
                        }
                        560 => {
                            let bytes: Bytes =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(ClassIdTypeChoice::Bytes(TaggedBytes::from(bytes)))
                        }
                        n => Ok(ClassIdTypeChoice::Extension(ExtensionValue::Tag(
                            n,
                            Box::new(
                                ExtensionValue::try_from(inner.deref().to_owned())
                                    .map_err(de::Error::custom)?,
                            ),
                        ))),
                    }
                }
                value => Ok(ClassIdTypeChoice::Extension(
                    ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                )),
            }
        }
    }
}

/// Possible types for instance identifiers
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum InstanceIdTypeChoice<'a> {
    /// Unique Entity Identifier
    Ueid(TaggedUeidType),
    /// UUID identifier
    Uuid(TaggedUuidType),
    /// Cryptographic key identifier
    CryptoKey(CryptoKeyTypeChoice<'a>),
    /// Raw bytes
    Bytes(TaggedBytes),
}

impl InstanceIdTypeChoice<'_> {
    pub fn as_ueid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ueid(ueid) => Some(ueid.as_ref()),
            _ => None,
        }
    }

    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(uuid) => Some(uuid.as_ref().as_slice()),
            _ => None,
        }
    }

    pub fn as_crypto_key(&self) -> Option<CryptoKeyTypeChoice> {
        match self {
            Self::CryptoKey(key) => Some(key.clone()),
            _ => None,
        }
    }

    pub fn as_ref_crypto_key(&self) -> Option<&CryptoKeyTypeChoice> {
        match self {
            Self::CryptoKey(key) => Some(key),
            _ => None,
        }
    }

    pub fn as_raw_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes.as_ref()),
            _ => None,
        }
    }
}

impl<'a> From<&'a [u8]> for InstanceIdTypeChoice<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Bytes(TaggedBytes::from(Bytes::from(value)))
    }
}

impl<'de> Deserialize<'de> for InstanceIdTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            let tagged_value = TaggedJsonValue::deserialize(deserializer)?;

            match tagged_value.typ {
                "pkix-base64-key" => {
                    let tstr: Tstr = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::CryptoKey(
                        CryptoKeyTypeChoice::PkixBase64Key(PkixBase64KeyType::from(tstr)),
                    ))
                }
                "pkix-base64-cert" => {
                    let tstr: Tstr = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::CryptoKey(
                        CryptoKeyTypeChoice::PkixBase64Cert(PkixBase64CertType::from(tstr)),
                    ))
                }
                "pkix-base64-cert-path" => {
                    let tstr: Tstr = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::CryptoKey(
                        CryptoKeyTypeChoice::PkixBase64CertPath(PkixBase64CertPathType::from(tstr)),
                    ))
                }
                "cose-key" => {
                    let sok: CoseKeySetOrKey = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::CryptoKey(
                        CryptoKeyTypeChoice::CoseKey(CoseKeyType::from(sok)),
                    ))
                }
                "thumbprint" => {
                    let digest: Digest = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::CryptoKey(
                        CryptoKeyTypeChoice::Thumbprint(ThumbprintType::from(digest)),
                    ))
                }
                "cert-thumbprint" => {
                    let digest: Digest = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::CryptoKey(
                        CryptoKeyTypeChoice::CertThumbprint(CertThumbprintType::from(digest)),
                    ))
                }
                "cert-path-thumbprint" => {
                    let digest: Digest = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::CryptoKey(
                        CryptoKeyTypeChoice::CertPathThumbprint(CertPathThumbprintType::from(
                            digest,
                        )),
                    ))
                }
                "pkix-asn1-der-cert" => {
                    let bytes: Bytes = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::CryptoKey(
                        CryptoKeyTypeChoice::PkixAsn1DerCert(PkixAsn1DerCertType::from(bytes)),
                    ))
                }
                "bytes" => {
                    let bytes: Bytes = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    // TODO(setrofim): both instance-id-type-choice and crypto-key-type-choice
                    // specify tagged-bytes as a variant. It is not possible to distinguish between
                    // them (see https://github.com/ietf-rats-wg/draft-ietf-rats-corim/issues/428),
                    // so we have to make a choice whether we treat tagged-bytes as an instance ID
                    // or as a crypto key (that is an instance ID); both interpretations would be
                    // valid according to the spec (until the above issue is fixed in some way).
                    // Here, we're choosing to treat it as a generic ID, on the assumption that
                    // this is more likely to be the intent.
                    Ok(InstanceIdTypeChoice::Bytes(TaggedBytes::from(bytes)))
                }
                "uuid" => {
                    let uuid: UuidType = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::Uuid(TaggedUuidType::from(uuid)))
                }
                "ueid" => {
                    let ueid: UeidType = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(InstanceIdTypeChoice::Ueid(TaggedUeidType::from(ueid)))
                }
                s => Err(de::Error::custom(format!(
                    "unexpected InstanceIdTypeChoice type \"{s}\""
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
                        554 => {
                            let tstr: Tstr =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::CryptoKey(
                                CryptoKeyTypeChoice::PkixBase64Key(PkixBase64KeyType::from(tstr)),
                            ))
                        }
                        555 => {
                            let tstr: Tstr =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::CryptoKey(
                                CryptoKeyTypeChoice::PkixBase64Cert(PkixBase64CertType::from(tstr)),
                            ))
                        }
                        556 => {
                            let tstr: Tstr =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::CryptoKey(
                                CryptoKeyTypeChoice::PkixBase64CertPath(
                                    PkixBase64CertPathType::from(tstr),
                                ),
                            ))
                        }
                        558 => {
                            let sok: CoseKeySetOrKey =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::CryptoKey(
                                CryptoKeyTypeChoice::CoseKey(CoseKeyType::from(sok)),
                            ))
                        }
                        557 => {
                            let digest: Digest =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::CryptoKey(
                                CryptoKeyTypeChoice::Thumbprint(ThumbprintType::from(digest)),
                            ))
                        }
                        559 => {
                            let digest: Digest =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::CryptoKey(
                                CryptoKeyTypeChoice::CertThumbprint(CertThumbprintType::from(
                                    digest,
                                )),
                            ))
                        }
                        561 => {
                            let digest: Digest =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::CryptoKey(
                                CryptoKeyTypeChoice::CertPathThumbprint(
                                    CertPathThumbprintType::from(digest),
                                ),
                            ))
                        }
                        562 => {
                            let bytes: Bytes =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::CryptoKey(
                                CryptoKeyTypeChoice::PkixAsn1DerCert(PkixAsn1DerCertType::from(
                                    bytes,
                                )),
                            ))
                        }
                        560 => {
                            let bytes: Bytes =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            // TODO(setrofim): both instance-id-type-choice and crypto-key-type-choice
                            // specify tagged-bytes as a variant. It is not possible to distinguish between
                            // them (see https://github.com/ietf-rats-wg/draft-ietf-rats-corim/issues/428),
                            // so we have to make a choice whether we treat tagged-bytes as an instance ID
                            // or as a crypto key (that is an instance ID); both interpretations would be
                            // valid according to the spec (until the above issue is fixed in some way).
                            // Here, we're choosing to treat it as a generic ID, on the assumption that
                            // this is more likely to be the intent.
                            Ok(InstanceIdTypeChoice::Bytes(TaggedBytes::from(bytes)))
                        }
                        37 => {
                            let uuid: UuidType =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::Uuid(TaggedUuidType::from(uuid)))
                        }
                        550 => {
                            let ueid: UeidType =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(InstanceIdTypeChoice::Ueid(TaggedUeidType::from(ueid)))
                        }
                        n => Err(de::Error::custom(format!(
                            "unexpected InstanceIdTypeChoice tag {n}"
                        ))),
                    }
                }
                _ => Err(de::Error::custom("did not see a tag")),
            }
        }
    }
}

/// Types of cryptographic keys and certificates
///
/// This enum supports all key and certificate formats defined in the CoRIM specification:
///
/// - PKIX formats use base64 encoding for certificates and keys
/// - COSE keys follow the COSE_Key structure from RFC 8152
/// - Thumbprints provide cryptographic hashes of keys/certificates
/// - ASN.1 DER supports raw certificate encoding
///
/// # Variants
///
/// * `PkixBase64Key` - Base64-encoded PKIX key
/// * `PkixBase64Cert` - Base64-encoded PKIX certificate
/// * `PkixBase64CertPath` - Base64-encoded PKIX certificate path
/// * `CoseKey` - COSE key structure (RFC 8152)
/// * `Thumbprint` - Generic cryptographic thumbprint
/// * `CertThumbprint` - Certificate thumbprint
/// * `CertPathThumbprint` - Certificate path thumbprint  
/// * `PkixAsn1DerCert` - ASN.1 DER encoded PKIX certificate
/// * `Bytes` - Raw bytes
///
/// # Example
///
/// # Example
///
/// ```rust
/// use corim_rs::triples::CryptoKeyTypeChoice;
/// use corim_rs::numbers::Integer;
/// use corim_rs::core::{Bytes, PkixBase64CertType, CoseKeyType, CoseKeySetOrKey, CoseKeyBuilder, CoseKty, CoseAlgorithm, CoseKeyOperation, CoseEllipticCurve, TaggedBytes};
///
/// // Base64 encoded certificate
/// let cert = CryptoKeyTypeChoice::PkixBase64Cert(
///     PkixBase64CertType::new("MIIBIjANBgkq...".into())
/// );
///
/// // COSE key structure
/// let cose = CryptoKeyTypeChoice::CoseKey(
///     CoseKeyType::new(CoseKeySetOrKey::Key(CoseKeyBuilder::new()
///         .kty(CoseKty::Ec2)  // EC2 key type
///         .kid(Bytes::from(vec![1, 2, 3]))  // Key ID
///         .alg(CoseAlgorithm::ES256)  // ES256 algorithm
///         .key_ops(vec![
///             CoseKeyOperation::Sign,  // sign
///             CoseKeyOperation::Verify,  // verify
///         ].into())
///         .base_iv(Bytes::new(vec![4, 5, 6]))  // Initialization vector
///         .crv(CoseEllipticCurve::P256)
///         .x(Bytes::from(vec![7, 8, 9]))
///         .y(Bytes::from(vec![10, 11, 12]))
///         .d(Bytes::from(vec![13, 14, 15]))
///         .build().unwrap()
///     ))
/// );
///
/// // Raw key bytes
/// let raw = CryptoKeyTypeChoice::Bytes(
///     TaggedBytes::from(Bytes::from(vec![0x01, 0x02, 0x03]))
/// );
/// ```
///
/// Each variant provides appropriate constructors and implements common traits
/// like `From`, `TryFrom`, `Serialize`, and `Deserialize`.
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum CryptoKeyTypeChoice<'a> {
    /// Base64-encoded PKIX key
    PkixBase64Key(PkixBase64KeyType<'a>),
    /// Base64-encoded PKIX certificate
    PkixBase64Cert(PkixBase64CertType<'a>),
    /// Base64-encoded PKIX certificate path
    PkixBase64CertPath(PkixBase64CertPathType<'a>),
    /// COSE key structure
    CoseKey(CoseKeyType),
    /// Generic cryptographic thumbprint
    Thumbprint(ThumbprintType),
    /// Certificate thumbprint
    CertThumbprint(CertThumbprintType),
    /// Certificate path thumbprint
    CertPathThumbprint(CertPathThumbprintType),
    /// ASN.1 DER encoded PKIX certificate
    PkixAsn1DerCert(PkixAsn1DerCertType),
    /// Raw bytes
    Bytes(TaggedBytes),
}

impl CryptoKeyTypeChoice<'_> {
    pub fn as_pkix_key(&self) -> Option<PkixBase64KeyType> {
        match self {
            Self::PkixBase64Key(key) => Some(key.clone()),
            _ => None,
        }
    }

    pub fn as_ref_pkix_key(&self) -> Option<&PkixBase64KeyType> {
        match self {
            Self::PkixBase64Key(key) => Some(key),
            _ => None,
        }
    }

    pub fn as_pkix_cert(&self) -> Option<PkixBase64CertType> {
        match self {
            Self::PkixBase64Cert(cert) => Some(cert.clone()),
            _ => None,
        }
    }

    pub fn as_ref_pkix_cert(&self) -> Option<&PkixBase64CertType> {
        match self {
            Self::PkixBase64Cert(cert) => Some(cert),
            _ => None,
        }
    }

    pub fn as_pkix_cert_path(&self) -> Option<PkixBase64CertPathType> {
        match self {
            Self::PkixBase64CertPath(cert_path) => Some(cert_path.clone()),
            _ => None,
        }
    }

    pub fn as_ref_pkix_cert_path(&self) -> Option<&PkixBase64CertPathType> {
        match self {
            Self::PkixBase64CertPath(cert_path) => Some(cert_path),
            _ => None,
        }
    }

    pub fn as_cose_key(&self) -> Option<CoseKeyType> {
        match self {
            Self::CoseKey(key) => Some(key.clone()),
            _ => None,
        }
    }

    pub fn as_ref_cose_key(&self) -> Option<&CoseKeyType> {
        match self {
            Self::CoseKey(key) => Some(key),
            _ => None,
        }
    }

    pub fn as_thumbprint(&self) -> Option<ThumbprintType> {
        match self {
            Self::Thumbprint(thumbprint) => Some(thumbprint.clone()),
            _ => None,
        }
    }

    pub fn as_ref_thumbprint(&self) -> Option<&ThumbprintType> {
        match self {
            Self::Thumbprint(thumbprint) => Some(thumbprint),
            _ => None,
        }
    }

    pub fn as_cert_thumbprint(&self) -> Option<CertThumbprintType> {
        match self {
            Self::CertThumbprint(thumbprint) => Some(thumbprint.clone()),
            _ => None,
        }
    }

    pub fn as_ref_cert_thumbprint(&self) -> Option<&CertThumbprintType> {
        match self {
            Self::CertThumbprint(thumbprint) => Some(thumbprint),
            _ => None,
        }
    }

    pub fn as_cert_path_thumbprint(&self) -> Option<CertPathThumbprintType> {
        match self {
            Self::CertPathThumbprint(thumbprint) => Some(thumbprint.clone()),
            _ => None,
        }
    }

    pub fn as_ref_cert_path_thumbprint(&self) -> Option<&CertPathThumbprintType> {
        match self {
            Self::CertPathThumbprint(thumbprint) => Some(thumbprint),
            _ => None,
        }
    }

    pub fn as_pkix_asn1_der_cert(&self) -> Option<PkixAsn1DerCertType> {
        match self {
            Self::PkixAsn1DerCert(cert) => Some(cert.clone()),
            _ => None,
        }
    }

    pub fn as_ref_pkix_asn1_der_cert(&self) -> Option<&PkixAsn1DerCertType> {
        match self {
            Self::PkixAsn1DerCert(cert) => Some(cert),
            _ => None,
        }
    }

    pub fn as_raw_bytes(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes.as_ref(),
            _ => &[],
        }
    }
}

impl<'de> Deserialize<'de> for CryptoKeyTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            let tagged_value = TaggedJsonValue::deserialize(deserializer)?;

            match tagged_value.typ {
                "pkix-base64-key" => {
                    let tstr: Tstr = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::PkixBase64Key(PkixBase64KeyType::from(
                        tstr,
                    )))
                }
                "pkix-base64-cert" => {
                    let tstr: Tstr = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::PkixBase64Cert(
                        PkixBase64CertType::from(tstr),
                    ))
                }
                "pkix-base64-cert-path" => {
                    let tstr: Tstr = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::PkixBase64CertPath(
                        PkixBase64CertPathType::from(tstr),
                    ))
                }
                "cose-key" => {
                    let sok: CoseKeySetOrKey = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::CoseKey(CoseKeyType::from(sok)))
                }
                "thumbprint" => {
                    let digest: Digest = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::Thumbprint(ThumbprintType::from(
                        digest,
                    )))
                }
                "cert-thumbprint" => {
                    let digest: Digest = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::CertThumbprint(
                        CertThumbprintType::from(digest),
                    ))
                }
                "cert-path-thumbprint" => {
                    let digest: Digest = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::CertPathThumbprint(
                        CertPathThumbprintType::from(digest),
                    ))
                }
                "pkix-asn1-der-cert" => {
                    let bytes: Bytes = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::PkixAsn1DerCert(
                        PkixAsn1DerCertType::from(bytes),
                    ))
                }
                "bytes" => {
                    let bytes: Bytes = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(CryptoKeyTypeChoice::Bytes(TaggedBytes::from(bytes)))
                }
                s => Err(de::Error::custom(format!(
                    "unexpected CryptoKeyTypeChoice type \"{s}\""
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
                        554 => {
                            let tstr: Tstr =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::PkixBase64Key(PkixBase64KeyType::from(
                                tstr,
                            )))
                        }
                        555 => {
                            let tstr: Tstr =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::PkixBase64Cert(
                                PkixBase64CertType::from(tstr),
                            ))
                        }
                        556 => {
                            let tstr: Tstr =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::PkixBase64CertPath(
                                PkixBase64CertPathType::from(tstr),
                            ))
                        }
                        558 => {
                            let sok: CoseKeySetOrKey =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::CoseKey(CoseKeyType::from(sok)))
                        }
                        557 => {
                            let digest: Digest =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::Thumbprint(ThumbprintType::from(
                                digest,
                            )))
                        }
                        559 => {
                            let digest: Digest =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::CertThumbprint(
                                CertThumbprintType::from(digest),
                            ))
                        }
                        561 => {
                            let digest: Digest =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::CertPathThumbprint(
                                CertPathThumbprintType::from(digest),
                            ))
                        }
                        562 => {
                            let bytes: Bytes =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::PkixAsn1DerCert(
                                PkixAsn1DerCertType::from(bytes),
                            ))
                        }
                        560 => {
                            let bytes: Bytes =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(CryptoKeyTypeChoice::Bytes(TaggedBytes::from(bytes)))
                        }
                        n => Err(de::Error::custom(format!(
                            "unexpected ClassIdTypeChoice tag {n}"
                        ))),
                    }
                }
                _ => Err(de::Error::custom("did not see a tag")),
            }
        }
    }
}

/// Types of group identifiers
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum GroupIdTypeChoice {
    /// UUID identifier
    Uuid(TaggedUuidType),
    /// Raw bytes
    Bytes(TaggedBytes),
}

impl GroupIdTypeChoice {
    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(uuid) => Some(uuid.as_slice()),
            _ => None,
        }
    }

    pub fn as_raw_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes.as_ref()),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for GroupIdTypeChoice {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let tagged_value = TaggedJsonValue::deserialize(deserializer)?;

            match tagged_value.typ {
                "uuid" => {
                    let uuid: UuidType = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(GroupIdTypeChoice::Uuid(TaggedUuidType::from(uuid)))
                }
                "bytes" => {
                    let bytes: Bytes = serde_json::from_str(tagged_value.value.get())
                        .map_err(de::Error::custom)?;
                    Ok(GroupIdTypeChoice::Bytes(TaggedBytes::from(bytes)))
                }
                s => Err(de::Error::custom(format!(
                    "unexpected GroupIdTypeChoice type \"{s}\""
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
                        37 => {
                            let uuid: UuidType =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(GroupIdTypeChoice::Uuid(TaggedUuidType::from(uuid)))
                        }
                        560 => {
                            let bytes: Bytes =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(GroupIdTypeChoice::Bytes(TaggedBytes::from(bytes)))
                        }
                        n => Err(de::Error::custom(format!(
                            "unexpected ClassIdTypeChoice tag {n}"
                        ))),
                    }
                }
                _ => Err(de::Error::custom("did not see a tag")),
            }
        }
    }
}

/// Map containing measurement values and metadata
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct MeasurementMap<'a> {
    /// Optional measurement key identifier
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    /// Measurement values
    pub mval: MeasurementValuesMap<'a>,
    /// Optional list of authorizing keys
    pub authorized_by: Option<Vec<CryptoKeyTypeChoice<'a>>>,
}

impl Serialize for MeasurementMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();

        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(mkey) = &self.mkey {
                map.serialize_entry("mkey", mkey)?;
            }

            map.serialize_entry("mval", &self.mval)?;

            if let Some(authorized_by) = &self.authorized_by {
                map.serialize_entry("authorized-by", authorized_by)?;
            }
        } else {
            if let Some(mkey) = &self.mkey {
                map.serialize_entry(&0, mkey)?;
            }

            map.serialize_entry(&1, &self.mval)?;

            if let Some(authorized_by) = &self.authorized_by {
                map.serialize_entry(&2, authorized_by)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for MeasurementMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MeasurementMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for MeasurementMapVisitor<'a> {
            type Value = MeasurementMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing MeasurementMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut mkey: Option<MeasuredElementTypeChoice<'a>> = None;
                let mut mval: Option<MeasurementValuesMap<'a>> = None;
                let mut authorized_by: Option<Vec<CryptoKeyTypeChoice<'a>>> = None;

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("mkey") => {
                                mkey = Some(map.next_value::<MeasuredElementTypeChoice>()?);
                            }
                            Some("mval") => {
                                mval = Some(map.next_value::<MeasurementValuesMap>()?);
                            }
                            Some("authorized-by") => {
                                authorized_by = Some(map.next_value::<Vec<CryptoKeyTypeChoice>>()?);
                            }
                            Some(name) => {
                                return Err(de::Error::unknown_field(
                                    name,
                                    &["mkey", "mval", "authorized-by"],
                                ))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                mkey = Some(map.next_value::<MeasuredElementTypeChoice>()?);
                            }
                            Some(1) => {
                                mval = Some(map.next_value::<MeasurementValuesMap>()?);
                            }
                            Some(2) => {
                                authorized_by = Some(map.next_value::<Vec<CryptoKeyTypeChoice>>()?);
                            }
                            Some(n) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected index {n} for MeasurementMap"
                                )))
                            }
                            None => break,
                        }
                    }
                }

                if let Some(mval) = mval {
                    Ok(MeasurementMap {
                        mkey,
                        mval,
                        authorized_by,
                    })
                } else {
                    Err(de::Error::missing_field("mval"))
                }
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(MeasurementMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

/// Types of measured element identifiers
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum MeasuredElementTypeChoice<'a> {
    /// Object Identifier (OID)
    Oid(OidType),
    /// UUID identifier
    Uuid(TaggedUuidType),
    /// Unsigned integer
    UInt(Uint),
    /// Text string
    Tstr(Tstr<'a>),
    /// Extension
    Extension(ExtensionValue<'a>),
}

impl MeasuredElementTypeChoice<'_> {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Oid(oid) => oid.is_empty(),
            Self::Uuid(uuid) => uuid.is_empty(),
            Self::UInt(_) => false,
            Self::Tstr(tstr) => tstr.is_empty(),
            Self::Extension(ext) => ext.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Oid(oid) => oid.len(),
            Self::Uuid(uuid) => uuid.len(),
            Self::UInt(_) => 4,
            Self::Tstr(tstr) => tstr.len(),
            Self::Extension(ext) => ext.len(),
        }
    }

    pub fn as_oid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Oid(oid) => Some(oid.as_ref()),
            _ => None,
        }
    }

    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(uuid) => Some(uuid.as_ref().as_ref()),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<Integer> {
        match self {
            Self::UInt(uint) => Some(*uint),
            Self::Extension(ext) => ext.as_uint(),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Tstr(tstr) => Some(tstr),
            Self::Extension(ext) => ext.as_str(),
            _ => None,
        }
    }
}

impl<'a> From<&'a str> for MeasuredElementTypeChoice<'a> {
    fn from(value: &'a str) -> Self {
        Self::Tstr(value.into())
    }
}

impl<'de> Deserialize<'de> for MeasuredElementTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
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
                                "oid" => Ok(MeasuredElementTypeChoice::Oid(OidType::from(
                                    ObjectIdentifier::try_from(value.as_str())
                                        .map_err(|_| de::Error::custom("invalid OID bytes"))?,
                                ))),
                                "uuid" => {
                                    Ok(MeasuredElementTypeChoice::Uuid(TaggedUuidType::from(
                                        UuidType::try_from(value.as_str())
                                            .map_err(|_| de::Error::custom("invalid UUID bytes"))?,
                                    )))
                                }
                                s => Err(de::Error::custom(format!(
                                    "unexpected type {s} for MeasuredElementTypeChoice"
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
                                Some(u) => {
                                    Ok(MeasuredElementTypeChoice::Extension(ExtensionValue::Tag(
                                        u,
                                        Box::new(
                                            ExtensionValue::try_from(map["value"].clone())
                                                .map_err(de::Error::custom)?,
                                        ),
                                    )))
                                }
                                None => Err(de::Error::custom(format!(
                                    "a number must be an unsinged integer, got {n:?}"
                                ))),
                            },
                            v => Err(de::Error::custom(format!("invalid tag {v:?}"))),
                        }
                    } else {
                        Ok(MeasuredElementTypeChoice::Extension(
                            ExtensionValue::try_from(serde_json::Value::Object(map))
                                .map_err(de::Error::custom)?,
                        ))
                    }
                }
                serde_json::Value::String(s) => Ok(MeasuredElementTypeChoice::Tstr(s.into())),
                serde_json::Value::Number(n) => match n.as_u64() {
                    Some(u) => Ok(MeasuredElementTypeChoice::UInt(u.into())),
                    None => Err(de::Error::custom(format!(
                        "a number must be an unsinged integer, got {n:?}"
                    ))),
                },
                array @ serde_json::Value::Array(_) => Ok(MeasuredElementTypeChoice::Extension(
                    ExtensionValue::try_from(array).map_err(de::Error::custom)?,
                )),
                serde_json::Value::Bool(b) => Ok(MeasuredElementTypeChoice::Extension(
                    ExtensionValue::Bool(b),
                )),
                serde_json::Value::Null => {
                    Ok(MeasuredElementTypeChoice::Extension(ExtensionValue::Null))
                }
            }
        } else {
            match ciborium::Value::deserialize(deserializer)? {
                ciborium::Value::Tag(tag, inner) => match tag {
                    37 => {
                        let value: Vec<u8> = match inner.deref() {
                            ciborium::Value::Bytes(bytes) => Ok(bytes.clone()),
                            value => Err(de::Error::custom(format!(
                                "unexpected value {value:?} for MeasuredElementTypeChoice"
                            ))),
                        }?;

                        Ok(MeasuredElementTypeChoice::Uuid(TaggedUuidType::from(
                            UuidType::try_from(value.as_slice())
                                .map_err(|_| de::Error::custom("invalid UUID bytes"))?,
                        )))
                    }
                    111 => {
                        let value: Vec<u8> = match inner.deref() {
                            ciborium::Value::Bytes(bytes) => Ok(bytes.clone()),
                            value => Err(de::Error::custom(format!(
                                "unexpected value {value:?} for MeasuredElementTypeChoice"
                            ))),
                        }?;

                        Ok(MeasuredElementTypeChoice::Oid(OidType::from(
                            ObjectIdentifier::try_from(value)
                                .map_err(|_| de::Error::custom("invalid OID bytes"))?,
                        )))
                    }
                    n => Ok(MeasuredElementTypeChoice::Extension(ExtensionValue::Tag(
                        n,
                        Box::new(
                            ExtensionValue::try_from(inner.deref().to_owned())
                                .map_err(de::Error::custom)?,
                        ),
                    ))),
                },
                ciborium::Value::Text(text) => Ok(MeasuredElementTypeChoice::Tstr(text.into())),
                ciborium::Value::Integer(int) => {
                    Ok(MeasuredElementTypeChoice::UInt(i128::from(int).into()))
                }
                value => Ok(MeasuredElementTypeChoice::Extension(
                    ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                )),
            }
        }
    }
}

/// Collection of measurement values and attributes. It is **HIGHLY** recommend to use MeasurementValuesMapBuilder
/// to ensure the CDDL enforcement of at least one field being present.
#[derive(Default, Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct MeasurementValuesMap<'a> {
    /// Optional version information
    pub version: Option<VersionMap<'a>>,
    /// Optional security version number
    pub svn: Option<SvnTypeChoice>,
    /// Optiona cryptographic digests
    pub digests: Option<DigestsType>,
    /// Optional status flags
    pub flags: Option<FlagsMap<'a>>,
    /// Optional raw measurement value
    pub raw: Option<RawValueType>,
    /// Optional MAC address
    pub mac_addr: Option<MacAddrTypeChoice>,
    /// Optional IP address
    pub ip_addr: Option<IpAddrTypeChoice>,
    /// Optional serial number
    pub serial_number: Option<Text<'a>>,
    /// Optional UEID
    pub ueid: Option<UeidType>,
    /// Optional UUID
    pub uuid: Option<UuidType>,
    /// Optional name
    pub name: Option<Text<'a>>,
    /// Optional cryptographic keys
    pub cryptokeys: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    /// Optional integrity register values
    pub integrity_registers: Option<IntegrityRegisters<'a>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Serialize for MeasurementValuesMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(version) = &self.version {
                map.serialize_entry("version", version)?;
            }
            if let Some(svn) = &self.svn {
                map.serialize_entry("svn", svn)?;
            }
            if let Some(digests) = &self.digests {
                map.serialize_entry("digests", digests)?;
            }
            if let Some(flags) = &self.flags {
                map.serialize_entry("flags", flags)?;
            }
            if let Some(raw) = &self.raw {
                map.serialize_entry("raw-value", &raw.raw_value)?;

                if let Some(mask) = &raw.raw_value_mask {
                    map.serialize_entry("raw-value-mask", mask)?;
                }
            }
            if let Some(mac_addr) = &self.mac_addr {
                map.serialize_entry("mac-addr", mac_addr)?;
            }
            if let Some(ip_addr) = &self.ip_addr {
                map.serialize_entry("ip-addr", ip_addr)?;
            }
            if let Some(serial_number) = &self.serial_number {
                map.serialize_entry("serial-number", serial_number)?;
            }
            if let Some(ueid) = &self.ueid {
                map.serialize_entry("ueid", ueid)?;
            }
            if let Some(uuid) = &self.uuid {
                map.serialize_entry("uuid", uuid)?;
            }
            if let Some(name) = &self.name {
                map.serialize_entry("name", name)?;
            }
            if let Some(cryptokeys) = &self.cryptokeys {
                map.serialize_entry("cryptokeys", cryptokeys)?;
            }
            if let Some(integrity_registers) = &self.integrity_registers {
                map.serialize_entry("integrity-registers", integrity_registers)?;
            }
        } else {
            if let Some(version) = &self.version {
                map.serialize_entry(&0, version)?;
            }
            if let Some(svn) = &self.svn {
                map.serialize_entry(&1, svn)?;
            }
            if let Some(digests) = &self.digests {
                map.serialize_entry(&2, digests)?;
            }
            if let Some(flags) = &self.flags {
                map.serialize_entry(&3, flags)?;
            }
            if let Some(raw) = &self.raw {
                map.serialize_entry(&4, &raw.raw_value)?;

                if let Some(mask) = &raw.raw_value_mask {
                    map.serialize_entry(&5, mask)?;
                }
            }
            if let Some(mac_addr) = &self.mac_addr {
                map.serialize_entry(&6, mac_addr)?;
            }
            if let Some(ip_addr) = &self.ip_addr {
                map.serialize_entry(&7, ip_addr)?;
            }
            if let Some(serial_number) = &self.serial_number {
                map.serialize_entry(&8, serial_number)?;
            }
            if let Some(ueid) = &self.ueid {
                map.serialize_entry(&9, ueid)?;
            }
            if let Some(uuid) = &self.uuid {
                map.serialize_entry(&10, uuid)?;
            }
            if let Some(name) = &self.name {
                map.serialize_entry(&11, name)?;
            }
            if let Some(cryptokeys) = &self.cryptokeys {
                map.serialize_entry(&13, cryptokeys)?;
            }
            if let Some(integrity_registers) = &self.integrity_registers {
                map.serialize_entry(&14, integrity_registers)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for MeasurementValuesMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MeasurementValuesMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for MeasurementValuesMapVisitor<'a> {
            type Value = MeasurementValuesMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing MeasurementValuesMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = MeasurementValuesMapBuilder::default();
                let mut raw_value: Option<RawValueTypeChoice> = None;
                let mut raw_value_mask: Option<RawValueMaskType> = None;
                let mut extensions = ExtensionMap::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("version") => {
                                builder = builder.version(map.next_value::<VersionMap>()?);
                            }
                            Some("svn") => {
                                builder = builder.svn(map.next_value::<SvnTypeChoice>()?);
                            }
                            Some("digests") => {
                                builder = builder.digest(map.next_value::<DigestsType>()?);
                            }
                            Some("flags") => {
                                builder = builder.flags(map.next_value::<FlagsMap>()?);
                            }
                            Some("raw-value") => {
                                raw_value = Some(map.next_value::<RawValueTypeChoice>()?);
                            }
                            Some("raw-value-mask") => {
                                raw_value_mask = Some(map.next_value::<RawValueMaskType>()?);
                            }
                            Some("mac-addr") => {
                                builder = builder.mac_addr(map.next_value::<MacAddrTypeChoice>()?);
                            }
                            Some("ip-addr") => {
                                builder = builder.ip_addr(map.next_value::<IpAddrTypeChoice>()?);
                            }
                            Some("serial-number") => {
                                builder = builder.serial_number(map.next_value::<Text>()?);
                            }
                            Some("ueid") => {
                                builder = builder.ueid(map.next_value::<UeidType>()?);
                            }
                            Some("uuid") => {
                                builder = builder.uuid(map.next_value::<UuidType>()?);
                            }
                            Some("name") => {
                                builder = builder.name(map.next_value::<Text>()?);
                            }
                            Some("cryptokeys") => {
                                builder = builder
                                    .cryptokeys(map.next_value::<Vec<CryptoKeyTypeChoice>>()?);
                            }
                            Some("integrity-registers") => {
                                builder = builder
                                    .integrity_registers(map.next_value::<IntegrityRegisters>()?);
                            }
                            Some(s) => {
                                extensions.insert(
                                    s.parse::<Integer>().map_err(de::Error::custom)?,
                                    map.next_value::<ExtensionValue>()?,
                                );
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                builder = builder.version(map.next_value::<VersionMap>()?);
                            }
                            Some(1) => {
                                builder = builder.svn(map.next_value::<SvnTypeChoice>()?);
                            }
                            Some(2) => {
                                builder = builder.digest(map.next_value::<DigestsType>()?);
                            }
                            Some(3) => {
                                builder = builder.flags(map.next_value::<FlagsMap>()?);
                            }
                            Some(4) => {
                                raw_value = Some(map.next_value::<RawValueTypeChoice>()?);
                            }
                            Some(5) => {
                                raw_value_mask = Some(map.next_value::<RawValueMaskType>()?);
                            }
                            Some(6) => {
                                builder = builder.mac_addr(map.next_value::<MacAddrTypeChoice>()?);
                            }
                            Some(7) => {
                                builder = builder.ip_addr(map.next_value::<IpAddrTypeChoice>()?);
                            }
                            Some(8) => {
                                builder = builder.serial_number(map.next_value::<Text>()?);
                            }
                            Some(9) => {
                                builder = builder.ueid(map.next_value::<UeidType>()?);
                            }
                            Some(10) => {
                                builder = builder.uuid(map.next_value::<UuidType>()?);
                            }
                            Some(11) => {
                                builder = builder.name(map.next_value::<Text>()?);
                            }
                            Some(13) => {
                                builder = builder
                                    .cryptokeys(map.next_value::<Vec<CryptoKeyTypeChoice>>()?);
                            }
                            Some(14) => {
                                builder = builder
                                    .integrity_registers(map.next_value::<IntegrityRegisters>()?);
                            }
                            Some(n) => {
                                extensions.insert(n.into(), map.next_value::<ExtensionValue>()?);
                            }
                            None => break,
                        }
                    }
                }

                if let Some(raw_value) = raw_value {
                    builder = builder.raw(RawValueType {
                        raw_value,
                        raw_value_mask,
                    });
                } else if raw_value_mask.is_some() {
                    return Err(de::Error::custom(
                        "raw-value-mask (index 5) specified without a raw-value (index 4)",
                    ));
                }

                if !extensions.is_empty() {
                    builder = builder.extensions(extensions)
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(MeasurementValuesMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct MeasurementValuesMapBuilder<'a> {
    /// Optional version information
    pub version: Option<VersionMap<'a>>,
    /// Optional security version number
    pub svn: Option<SvnTypeChoice>,
    /// Optional cryptographic digest
    pub digest: Option<DigestsType>,
    /// Optional status flags
    pub flags: Option<FlagsMap<'a>>,
    /// Optional raw measurement value
    pub raw: Option<RawValueType>,
    /// Optional MAC address
    pub mac_addr: Option<MacAddrTypeChoice>,
    /// Optional IP address
    pub ip_addr: Option<IpAddrTypeChoice>,
    /// Optional serial number
    pub serial_number: Option<Text<'a>>,
    /// Optional UEID
    pub ueid: Option<UeidType>,
    /// Optional UUID
    pub uuid: Option<UuidType>,
    /// Optional name
    pub name: Option<Text<'a>>,
    /// Optional cryptographic keys
    pub cryptokeys: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    /// Optional integrity register values
    pub integrity_registers: Option<IntegrityRegisters<'a>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl<'a> MeasurementValuesMapBuilder<'a> {
    pub fn version(mut self, value: VersionMap<'a>) -> Self {
        self.version = Some(value);
        self
    }
    pub fn svn(mut self, value: SvnTypeChoice) -> Self {
        self.svn = Some(value);
        self
    }
    pub fn digest(mut self, value: DigestsType) -> Self {
        self.digest = Some(value);
        self
    }
    pub fn flags(mut self, value: FlagsMap<'a>) -> Self {
        self.flags = Some(value);
        self
    }
    pub fn raw(mut self, value: RawValueType) -> Self {
        self.raw = Some(value);
        self
    }
    pub fn mac_addr(mut self, value: MacAddrTypeChoice) -> Self {
        self.mac_addr = Some(value);
        self
    }
    pub fn ip_addr(mut self, value: IpAddrTypeChoice) -> Self {
        self.ip_addr = Some(value);
        self
    }
    pub fn serial_number(mut self, value: Text<'a>) -> Self {
        self.serial_number = Some(value);
        self
    }
    pub fn ueid(mut self, value: UeidType) -> Self {
        self.ueid = Some(value);
        self
    }
    pub fn uuid(mut self, value: UuidType) -> Self {
        self.uuid = Some(value);
        self
    }
    pub fn name(mut self, value: Text<'a>) -> Self {
        self.name = Some(value);
        self
    }
    pub fn cryptokeys(mut self, value: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.cryptokeys = Some(value);
        self
    }
    pub fn integrity_registers(mut self, value: IntegrityRegisters<'a>) -> Self {
        self.integrity_registers = Some(value);
        self
    }
    pub fn extensions(mut self, value: ExtensionMap<'a>) -> Self {
        self.extensions = Some(value);
        self
    }

    pub fn build(self) -> Result<MeasurementValuesMap<'a>> {
        if self.version.is_none()
            && self.svn.is_none()
            && self.digest.is_none()
            && self.flags.is_none()
            && self.raw.is_none()
            && self.mac_addr.is_none()
            && self.ip_addr.is_none()
            && self.serial_number.is_none()
            && self.ueid.is_none()
            && self.uuid.is_none()
            && self.name.is_none()
            && self.cryptokeys.is_none()
            && self.integrity_registers.is_none()
            && self.extensions.is_none()
        {
            return Err(TriplesError::EmptyMeasurementValuesMap)?;
        }
        Ok(MeasurementValuesMap {
            version: self.version,
            svn: self.svn,
            digests: self.digest,
            flags: self.flags,
            raw: self.raw,
            mac_addr: self.mac_addr,
            ip_addr: self.ip_addr,
            serial_number: self.serial_number,
            ueid: self.ueid,
            uuid: self.uuid,
            name: self.name,
            cryptokeys: self.cryptokeys,
            integrity_registers: self.integrity_registers,
            extensions: self.extensions,
        })
    }
}

/// Version information with optional versioning scheme
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct VersionMap<'a> {
    /// Version identifier string
    pub version: Text<'a>,
    /// Optional version numbering scheme
    pub version_scheme: Option<VersionScheme<'a>>,
}

impl Serialize for VersionMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("version", self.version.as_ref())?;

            if let Some(scheme) = &self.version_scheme {
                map.serialize_entry("version-scheme", scheme)?;
            }
        } else {
            map.serialize_entry(&0, self.version.as_ref())?;

            if let Some(scheme) = &self.version_scheme {
                map.serialize_entry(&1, scheme)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for VersionMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VersionMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for VersionMapVisitor<'a> {
            type Value = VersionMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing VersionMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut version: Option<Text<'a>> = None;
                let mut version_scheme: Option<VersionScheme<'a>> = None;

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("version") => {
                                version = Some(map.next_value::<String>()?.into());
                            }
                            Some("version-scheme") => {
                                version_scheme = Some(map.next_value::<VersionScheme>()?);
                            }
                            Some(name) => {
                                return Err(de::Error::unknown_field(
                                    name,
                                    &["version", "version-scheme"],
                                ));
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                version = Some(map.next_value::<String>()?.into());
                            }
                            Some(1) => {
                                version_scheme = Some(map.next_value::<VersionScheme>()?);
                            }
                            Some(key) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected key {key} for VersionMap"
                                )))
                            }
                            None => break,
                        }
                    }
                }

                if let Some(version) = version {
                    Ok(VersionMap {
                        version,
                        version_scheme,
                    })
                } else {
                    Err(de::Error::missing_field("version"))
                }
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(VersionMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

/// Security version number types
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum SvnTypeChoice {
    /// Regular SVN as an unsigned integer
    Svn(Uint),
    /// SVN with CBOR tag 552
    TaggedSvn(SvnType),
    /// Minimum SVN with CBOR tag 553
    TaggedMinSvn(MinSvnType),
}

impl SvnTypeChoice {
    pub fn as_svn(&self) -> Option<Integer> {
        match self {
            Self::Svn(svn) => Some(*svn),
            _ => None,
        }
    }

    pub fn as_tagged_svn(&self) -> Option<SvnType> {
        match self {
            Self::TaggedSvn(svn) => Some(svn.clone()),
            _ => None,
        }
    }

    pub fn as_tagged_min_svn(&self) -> Option<MinSvnType> {
        match self {
            Self::TaggedMinSvn(svn) => Some(svn.clone()),
            _ => None,
        }
    }
}

impl From<u64> for SvnTypeChoice {
    fn from(value: u64) -> Self {
        Self::Svn(value.into())
    }
}

impl<'de> Deserialize<'de> for SvnTypeChoice {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SvnTypeChoiceJsonVisitor;

        impl<'de> Visitor<'de> for SvnTypeChoiceJsonVisitor {
            type Value = SvnTypeChoice;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("either a uint, a tagged SVN, or a tagged MinSVN")
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SvnTypeChoice::Svn(v.into()))
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut typ: Option<&str> = None;
                let mut value: Option<Uint> = None;

                loop {
                    match map.next_key::<&str>()? {
                        Some("type") => {
                            typ = Some(map.next_value()?);
                        }
                        Some("value") => {
                            value = Some(map.next_value()?);
                        }
                        Some(name) => {
                            return Err(de::Error::unknown_field(name, &["type", "value"]))
                        }
                        None => break,
                    }
                }

                if value.is_none() {
                    return Err(de::Error::missing_field("value"));
                }

                match typ {
                    Some("svn") => Ok(SvnTypeChoice::TaggedSvn(SvnType::from(value.unwrap()))),
                    Some("min-svn") => Ok(SvnTypeChoice::TaggedMinSvn(MinSvnType::from(
                        value.unwrap(),
                    ))),
                    Some(s) => Err(de::Error::custom(format!(
                        "unexpected type {s} for SvnTypeChoice"
                    ))),
                    None => Err(de::Error::missing_field("type")),
                }
            }
        }

        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            deserializer.deserialize_any(SvnTypeChoiceJsonVisitor)
        } else {
            match ciborium::Value::deserialize(deserializer)? {
                ciborium::Value::Tag(tag, inner) => {
                    let value: i128 = match inner.as_ref() {
                        &ciborium::Value::Integer(int) => Ok(int),
                        value => Err(de::Error::custom(format!(
                            "unexpected value {value:?} for SvnTypeChoice"
                        ))),
                    }?
                    .into();

                    match tag {
                        552 => Ok(SvnTypeChoice::TaggedSvn(SvnType::from(Integer(value)))),
                        553 => Ok(SvnTypeChoice::TaggedMinSvn(MinSvnType::from(Integer(
                            value,
                        )))),
                        n => Err(de::Error::custom(format!(
                            "unexpected tag {n} for SvnTypeChoice"
                        ))),
                    }
                }
                ciborium::Value::Integer(int) => Ok(SvnTypeChoice::Svn(i128::from(int).into())),
                value => Err(de::Error::custom(format!(
                    "unexpected value {value:?} for SvnTypeChoice"
                ))),
            }
        }
    }
}

/// Collection of one or more cryptographic digests
pub type DigestsType = Vec<Digest>;

/// Status flags indicating various security and configuration states
#[derive(Default, Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct FlagsMap<'a> {
    /// Whether the environment is configured
    pub is_configured: Option<bool>,
    /// Whether the environment is in a secure state
    pub is_secure: Option<bool>,
    /// Whether the environment is in recovery mode
    pub is_recovery: Option<bool>,
    /// Whether debug features are enabled
    pub is_debug: Option<bool>,
    /// Whether replay protection is enabled
    pub is_replay_protected: Option<bool>,
    /// Whether integrity protection is enabled
    pub is_integrity_protected: Option<bool>,
    /// Whether runtime measurements are enabled
    pub is_runtime_meas: Option<bool>,
    /// Whether the environment is immutable
    pub is_immutable: Option<bool>,
    /// Whether the environment is part of the TCB
    pub is_tcb: Option<bool>,
    /// Whether confidentiality protection is enabled
    pub is_confidentiality_protected: Option<bool>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Serialize for FlagsMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();

        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(is_configured) = self.is_configured {
                map.serialize_entry("is-configured", &is_configured)?;
            }
            if let Some(is_secure) = self.is_secure {
                map.serialize_entry("is-secure", &is_secure)?;
            }
            if let Some(is_recovery) = self.is_recovery {
                map.serialize_entry("is-recovery", &is_recovery)?;
            }
            if let Some(is_debug) = self.is_debug {
                map.serialize_entry("is-debug", &is_debug)?;
            }
            if let Some(is_replay_protected) = self.is_replay_protected {
                map.serialize_entry("is-replay-protected", &is_replay_protected)?;
            }
            if let Some(is_integrity_protected) = self.is_integrity_protected {
                map.serialize_entry("is-integrity-protected", &is_integrity_protected)?;
            }
            if let Some(is_runtime_meas) = self.is_runtime_meas {
                map.serialize_entry("is-runtime-meas", &is_runtime_meas)?;
            }
            if let Some(is_immutable) = self.is_immutable {
                map.serialize_entry("is-immutable", &is_immutable)?;
            }
            if let Some(is_tcb) = self.is_tcb {
                map.serialize_entry("is-tcb", &is_tcb)?;
            }
            if let Some(is_confidentiality_protected) = self.is_confidentiality_protected {
                map.serialize_entry(
                    "is-confidentiality-protected",
                    &is_confidentiality_protected,
                )?;
            }
            if let Some(extensions) = &self.extensions {
                extensions.serialize_map(&mut map, is_human_readable)?;
            }
        } else {
            if let Some(is_configured) = self.is_configured {
                map.serialize_entry(&0, &is_configured)?;
            }
            if let Some(is_secure) = self.is_secure {
                map.serialize_entry(&1, &is_secure)?;
            }
            if let Some(is_recovery) = self.is_recovery {
                map.serialize_entry(&2, &is_recovery)?;
            }
            if let Some(is_debug) = self.is_debug {
                map.serialize_entry(&3, &is_debug)?;
            }
            if let Some(is_replay_protected) = self.is_replay_protected {
                map.serialize_entry(&4, &is_replay_protected)?;
            }
            if let Some(is_integrity_protected) = self.is_integrity_protected {
                map.serialize_entry(&5, &is_integrity_protected)?;
            }
            if let Some(is_runtime_meas) = self.is_runtime_meas {
                map.serialize_entry(&6, &is_runtime_meas)?;
            }
            if let Some(is_immutable) = self.is_immutable {
                map.serialize_entry(&7, &is_immutable)?;
            }
            if let Some(is_tcb) = self.is_tcb {
                map.serialize_entry(&8, &is_tcb)?;
            }
            if let Some(is_confidentiality_protected) = self.is_confidentiality_protected {
                map.serialize_entry(&9, &is_confidentiality_protected)?;
            }
            if let Some(extensions) = &self.extensions {
                extensions.serialize_map(&mut map, is_human_readable)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for FlagsMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FlagsMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for FlagsMapVisitor<'a> {
            type Value = FlagsMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing FlagsMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut flags_map: FlagsMap = FlagsMap::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("is-configured") => {
                                flags_map.is_configured = Some(map.next_value::<bool>()?);
                            }
                            Some("is-secure") => {
                                flags_map.is_secure = Some(map.next_value::<bool>()?);
                            }
                            Some("is-recovery") => {
                                flags_map.is_recovery = Some(map.next_value::<bool>()?);
                            }
                            Some("is-debug") => {
                                flags_map.is_debug = Some(map.next_value::<bool>()?);
                            }
                            Some("is-replay-protected") => {
                                flags_map.is_replay_protected = Some(map.next_value::<bool>()?);
                            }
                            Some("is-integrity-protected") => {
                                flags_map.is_integrity_protected = Some(map.next_value::<bool>()?);
                            }
                            Some("is-runtime-meas") => {
                                flags_map.is_runtime_meas = Some(map.next_value::<bool>()?);
                            }
                            Some("is-immutable") => {
                                flags_map.is_immutable = Some(map.next_value::<bool>()?);
                            }
                            Some("is-tcb") => {
                                flags_map.is_tcb = Some(map.next_value::<bool>()?);
                            }
                            Some("is-confidentiality-protected") => {
                                flags_map.is_confidentiality_protected =
                                    Some(map.next_value::<bool>()?);
                            }
                            Some(s) => {
                                if let Some(ref mut extensions) = flags_map.extensions.as_mut() {
                                    extensions.insert(
                                        s.parse::<Integer>().map_err(de::Error::custom)?,
                                        map.next_value::<ExtensionValue>()?,
                                    );
                                } else {
                                    let mut extensions = ExtensionMap::default();
                                    extensions.insert(
                                        s.parse::<Integer>().map_err(de::Error::custom)?,
                                        map.next_value::<ExtensionValue>()?,
                                    );
                                    flags_map.extensions = Some(extensions);
                                }
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                flags_map.is_configured = Some(map.next_value::<bool>()?);
                            }
                            Some(1) => {
                                flags_map.is_secure = Some(map.next_value::<bool>()?);
                            }
                            Some(2) => {
                                flags_map.is_recovery = Some(map.next_value::<bool>()?);
                            }
                            Some(3) => {
                                flags_map.is_debug = Some(map.next_value::<bool>()?);
                            }
                            Some(4) => {
                                flags_map.is_replay_protected = Some(map.next_value::<bool>()?);
                            }
                            Some(5) => {
                                flags_map.is_integrity_protected = Some(map.next_value::<bool>()?);
                            }
                            Some(6) => {
                                flags_map.is_runtime_meas = Some(map.next_value::<bool>()?);
                            }
                            Some(7) => {
                                flags_map.is_immutable = Some(map.next_value::<bool>()?);
                            }
                            Some(8) => {
                                flags_map.is_tcb = Some(map.next_value::<bool>()?);
                            }
                            Some(9) => {
                                flags_map.is_confidentiality_protected =
                                    Some(map.next_value::<bool>()?);
                            }
                            Some(n) => {
                                if let Some(ref mut extensions) = flags_map.extensions.as_mut() {
                                    extensions
                                        .insert(n.into(), map.next_value::<ExtensionValue>()?);
                                } else {
                                    let mut extensions = ExtensionMap::default();
                                    extensions
                                        .insert(n.into(), map.next_value::<ExtensionValue>()?);
                                    flags_map.extensions = Some(extensions);
                                }
                            }
                            None => break,
                        }
                    }
                }

                Ok(flags_map)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(FlagsMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

/// Types of MAC addresses supporting both EUI-48 and EUI-64 formats
///
/// Implements standard traits for byte access:
/// - `AsRef<[u8]>`/`AsMut<[u8]>` for buffer access
/// - `Deref`/`DerefMut` for direct byte manipulation
/// - `From` for construction from byte arrays
/// - `TryFrom` for fallible construction from slices
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub enum MacAddrTypeChoice {
    /// 48-bit EUI address
    Eui48Addr(Eui48AddrType),
    /// 64-bit EUI address
    Eui64Addr(Eui64AddrType),
}

impl MacAddrTypeChoice {
    pub fn as_eui48_addr(&self) -> Option<&[u8]> {
        match self {
            Self::Eui48Addr(addr) => Some(addr),
            _ => None,
        }
    }

    pub fn as_eui64_addr(&self) -> Option<&[u8]> {
        match self {
            Self::Eui64Addr(addr) => Some(addr),
            _ => None,
        }
    }
}

impl From<Eui48AddrType> for MacAddrTypeChoice {
    fn from(value: Eui48AddrType) -> Self {
        Self::Eui48Addr(value)
    }
}

impl From<Eui64AddrType> for MacAddrTypeChoice {
    fn from(value: Eui64AddrType) -> Self {
        Self::Eui64Addr(value)
    }
}

impl TryFrom<&[u8]> for MacAddrTypeChoice {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        match value.len() {
            6 => Ok(Self::Eui48Addr(value.try_into().unwrap())),
            8 => Ok(Self::Eui64Addr(value.try_into().unwrap())),
            _ => Err(<[u8; 0]>::try_from(&[][..]).unwrap_err()),
        }
    }
}

impl TryFrom<&str> for MacAddrTypeChoice {
    type Error = TriplesError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let parts: Vec<u8> = value
            .split("-")
            .map(|x| u8::from_str_radix(x, 16).map_err(|_| TriplesError::InvalidMacAddrType))
            .collect::<std::result::Result<Vec<u8>, TriplesError>>()?;

        let n = parts.len();
        match n {
            6 => Ok(Self::Eui48Addr(parts.try_into().unwrap())),
            8 => Ok(Self::Eui64Addr(parts.try_into().unwrap())),
            _ => Err(TriplesError::InvalidMacAddrType),
        }
    }
}

impl AsRef<[u8]> for MacAddrTypeChoice {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Eui48Addr(addr) => addr,
            Self::Eui64Addr(addr) => addr,
        }
    }
}

impl AsMut<[u8]> for MacAddrTypeChoice {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Eui48Addr(addr) => addr,
            Self::Eui64Addr(addr) => addr,
        }
    }
}

impl Deref for MacAddrTypeChoice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Eui48Addr(addr) => addr,
            Self::Eui64Addr(addr) => addr,
        }
    }
}

impl DerefMut for MacAddrTypeChoice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Eui48Addr(addr) => addr,
            Self::Eui64Addr(addr) => addr,
        }
    }
}

impl Display for MacAddrTypeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eui48Addr(addr) => write!(
                f,
                "{:02X?}-{:02X?}-{:02X?}-{:02X?}-{:02X?}-{:02X?}",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
            ),
            Self::Eui64Addr(addr) => write!(
                f,
                "{:02X?}-{:02X?}-{:02X?}-{:02X?}-{:02X?}-{:02X?}-{:02X?}-{:02X?}",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]
            ),
        }
    }
}

impl Serialize for MacAddrTypeChoice {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();

        if is_human_readable {
            self.to_string().serialize(serializer)
        } else {
            match self {
                Self::Eui48Addr(octets) => serializer.serialize_bytes(octets.as_slice()),
                Self::Eui64Addr(octets) => serializer.serialize_bytes(octets.as_slice()),
            }
        }
    }
}

impl<'de> Deserialize<'de> for MacAddrTypeChoice {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            String::deserialize(deserializer)?
                .as_str()
                .try_into()
                .map_err(de::Error::custom)
        } else {
            Vec::<u8>::deserialize(deserializer)?
                .as_slice()
                .try_into()
                .map_err(de::Error::custom)
        }
    }
}

/// 48-bit MAC address type
pub type Eui48AddrType = [u8; 6];
/// 64-bit MAC address type
pub type Eui64AddrType = [u8; 8];

/// Types of IP addresses supporting both IPv4 and IPv6
///
/// Storage uses network byte order (big-endian) following RFC 791/8200.
/// Implements the same traits as MacAddrTypeChoice for consistent handling.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub enum IpAddrTypeChoice {
    /// IPv4 address
    Ipv4(Ipv4AddrType),
    /// IPv6 address
    Ipv6(Ipv6AddrType),
}

impl IpAddrTypeChoice {
    pub fn as_ipv4_addr(&self) -> Option<&[u8]> {
        match self {
            Self::Ipv4(addr) => Some(addr),
            _ => None,
        }
    }

    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Ipv4(addr) => Some(Ipv4Addr::from(*addr)),
            _ => None,
        }
    }

    pub fn as_ipv6_addr(&self) -> Option<&[u8]> {
        match self {
            Self::Ipv6(addr) => Some(addr),
            _ => None,
        }
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Self::Ipv6(addr) => Some(Ipv6Addr::from(*addr)),
            _ => None,
        }
    }
}

impl From<Ipv4AddrType> for IpAddrTypeChoice {
    fn from(value: Ipv4AddrType) -> Self {
        Self::Ipv4(value)
    }
}
impl From<Ipv6AddrType> for IpAddrTypeChoice {
    fn from(value: Ipv6AddrType) -> Self {
        Self::Ipv6(value)
    }
}

impl From<IpAddrTypeChoice> for std::net::IpAddr {
    fn from(value: IpAddrTypeChoice) -> Self {
        match value {
            IpAddrTypeChoice::Ipv4(addr) => Self::from(addr.to_owned()),
            IpAddrTypeChoice::Ipv6(addr) => Self::from(addr.to_owned()),
        }
    }
}

impl From<&IpAddrTypeChoice> for std::net::IpAddr {
    fn from(value: &IpAddrTypeChoice) -> Self {
        match value {
            IpAddrTypeChoice::Ipv4(addr) => Self::from(addr.to_owned()),
            IpAddrTypeChoice::Ipv6(addr) => Self::from(addr.to_owned()),
        }
    }
}

impl From<std::net::IpAddr> for IpAddrTypeChoice {
    fn from(value: std::net::IpAddr) -> Self {
        match value {
            std::net::IpAddr::V4(addrv4) => {
                let octets: [u8; 4] = unsafe { std::mem::transmute(addrv4) };
                IpAddrTypeChoice::Ipv4(octets)
            }
            std::net::IpAddr::V6(addrv6) => {
                let octets: [u8; 16] = unsafe { std::mem::transmute(addrv6) };
                IpAddrTypeChoice::Ipv6(octets)
            }
        }
    }
}

impl TryFrom<&[u8]> for IpAddrTypeChoice {
    type Error = std::array::TryFromSliceError;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        match value.len() {
            4 => Ok(Self::Ipv4(value.try_into()?)),
            16 => Ok(Self::Ipv6(value.try_into()?)),
            _ => Err(<[u8; 0]>::try_from(&[][..]).unwrap_err()),
        }
    }
}

impl TryFrom<&str> for IpAddrTypeChoice {
    type Error = std::net::AddrParseError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Ok(value.parse::<std::net::IpAddr>()?.into())
    }
}

impl Deref for IpAddrTypeChoice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Ipv4(addr) => addr,
            Self::Ipv6(addr) => addr,
        }
    }
}

impl DerefMut for IpAddrTypeChoice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Ipv4(addr) => addr,
            Self::Ipv6(addr) => addr,
        }
    }
}

impl AsRef<[u8]> for IpAddrTypeChoice {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ipv4(addr) => addr,
            Self::Ipv6(addr) => addr,
        }
    }
}

impl AsMut<[u8]> for IpAddrTypeChoice {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Ipv4(addr) => addr,
            Self::Ipv6(addr) => addr,
        }
    }
}

impl Display for IpAddrTypeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ip_addr: std::net::IpAddr = self.into();
        f.write_str(&format!("{}", ip_addr))
    }
}

impl Serialize for IpAddrTypeChoice {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();

        if is_human_readable {
            self.to_string().serialize(serializer)
        } else {
            match self {
                Self::Ipv4(octets) => serializer.serialize_bytes(octets.as_slice()),
                Self::Ipv6(octets) => serializer.serialize_bytes(octets.as_slice()),
            }
        }
    }
}

impl<'de> Deserialize<'de> for IpAddrTypeChoice {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            String::deserialize(deserializer)?
                .as_str()
                .try_into()
                .map_err(de::Error::custom)
        } else {
            Vec::<u8>::deserialize(deserializer)?
                .as_slice()
                .try_into()
                .map_err(de::Error::custom)
        }
    }
}

/// IPv4 address as 4 bytes
pub type Ipv4AddrType = [u8; 4];
/// IPv6 address as 16 bytes
pub type Ipv6AddrType = [u8; 16];

/// Collection of integrity register values
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone, Default)]
#[repr(C)]
pub struct IntegrityRegisters<'a>(pub BTreeMap<Ulabel<'a>, Vec<Digest>>);

impl IntegrityRegisters<'_> {
    /// Returns whether the IntegrityRegisters is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of measured objects in the IntegrityRegisters.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over (Ulabel, Vec<Digest>) tuples contained in the IntegrityRegisters.
    pub fn iter(&self) -> Iter<'_, Ulabel, Vec<Digest>> {
        self.0.iter()
    }
}

impl<'a> IntegrityRegisters<'a> {
    /// Returns whether the provided digest matches the measured object associated with the label.
    pub fn check(&self, label: &'a Ulabel<'a>, digest: Digest) -> bool {
        for (key, digests) in self.iter() {
            if key == label {
                if digests.contains(&digest) {
                    return true;
                }

                break;
            }
        }

        false
    }

    /// Adds a digest to the measured object identified by label.
    pub fn add_digest(&mut self, label: Ulabel<'a>, digest: Digest) -> Result<()> {
        match self.0.get_mut(&label) {
            Some(v) => {
                for existing_digest in v.iter() {
                    if existing_digest.alg == digest.alg {
                        return Err(crate::Error::Triples(TriplesError::DigestAlreadyExists(
                            label.to_string(),
                            digest.alg,
                        )));
                    }
                }
                v.push(digest)
            }
            None => {
                self.0.insert(label, vec![digest]);
            }
        };

        Ok(())
    }

    /// Adds a digest to the measured object identified by label, replacing the existing digest
    /// with that algorithm, if one is already registered for label. If a digest was replaced, the
    /// old value is returned
    pub fn replace_digest(&mut self, label: Ulabel<'a>, digest: Digest) -> Option<Digest> {
        let mut replaced: Option<Digest> = None;

        match self.0.get_mut(&label) {
            Some(v) => {
                for (i, existing_digest) in v.iter().enumerate() {
                    if existing_digest.alg == digest.alg {
                        replaced = Some(std::mem::replace(&mut v[i], digest.clone()));
                        break;
                    }
                }

                if replaced.is_none() {
                    v.push(digest)
                }
            }
            None => {
                self.0.insert(label, vec![digest]);
            }
        };

        replaced
    }
}

impl<'a> Index<&Ulabel<'a>> for IntegrityRegisters<'a> {
    type Output = Vec<Digest>;

    fn index(&self, index: &Ulabel<'a>) -> &Self::Output {
        &self.0[index]
    }
}

impl Serialize for IntegrityRegisters<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.is_empty() {
            return Err(ser::Error::custom(
                "IntegrityRegisters must contain at least one entry",
            ));
        }

        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IntegrityRegisters<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let regs = IntegrityRegisters(BTreeMap::deserialize(deserializer)?);

        if regs.is_empty() {
            Err(de::Error::custom(
                "IntegrityRegisters must contain at least one entry",
            ))
        } else {
            Ok(regs)
        }
    }
}

/// Record containing an endorsement for a specific environmental condition
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct EndorsedTripleRecord<'a> {
    /// Environmental condition being endorsed
    pub condition: EnvironmentMap<'a>,
    /// One or more measurement endorsements
    pub endorsement: Vec<MeasurementMap<'a>>,
}

impl Serialize for EndorsedTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.condition)?;
        seq.serialize_element(&self.endorsement)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for EndorsedTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<EndorsedTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EndorsedTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for EndorsedTripleRecordVisitor<'a> {
            type Value = EndorsedTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of [EnvironmentMap, Vec<MeasurementMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<EndorsedTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let condition = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let endorsement = seq
                    .next_element::<Vec<MeasurementMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(EndorsedTripleRecord::new(condition, endorsement))
            }
        }

        deserializer.deserialize_seq(EndorsedTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record containing identity information for an environment
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct IdentityTripleRecord<'a> {
    /// Environment being identified
    pub environment: EnvironmentMap<'a>,
    /// List of cryptographic keys associated with the identity
    pub key_list: Vec<CryptoKeyTypeChoice<'a>>,
    /// Optional conditions for the identity
    pub conditions: Option<TriplesRecordCondition<'a>>,
}

impl Serialize for IdentityTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.conditions.is_none() {
            let mut seq = serializer.serialize_seq(Some(2))?;
            seq.serialize_element(&self.environment)?;
            seq.serialize_element(&self.key_list)?;
            seq.end()
        } else {
            let mut seq = serializer.serialize_seq(Some(3))?;
            seq.serialize_element(&self.environment)?;
            seq.serialize_element(&self.key_list)?;
            seq.serialize_element(&self.conditions)?;
            seq.end()
        }
    }
}

impl<'de, 'a> Deserialize<'de> for IdentityTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<IdentityTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdentityTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for IdentityTripleRecordVisitor<'a> {
            type Value = IdentityTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [EnvironmentMap, Vec<CryptoKeyTypeChoice>, Option<TriplesRecordCondition>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<IdentityTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let key_list = seq
                    .next_element::<Vec<CryptoKeyTypeChoice>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let conditions = seq.next_element::<Option<TriplesRecordCondition>>()?;

                if let Some(conditions) = conditions {
                    Ok(IdentityTripleRecord::new(environment, key_list, conditions))
                } else {
                    Ok(IdentityTripleRecord::new(environment, key_list, None))
                }
            }
        }

        deserializer.deserialize_seq(IdentityTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Conditions that must be met for a triple record to be valid.It is
/// **HIGHLY** recommended to use the TriplesRecordConditionBuilder, to ensure the CDDL enforcement of
/// at least one field being present.
#[derive(Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct TriplesRecordCondition<'a> {
    /// Optional measurement key identifier
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    /// Keys authorized to verify the condition
    pub authorized_by: Option<Vec<CryptoKeyTypeChoice<'a>>>,
}

impl Serialize for TriplesRecordCondition<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(mkey) = &self.mkey {
                map.serialize_entry("mkey", mkey)?;
            }

            if let Some(authorized_by) = &self.authorized_by {
                map.serialize_entry("authorized-by", authorized_by)?;
            }
        } else {
            if let Some(mkey) = &self.mkey {
                map.serialize_entry(&0, mkey)?;
            }

            if let Some(authorized_by) = &self.authorized_by {
                map.serialize_entry(&1, authorized_by)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for TriplesRecordCondition<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TriplesRecordConditionVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for TriplesRecordConditionVisitor<'a> {
            type Value = TriplesRecordCondition<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing TriplesRecordCondition fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = TriplesRecordConditionBuilder::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("mkey") => {
                                builder =
                                    builder.mkey(map.next_value::<MeasuredElementTypeChoice>()?);
                            }
                            Some("authorized-by") => {
                                builder = builder
                                    .authorized_by(map.next_value::<Vec<CryptoKeyTypeChoice>>()?);
                            }
                            Some(s) => {
                                return Err(de::Error::unknown_field(s, &["mkey", "authorized-by"]))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                builder =
                                    builder.mkey(map.next_value::<MeasuredElementTypeChoice>()?);
                            }
                            Some(1) => {
                                builder = builder
                                    .authorized_by(map.next_value::<Vec<CryptoKeyTypeChoice>>()?);
                            }
                            Some(n) => {
                                return Err(de::Error::unknown_field(
                                    n.to_string().as_str(),
                                    &["0-1"],
                                ))
                            }
                            None => break,
                        }
                    };
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(TriplesRecordConditionVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct TriplesRecordConditionBuilder<'a> {
    /// Optional measurement key identifier
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    /// Keys authorized to verify the condition
    pub authorized_by: Option<Vec<CryptoKeyTypeChoice<'a>>>,
}

impl<'a> TriplesRecordConditionBuilder<'a> {
    pub fn mkey(mut self, value: MeasuredElementTypeChoice<'a>) -> Self {
        self.mkey = Some(value);
        self
    }

    pub fn authorized_by(mut self, value: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.authorized_by = Some(value);
        self
    }

    pub fn build(self) -> Result<TriplesRecordCondition<'a>> {
        if self.mkey.is_none() && self.authorized_by.is_none() {
            return Err(TriplesError::EmptyTripleRecordCondition)?;
        }
        Ok(TriplesRecordCondition {
            mkey: self.mkey,
            authorized_by: self.authorized_by,
        })
    }
}

/// Record containing attestation key information for an environment
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct AttestKeyTripleRecord<'a> {
    /// Environment the keys belong to
    pub environment: EnvironmentMap<'a>,
    /// List of attestation keys
    pub key_list: Vec<CryptoKeyTypeChoice<'a>>,
    /// Optional conditions for key usage
    pub conditions: Option<TriplesRecordCondition<'a>>,
}

impl Serialize for AttestKeyTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.conditions.is_none() {
            let mut seq = serializer.serialize_seq(Some(2))?;
            seq.serialize_element(&self.environment)?;
            seq.serialize_element(&self.key_list)?;
            seq.end()
        } else {
            let mut seq = serializer.serialize_seq(Some(3))?;
            seq.serialize_element(&self.environment)?;
            seq.serialize_element(&self.key_list)?;
            seq.serialize_element(&self.conditions)?;
            seq.end()
        }
    }
}

impl<'de, 'a> Deserialize<'de> for AttestKeyTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<AttestKeyTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AttestKeyTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for AttestKeyTripleRecordVisitor<'a> {
            type Value = AttestKeyTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [EnvironmentMap, Vec<CryptoKeyTypeChoice>, Option<TriplesRecordCondition>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<AttestKeyTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let key_list = seq
                    .next_element::<Vec<CryptoKeyTypeChoice>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let conditions = seq.next_element::<Option<TriplesRecordCondition>>()?;

                if let Some(conditions) = conditions {
                    Ok(AttestKeyTripleRecord::new(
                        environment,
                        key_list,
                        conditions,
                    ))
                } else {
                    Ok(AttestKeyTripleRecord::new(environment, key_list, None))
                }
            }
        }

        deserializer.deserialize_seq(AttestKeyTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record describing dependencies between domains and environments
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct DomainDependencyTripleRecord<'a> {
    /// Domain identifier
    pub domain_choice: DomainTypeChoice<'a>,
    /// One or more dependent environments
    pub environment_map: Vec<EnvironmentMap<'a>>,
}

// Need to implement Serialize / Deserialize here.
impl Serialize for DomainDependencyTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.domain_choice)?;
        seq.serialize_element(&self.environment_map)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for DomainDependencyTripleRecord<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DomainDependencyTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for DomainDependencyTripleRecordVisitor<'a> {
            type Value = DomainDependencyTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [DomainTypeChoice, Vec<EnvironmentMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<DomainDependencyTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let domain_choice = seq
                    .next_element::<DomainTypeChoice>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let environment_map = seq
                    .next_element::<Vec<EnvironmentMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(DomainDependencyTripleRecord::new(
                    domain_choice,
                    environment_map,
                ))
            }
        }

        deserializer.deserialize_seq(DomainDependencyTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Types of domain identifiers
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
pub enum DomainTypeChoice<'a> {
    /// Unsigned integer identifier
    Uint(Uint),
    /// Text string identifier
    Text(Text<'a>),
    /// UUID identifier
    Uuid(TaggedUuidType),
    /// Object Identifier (OID)
    Oid(OidType),
    /// Extensions
    Extension(ExtensionValue<'a>),
}

impl DomainTypeChoice<'_> {
    pub fn as_uint(&self) -> Option<Integer> {
        match self {
            Self::Uint(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(value) => Some(value.as_ref().as_ref()),
            _ => None,
        }
    }

    pub fn as_oid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Oid(value) => Some(value.as_ref()),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for DomainTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
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
                                "oid" => Ok(DomainTypeChoice::Oid(OidType::from(
                                    ObjectIdentifier::try_from(value.as_str())
                                        .map_err(|_| de::Error::custom("invalid OID bytes"))?,
                                ))),
                                "uuid" => Ok(DomainTypeChoice::Uuid(TaggedUuidType::from(
                                    UuidType::try_from(value.as_str())
                                        .map_err(|_| de::Error::custom("invalid UUID bytes"))?,
                                ))),
                                s => Err(de::Error::custom(format!(
                                    "unexpected type {s} for DomainTypeChoice"
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
                                Some(u) => Ok(DomainTypeChoice::Extension(ExtensionValue::Tag(
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
                        Ok(DomainTypeChoice::Extension(
                            ExtensionValue::try_from(serde_json::Value::Object(map))
                                .map_err(de::Error::custom)?,
                        ))
                    }
                }
                serde_json::Value::String(s) => Ok(DomainTypeChoice::Text(s.into())),
                serde_json::Value::Number(n) => {
                    if n.is_u64() {
                        Ok(DomainTypeChoice::Uint(n.as_u64().unwrap().into()))
                    } else if n.is_i64() {
                        Ok(DomainTypeChoice::Extension(ExtensionValue::Int(
                            n.as_i64().unwrap().into(),
                        )))
                    } else {
                        Err(de::Error::custom(
                            "floating point DomainTypeChoice extensions not supported",
                        ))
                    }
                }
                value => Ok(DomainTypeChoice::Extension(
                    value.try_into().map_err(de::Error::custom)?,
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
                            Ok(DomainTypeChoice::Oid(OidType::from(oid)))
                        }
                        37 => {
                            let uuid: UuidType =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(DomainTypeChoice::Uuid(TaggedUuidType::from(uuid)))
                        }
                        n => Ok(DomainTypeChoice::Extension(ExtensionValue::Tag(
                            n,
                            Box::new(
                                ExtensionValue::try_from(inner.deref().to_owned())
                                    .map_err(de::Error::custom)?,
                            ),
                        ))),
                    }
                }
                ciborium::Value::Text(s) => Ok(DomainTypeChoice::Text(s.into())),
                ciborium::Value::Integer(i) => {
                    let val: i128 = i.into();
                    if val >= 0 {
                        Ok(DomainTypeChoice::Uint(val.into()))
                    } else {
                        Ok(DomainTypeChoice::Extension(ExtensionValue::Int(val.into())))
                    }
                }
                value => Ok(DomainTypeChoice::Extension(
                    value.try_into().map_err(de::Error::custom)?,
                )),
            }
        }
    }
}

/// Record describing domain membership associations
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct DomainMembershipTripleRecord<'a> {
    /// Domain identifier
    pub domain_choice: DomainTypeChoice<'a>,
    /// One or more member environments
    pub environment_map: Vec<EnvironmentMap<'a>>,
}

impl Serialize for DomainMembershipTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.domain_choice)?;
        seq.serialize_element(&self.environment_map)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for DomainMembershipTripleRecord<'a> {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<DomainMembershipTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DomainMembershipTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for DomainMembershipTripleRecordVisitor<'a> {
            type Value = DomainMembershipTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [DomainTypeChoice, Vec<EnvironmentMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<DomainMembershipTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let domain_choice = seq
                    .next_element::<DomainTypeChoice>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let environment_map = seq
                    .next_element::<Vec<EnvironmentMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(DomainMembershipTripleRecord::new(
                    domain_choice,
                    environment_map,
                ))
            }
        }

        deserializer.deserialize_seq(DomainMembershipTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record linking environments to CoSWID tags
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct CoswidTripleRecord<'a> {
    /// Environment the CoSWID tags belong to
    pub environment_map: EnvironmentMap<'a>,
    /// List of associated CoSWID tag identifiers
    pub coswid_tags: Vec<ConciseSwidTagId<'a>>,
}

impl Serialize for CoswidTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.environment_map)?;
        seq.serialize_element(&self.coswid_tags)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for CoswidTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<CoswidTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoswidTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CoswidTripleRecordVisitor<'a> {
            type Value = CoswidTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [EnvironmentMap, Vec<ConciseSwidTagId>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<CoswidTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment_map = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let coswid_tags = seq
                    .next_element::<Vec<ConciseSwidTagId>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(CoswidTripleRecord::new(environment_map, coswid_tags))
            }
        }

        deserializer.deserialize_seq(CoswidTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record describing a series of conditional endorsements
///
/// This type implements complex endorsement scenarios where measurements
/// may change over time in a defined sequence. The record tracks:
///
/// 1. Initial environment state and measurements
/// 2. Series of allowed measurement changes
/// 3. Required verification at each step
///
/// # Processing Rules
///
/// - Changes must be applied in sequence order
/// - Each change requires matching the selection criteria
/// - New measurements are added only when selections match
/// - Previous measurements remain valid unless replaced
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConditionalEndorsementSeriesTripleRecord<'a> {
    /// Initial environmental condition
    pub condition: StatefulEnvironmentRecord<'a>,
    /// Series of conditional changes
    pub series: Vec<ConditionalSeriesRecord<'a>>,
}

impl Serialize for ConditionalEndorsementSeriesTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.condition)?;
        seq.serialize_element(&self.series)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for ConditionalEndorsementSeriesTripleRecord<'a> {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<ConditionalEndorsementSeriesTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConditionalEndorsementSeriesTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for ConditionalEndorsementSeriesTripleRecordVisitor<'a> {
            type Value = ConditionalEndorsementSeriesTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "A sequence of [StatefulEnvironmentRecord, Vec<ConditionalSeriesRecord>]",
                )
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<ConditionalEndorsementSeriesTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let condition = seq
                    .next_element::<StatefulEnvironmentRecord>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let series = seq
                    .next_element::<Vec<ConditionalSeriesRecord>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ConditionalEndorsementSeriesTripleRecord::new(
                    condition, series,
                ))
            }
        }

        deserializer.deserialize_seq(ConditionalEndorsementSeriesTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record containing environment state and measurement claims
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct StatefulEnvironmentRecord<'a> {
    /// Environment being described
    pub environment: EnvironmentMap<'a>,
    /// List of measurement claims about the environment
    pub claims_list: Vec<MeasurementMap<'a>>,
}

impl Serialize for StatefulEnvironmentRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.environment)?;
        seq.serialize_element(&self.claims_list)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for StatefulEnvironmentRecord<'a> {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<StatefulEnvironmentRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatefulEnvironmentRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for StatefulEnvironmentRecordVisitor<'a> {
            type Value = StatefulEnvironmentRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [EnvironmentMap, [+ MeasurementMap]]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<StatefulEnvironmentRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let claims_list = seq
                    .next_element::<Vec<MeasurementMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(StatefulEnvironmentRecord::new(environment, claims_list))
            }
        }

        deserializer.deserialize_seq(StatefulEnvironmentRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record describing conditional changes to measurements
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConditionalSeriesRecord<'a> {
    /// Measurements that must match for changes to apply
    pub selection: Vec<MeasurementMap<'a>>,
    /// Measurements to add when selection matches
    pub addition: Vec<MeasurementMap<'a>>,
}

impl Serialize for ConditionalSeriesRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.selection)?;
        seq.serialize_element(&self.addition)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for ConditionalSeriesRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<ConditionalSeriesRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConditionalSeriesRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for ConditionalSeriesRecordVisitor<'a> {
            type Value = ConditionalSeriesRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [Vec<MeasurementMap>, Vec<MeasurementMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<ConditionalSeriesRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let selection = seq
                    .next_element::<Vec<MeasurementMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let addition = seq
                    .next_element::<Vec<MeasurementMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ConditionalSeriesRecord::new(selection, addition))
            }
        }

        deserializer.deserialize_seq(ConditionalSeriesRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record containing conditional endorsements
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConditionalEndorsementTripleRecord<'a> {
    /// List of environmental conditions
    pub conditions: Vec<StatefulEnvironmentRecord<'a>>,
    /// List of endorsements that apply when conditions are met
    pub endorsements: Vec<EndorsedTripleRecord<'a>>,
}

impl Serialize for ConditionalEndorsementTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.conditions)?;
        seq.serialize_element(&self.endorsements)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for ConditionalEndorsementTripleRecord<'a> {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<ConditionalEndorsementTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConditionalEndorsementTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for ConditionalEndorsementTripleRecordVisitor<'a> {
            type Value = ConditionalEndorsementTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "A sequence of [Vec<StatefulEnvironmentRecord>, Vec<EndorsedTripleRecord>]",
                )
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<ConditionalEndorsementTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let conditions = seq
                    .next_element::<Vec<StatefulEnvironmentRecord>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let endorsements = seq
                    .next_element::<Vec<EndorsedTripleRecord>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ConditionalEndorsementTripleRecord::new(
                    conditions,
                    endorsements,
                ))
            }
        }

        deserializer.deserialize_seq(ConditionalEndorsementTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(vec)]
mod test {
    use super::*;
    use crate::{
        core::{ExtensionValue, HashAlgorithm},
        test::SerdeTestCase,
    };

    #[test]
    fn test_class_id_json_serde() {
        let class_id_oid = ClassIdTypeChoice::Oid(OidType::try_from("1.2.3.4").unwrap());

        let actual = serde_json::to_string(&class_id_oid).unwrap();

        let expected = r#"{"type":"oid","value":"1.2.3.4"}"#;

        assert_eq!(actual, expected);

        let other: ClassIdTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(class_id_oid, other);

        let class_id_bytes =
            ClassIdTypeChoice::Bytes(Bytes::from(&[0xde, 0xad, 0xbe, 0xef][..]).into());

        let expected = r#"{"type":"bytes","value":"3q2-7w"}"#;

        let actual = serde_json::to_string(&class_id_bytes).unwrap();

        assert_eq!(actual, expected);

        let other: ClassIdTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(class_id_bytes, other);

        let class_id_uuid = ClassIdTypeChoice::Uuid(
            TaggedUuidType::try_from("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        );

        let actual = serde_json::to_string(&class_id_uuid).unwrap();

        let expected = r#"{"type":"uuid","value":"550e8400-e29b-41d4-a716-446655440000"}"#;

        assert_eq!(actual, expected);

        let bad_tag = r#"{"type":"foo","value":"3q2-7w"}"#;

        let err = serde_json::from_str::<ClassIdTypeChoice>(bad_tag)
            .err()
            .unwrap();

        assert_eq!(
            err.to_string(),
            "unexpected type foo for ClassIdTypeChoice".to_string()
        );

        let class_id_ext = ClassIdTypeChoice::Extension(ExtensionValue::Tag(
            600,
            Box::new(ExtensionValue::Bytes([0x01, 0x02, 0x03].as_slice().into())),
        ));

        let actual = serde_json::to_string(&class_id_ext).unwrap();

        let expected = r#"{"tag":600,"value":"AQID"}"#;

        assert_eq!(actual, expected);

        let class_id_ext_de: ClassIdTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(class_id_ext_de, class_id_ext);
    }

    #[test]
    fn test_class_id_cbor_serde() {
        let class_id_oid = ClassIdTypeChoice::Oid(OidType::from(
            ObjectIdentifier::try_from("1.2.3.4").unwrap(),
        ));

        let mut actual: Vec<u8> = Vec::new();
        ciborium::into_writer(&class_id_oid, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xd8, 0x6f, // tag 111
              0x43, // bstr(3)
                0x2a, 0x03, 0x04, // OID bytes
        ];

        assert_eq!(actual, expected);

        let class_id_oid_de: ClassIdTypeChoice =
            ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(class_id_oid_de, class_id_oid);

        let class_id_ext = ClassIdTypeChoice::Extension(ExtensionValue::Tag(
            600,
            Box::new(ExtensionValue::Bytes([0x01, 0x02, 0x03].as_slice().into())),
        ));

        let mut actual: Vec<u8> = Vec::new();
        ciborium::into_writer(&class_id_ext, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xd9, 0x02, 0x58, // tag(600)
              0x43, // bstr(3)
                0x01, 0x02, 0x03,
        ];

        assert_eq!(actual, expected);

        let class_id_ext_de: ClassIdTypeChoice =
            ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(class_id_ext_de, class_id_ext);
    }

    #[test]
    fn test_class_map_serde() {
        let class_map = ClassMap {
            class_id: Some(ClassIdTypeChoice::Oid(OidType::from(
                ObjectIdentifier::try_from("1.2.3.4").unwrap(),
            ))),
            vendor: Some("foo".into()),
            model: Some("bar".into()),
            layer: Some(Integer(1)),
            index: Some(Integer(0)),
        };

        let mut actual: Vec<u8> = Vec::new();
        ciborium::into_writer(&class_map, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0
              0xd8, 0x6f, // value: tag 111
                0x43, // bstr(3)
                  0x2a, 0x03, 0x04, // OID bytes
              0x01, // key: 1
              0x63, // value: tstr(3)
                0x66, 0x6f, 0x6f, // "foo"
              0x02, // key: 2
              0x63, // value: tstr(3)
                0x62, 0x61, 0x72, // "bar"
              0x03, // key: 3
              0x01, // value: 1
              0x04, // key: 4
              0x00, // value: 0
            0xff, // break
        ];

        assert_eq!(actual, expected);

        let class_map_de: ClassMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(class_map_de, class_map);

        let expected = r#"{"class-id":{"type":"oid","value":"1.2.3.4"},"vendor":"foo","model":"bar","layer":1,"index":0}"#;
        let actual = serde_json::to_string(&class_map).unwrap();

        assert_eq!(actual, expected);

        let class_map_de: ClassMap = serde_json::from_str(expected).unwrap();

        assert_eq!(class_map_de, class_map);

        let class_map = ClassMap {
            class_id: None,
            vendor: Some("foo".into()),
            model: None,
            layer: Some(Integer(1)),
            index: None,
        };

        let mut actual: Vec<u8> = Vec::new();
        ciborium::into_writer(&class_map, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xbf, // map(indef)
              0x01, // key: 1
              0x63, // value: tstr(3)
                0x66, 0x6f, 0x6f, // "foo"
              0x03, // key: 3
              0x01, // value: 1
            0xff, // break
        ];

        assert_eq!(actual, expected);

        let class_map_de: ClassMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(class_map_de, class_map);

        let expected = r#"{"vendor":"foo","layer":1}"#;
        let actual = serde_json::to_string(&class_map).unwrap();

        assert_eq!(actual, expected);

        let class_map_de: ClassMap = serde_json::from_str(expected).unwrap();

        assert_eq!(class_map_de, class_map);
    }

    #[test]
    fn test_group_id_serde() {
        let uuid_bytes: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];

        let expected = r#"{"type":"uuid","value":"550e8400-e29b-41d4-a716-446655440000"}"#;

        let group_id = GroupIdTypeChoice::Uuid(TaggedUuidType::from(uuid_bytes));

        let actual = serde_json::to_string(&group_id).unwrap();

        assert_eq!(&actual, expected);

        let group_id_de: GroupIdTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(group_id_de, group_id);

        let expected: Vec<u8> = vec![
            0xd8, 0x25, // tag(37)
              0x50, // bstr(16)
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
                0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
        ];

        let mut actual: Vec<u8> = Vec::new();
        ciborium::into_writer(&group_id, &mut actual).unwrap();

        assert_eq!(actual, expected);

        let group_id_de: GroupIdTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(group_id_de, group_id);
    }

    #[test]
    fn test_crypo_key_type_choice_serde() {
        let thumbprint_bytes = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let crypto_key = CryptoKeyTypeChoice::Thumbprint(ThumbprintType::from(Digest {
            alg: HashAlgorithm::Sha384,
            val: Bytes::from(thumbprint_bytes.to_vec()),
        }));

        let expected: Vec<u8> = vec![
            0xd9, 0x02, 0x2d, // tag(557)
              0x82, // array(2)
                0x07,  // 7 [SHA-384]
                0x48, // bstr(8)
                  0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        ];

        let mut buffer: Vec<u8> = vec![];

        ciborium::into_writer(&crypto_key, &mut buffer).unwrap();

        assert_eq!(buffer, expected);

        let crypto_key_de: CryptoKeyTypeChoice =
            ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(crypto_key_de, crypto_key);

        let actual = serde_json::to_string(&crypto_key).unwrap();

        let expected = r#"{"type":"thumbprint","value":"sha-384;ECAwQFBgcIA"}"#;

        assert_eq!(actual, expected);

        let crypto_key_de: CryptoKeyTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(crypto_key_de, crypto_key);
    }

    #[test]
    fn test_environment_map_serde() {
        let class_map = ClassMapBuilder::default()
            .class_id(ClassIdTypeChoice::Oid(OidType::from(
                ObjectIdentifier::try_from("1.2.3.4").unwrap(),
            )))
            .build()
            .unwrap();

        let thumbprint_bytes = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let instance_id = InstanceIdTypeChoice::CryptoKey(CryptoKeyTypeChoice::Thumbprint(
            ThumbprintType::from(Digest {
                alg: HashAlgorithm::Sha384,
                val: Bytes::from(thumbprint_bytes.to_vec()),
            }),
        ));

        let uuid_bytes: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        let group_id = GroupIdTypeChoice::Uuid(TaggedUuidType::from(uuid_bytes));

        let env_map = EnvironmentMapBuilder::default()
            .class(class_map)
            .instance(instance_id.clone())
            .group(group_id)
            .build()
            .unwrap();

        let expected: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [class]
              0xbf, // value: map(indef)
                0x00, // key: 0 [class_id]
                0xd8, 0x6f, // value: tag 111
                  0x43, // bstr(3)
                    0x2a, 0x03, 0x04, // OID bytes
              0xff, // break
              0x01, // key: 1 [instance]
              0xd9, 0x02, 0x2d, // value: tag(557)
                0x82, // array(2)
                  0x07, // 7 [SHA-384]
                  0x48, // bstr(8)
                    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
              0x02, // key: 2 [group]
              0xd8, 0x25, // value: tag(37)
                0x50, // bstr(16)
                  0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
                  0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
            0xff, // break
        ];

        let mut buffer: Vec<u8> = vec![];
        ciborium::into_writer(&env_map, &mut buffer).unwrap();

        assert_eq!(buffer, expected);

        let env_map_de: EnvironmentMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(env_map_de, env_map);

        let expected = r#"{"class":{"class-id":{"type":"oid","value":"1.2.3.4"}},"instance":{"type":"thumbprint","value":"sha-384;ECAwQFBgcIA"},"group":{"type":"uuid","value":"550e8400-e29b-41d4-a716-446655440000"}}"#;

        let json = serde_json::to_string(&env_map).unwrap();

        assert_eq!(json, expected);

        let env_map_de: EnvironmentMap = serde_json::from_str(expected).unwrap();

        assert_eq!(env_map_de, env_map);

        let env_map = EnvironmentMapBuilder::default()
            .instance(instance_id)
            .build()
            .unwrap();

        let expected: Vec<u8> = vec![
            0xbf, // map(indef)
              0x01, // key: 1 [instance]
              0xd9, 0x02, 0x2d, // value: tag(557)
                0x82, // array(2)
                  0x07, // 7 [SHA-384]
                  0x48, // bstr(8)
                    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0xff, // break
        ];

        let mut buffer: Vec<u8> = vec![];
        ciborium::into_writer(&env_map, &mut buffer).unwrap();

        assert_eq!(buffer, expected);

        let env_map_de: EnvironmentMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(env_map_de, env_map);

        let expected = r#"{"instance":{"type":"thumbprint","value":"sha-384;ECAwQFBgcIA"}}"#;

        let json = serde_json::to_string(&env_map).unwrap();

        assert_eq!(json, expected);

        let env_map_de: EnvironmentMap = serde_json::from_str(expected).unwrap();

        assert_eq!(env_map_de, env_map);
    }

    mod integ_regs {
        use super::super::*;
        use crate::core::*;

        #[test]
        fn test_add_replace_check() {
            let mut regs = IntegrityRegisters::default();

            assert!(regs.is_empty());
            assert_eq!(regs.len(), 0);

            regs.add_digest(
                1.into(),
                Digest::new(HashAlgorithm::Sha256, [1, 2, 3].as_ref().into()),
            )
            .unwrap();

            regs.add_digest(
                "1".into(), // "1" is different from 1
                Digest::new(HashAlgorithm::Sha256, [4, 5, 6].as_ref().into()),
            )
            .unwrap();

            let err = regs
                .add_digest(
                    1.into(),
                    Digest::new(HashAlgorithm::Sha256, [7, 8, 9].as_ref().into()),
                )
                .err()
                .unwrap()
                .to_string();

            assert_eq!(err, "sha-256 digest for label 1 already exists");

            regs.add_digest(
                1.into(), // OK because alg is different
                Digest::new(HashAlgorithm::Sha384, [7, 8, 9].as_ref().into()),
            )
            .unwrap();

            let old = regs
                .replace_digest(
                    1.into(),
                    Digest::new(HashAlgorithm::Sha256, [10, 11, 12].as_ref().into()),
                )
                .unwrap();

            assert_eq!(
                old,
                Digest::new(HashAlgorithm::Sha256, [1, 2, 3].as_ref().into())
            );

            assert_eq!(regs.len(), 2);

            assert!(regs.check(
                &1.into(),
                Digest::new(HashAlgorithm::Sha256, [10, 11, 12].as_ref().into()),
            ));

            assert!(!regs.check(
                &1.into(),
                Digest::new(HashAlgorithm::Sha256, [1, 2, 3].as_ref().into()),
            ));

            assert!(!regs.check(
                &2.into(),
                Digest::new(HashAlgorithm::Sha256, [10, 11, 12].as_ref().into()),
            ));
        }

        #[test]
        fn test_serde() {
            let mut regs = IntegrityRegisters::default();

            assert!(regs.is_empty());
            assert_eq!(regs.len(), 0);

            regs.add_digest(
                1.into(),
                Digest::new(HashAlgorithm::Sha256, [1, 2, 3].as_ref().into()),
            )
            .unwrap();

            regs.add_digest(
                "foo".into(),
                Digest::new(HashAlgorithm::Sha256, [4, 5, 6].as_ref().into()),
            )
            .unwrap();

            let mut buffer: Vec<u8> = vec![];
            ciborium::into_writer(&regs, &mut buffer).unwrap();

            let expected: Vec<u8> = vec![
                0xa2, // map(2)
                  0x63, // key: tstr(3)
                    0x66, 0x6f, 0x6f, // "foo"
                  0x81, // value: array(1)
                    0x82, // array(2)
                      0x01, // 1 [sha-256]
                      0x43, // bstr(3)
                        0x04, 0x05, 0x06,
                  0x01, // key: 1
                  0x81, // value: array(1)
                    0x82, // array(2)
                      0x01, // 1 [sha-256]
                      0x43, // bstr(3)
                        0x01, 0x02, 0x03
            ];

            assert_eq!(buffer, expected);

            let regs_de: IntegrityRegisters = ciborium::from_reader(expected.as_slice()).unwrap();

            assert_eq!(regs_de, regs);

            regs.add_digest(
                "1".into(),
                Digest::new(HashAlgorithm::Sha256, [1, 2, 3].as_ref().into()),
            )
            .unwrap();

            let expected =
                r#"{"\"1\"":["sha-256;AQID"],"\"foo\"":["sha-256;BAUG"],"1":["sha-256;AQID"]}"#;

            let json = serde_json::to_string(&regs).unwrap();

            assert_eq!(json, expected);

            let regs_de: IntegrityRegisters = serde_json::from_str(&json).unwrap();

            assert_eq!(regs_de, regs);
        }
    }

    #[test]
    fn test_ip_addr_serde() {
        let addr = IpAddrTypeChoice::Ipv4([127, 0, 0, 1]);

        let json = serde_json::to_string(&addr).unwrap();

        assert_eq!("\"127.0.0.1\"", json);

        let addr_de: IpAddrTypeChoice = serde_json::from_str(&json).unwrap();

        assert_eq!(addr_de, addr);

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&addr, &mut actual).unwrap();

        let expected = vec![
            0x44, // bstr(4),
              0x7f, 0x00, 0x00, 0x01,
        ];

        assert_eq!(actual, expected);

        let addr_de: IpAddrTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(addr_de, addr);

        let addr = IpAddrTypeChoice::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let json = serde_json::to_string(&addr).unwrap();

        assert_eq!("\"::1\"", json);

        let addr_de: IpAddrTypeChoice = serde_json::from_str(&json).unwrap();

        assert_eq!(addr_de, addr);

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&addr, &mut actual).unwrap();

        let expected = vec![
            0x50, // bstr(16),
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        assert_eq!(actual, expected);

        let addr_de: IpAddrTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(addr_de, addr);
    }

    #[test]
    fn test_mac_addr_serde() {
        let addr = MacAddrTypeChoice::Eui48Addr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        let json = serde_json::to_string(&addr).unwrap();

        assert_eq!("\"01-02-03-04-05-06\"", json);

        let addr_de: MacAddrTypeChoice = serde_json::from_str(&json).unwrap();

        assert_eq!(addr_de, addr);

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&addr, &mut actual).unwrap();

        let expected = vec![
            0x46, // bstr(6),
              0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        ];

        assert_eq!(actual, expected);

        let addr_de: MacAddrTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(addr_de, addr);

        let addr = MacAddrTypeChoice::Eui64Addr([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x20]);

        let json = serde_json::to_string(&addr).unwrap();

        assert_eq!("\"0A-0B-0C-0D-0E-0F-10-20\"", json);

        let addr_de: MacAddrTypeChoice = serde_json::from_str(&json).unwrap();

        assert_eq!(addr_de, addr);

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&addr, &mut actual).unwrap();

        let expected = vec![
            0x48, // bstr(8),
              0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x20,
        ];

        assert_eq!(actual, expected);

        let addr_de: MacAddrTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(addr_de, addr);
    }

    #[test]
    fn test_flags_map_serde() {
        let fm = FlagsMap {
            is_configured: Some(true),
            is_secure: Some(false),
            is_recovery: Some(true),
            is_debug: Some(false),
            is_replay_protected: Some(true),
            is_integrity_protected: Some(false),
            is_runtime_meas: Some(true),
            is_immutable: Some(false),
            is_tcb: Some(true),
            is_confidentiality_protected: Some(false),
            extensions: None,
        };

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&fm, &mut actual).unwrap();

        let expected = vec![
            0xbf, // map(indef)
              0x00, // key: 0
              0xf5, // value: true
              0x01, // key: 1
              0xf4, // value: false
              0x02, // key: 2
              0xf5, // value: true
              0x03, // key: 3
              0xf4, // value: false
              0x04, // key: 4
              0xf5, // value: true
              0x05, // key: 5
              0xf4, // value: false
              0x06, // key: 6
              0xf5, // value: true
              0x07, // key: 7
              0xf4, // value: false
              0x08, // key: 8
              0xf5, // value: true
              0x09, // key: 9
              0xf4, // value: false
            0xff, // break
        ];

        assert_eq!(actual, expected);

        let fm_de: FlagsMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(fm_de, fm);

        let json = serde_json::to_string(&fm).unwrap();

        let expected = r#"{"is-configured":true,"is-secure":false,"is-recovery":true,"is-debug":false,"is-replay-protected":true,"is-integrity-protected":false,"is-runtime-meas":true,"is-immutable":false,"is-tcb":true,"is-confidentiality-protected":false}"#;

        assert_eq!(json, expected);

        let fm_de: FlagsMap = serde_json::from_str(expected).unwrap();

        assert_eq!(fm_de, fm);

        let fm = FlagsMap {
            is_configured: Some(true),
            is_secure: None,
            is_recovery: None,
            is_debug: None,
            is_replay_protected: None,
            is_integrity_protected: None,
            is_runtime_meas: None,
            is_immutable: None,
            is_tcb: None,
            is_confidentiality_protected: None,
            extensions: Some(ExtensionMap(BTreeMap::from([(
                Integer(-1),
                ExtensionValue::Bool(true),
            )]))),
        };

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&fm, &mut actual).unwrap();

        let expected = vec![
            0xbf, // map(indef)
              0x00, // key: 0
              0xf5, // value: true
              0x20, // key: -1
              0xf5, // value: true
            0xff, // break
        ];

        assert_eq!(actual, expected);

        let fm_de: FlagsMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(fm_de, fm);

        let json = serde_json::to_string(&fm).unwrap();

        let expected = r#"{"is-configured":true,"-1":true}"#;

        assert_eq!(json, expected);

        let fm_de: FlagsMap = serde_json::from_str(expected).unwrap();

        assert_eq!(fm_de, fm);
    }

    #[test]
    fn test_svn_type_choice_serde() {
        let svn = SvnTypeChoice::Svn(1.into());

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&svn, &mut actual).unwrap();

        let expected = vec![
            0x01 // 1
        ];

        assert_eq!(actual, expected);

        let svn_de: SvnTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(svn_de, svn);

        let json = serde_json::to_string(&svn).unwrap();

        assert_eq!(json, "1");

        let svn_de: SvnTypeChoice = serde_json::from_str("1").unwrap();

        assert_eq!(svn_de, svn);

        let svn = SvnTypeChoice::TaggedSvn(SvnType::from(Integer(1)));

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&svn, &mut actual).unwrap();

        let expected = vec![
            0xd9, 0x02, 0x28, // tag(552)
              0x01 // 1
        ];

        assert_eq!(actual, expected);

        let svn_de: SvnTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(svn_de, svn);

        let json = serde_json::to_string(&svn).unwrap();

        let expected = r#"{"type":"svn","value":1}"#;

        assert_eq!(json, expected);

        let svn_de: SvnTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(svn_de, svn);

        let svn = SvnTypeChoice::TaggedMinSvn(MinSvnType::from(Integer(1)));

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&svn, &mut actual).unwrap();

        let expected = vec![
            0xd9, 0x02, 0x29, // tag(553)
              0x01 // 1
        ];

        assert_eq!(actual, expected);

        let svn_de: SvnTypeChoice = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(svn_de, svn);

        let json = serde_json::to_string(&svn).unwrap();

        let expected = r#"{"type":"min-svn","value":1}"#;

        assert_eq!(json, expected);

        let svn_de: SvnTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(svn_de, svn);
    }

    #[test]
    fn test_version_map_serde() {
        let vm = VersionMap {
            version: "1.2.3a".into(),
            version_scheme: Some(VersionScheme::MultipartnumericSuffix),
        };

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&vm, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [version]
              0x66, // value: tstr(6)
                0x31, 0x2e, 0x32, 0x2e, 0x33, 0x61, // "1.2.3a"
              0x01, // key: 1 [version-scheme]
              0x02, // value: 2 [multipartnumeric+suffix]
            0xff, // break
        ];

        assert_eq!(actual, expected);

        let vm_de: VersionMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(vm_de, vm);

        let actual = serde_json::to_string(&vm).unwrap();

        let expected = r#"{"version":"1.2.3a","version-scheme":"multipartnumeric+suffix"}"#;

        assert_eq!(actual, expected);

        let vm_de: VersionMap = serde_json::from_str(expected).unwrap();

        assert_eq!(vm_de, vm);
    }

    #[test]
    fn test_measurement_values_map_serde() {
        let mvm = MeasurementValuesMap {
            version: Some(VersionMap {
                version: "1.2".into(),
                version_scheme: Some(VersionScheme::Decimal),
            }),
            svn: Some(SvnTypeChoice::Svn(Integer(1))),
            digests: Some(vec![Digest{
                alg: HashAlgorithm::Sha256,
                val: Bytes::from(vec![0x01, 0x02, 0x03]),
            }]),
            flags: {
                let mut fm = FlagsMap::default();
                fm.is_configured = Some(true);
                Some(fm)
            },
            raw: Some(RawValueType {
                raw_value: RawValueTypeChoice::TaggedBytes(TaggedBytes::from(Bytes::from(
                    vec![0x04,0x05,0x06],
                ))),
                raw_value_mask: None,
            }),
            mac_addr: Some(MacAddrTypeChoice::Eui48Addr([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            ])),
            ip_addr: Some(IpAddrTypeChoice::Ipv4([0x7f, 0x00, 0x00, 0x01])),
            serial_number: Some(Text::from("foo")),
            ueid: Some(
                UeidType::try_from(vec![
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ])
                .unwrap(),
            ),
            uuid: Some(UuidType::from([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ])),
            name: Some(Text::from("bar")),
            cryptokeys: Some(
                vec![CryptoKeyTypeChoice::Thumbprint(ThumbprintType::from(Digest {
                alg: HashAlgorithm::Sha384,
                val: Bytes::from(vec![0x07, 0x08, 0x09]),
            }))],
            ),
            integrity_registers: {
                let mut regs = IntegrityRegisters::default();
                regs.add_digest(
                    1.into(),
                    Digest::new(HashAlgorithm::Sha256, [1, 2, 3].as_ref().into()),
                )
                .unwrap();
                Some(regs)
            },
            extensions: Some(ExtensionMap(BTreeMap::from([(
                Integer(-1),
                ExtensionValue::Bytes(Bytes::from(vec![0x0a, 0x0b, 0x0c])),
            )]))),
        };

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&mvm, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [version]
              0xbf, // value: map(indef)
                0x00,  // key: 0 [version]
                0x63,  // value: tstr(3)
                  0x31, 0x2e, 0x32, // "1.2"
                0x01, // key: 1 [version-scheme]
                0x04, // value: 4 [decimal]
              0xff, // break
              0x01, // key: 1 [svn]
              0x01, // value: 1
              0x02, // key: 2 [digests]
              0x81, // value: array(1)
                0x82, // array(2)
                  0x01, // 1 [sha-256]
                  0x43, // bstr(3)
                    0x01, 0x02, 0x03,
              0x03, // key: 3 [flags]
              0xbf, // value: map(indef)
                0x00, // key: 0 [is-configured]
                0xf5, // value: true
              0xff, // break
              0x04, // key: 4 [raw-value]
              0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                0x43, // bstr(3)
                  0x04, 0x05, 0x06,
              0x06, // key: 6 [mac-addr]
              0x46, // value: bstr(6),
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
              0x07, // key: 7 [ip-addr]
              0x44, // value: bstr(4),
                0x7f, 0x00, 0x00, 0x01,
              0x08, // key: 8 [serial-number]
              0x63, // value: tstr(3)
                0x66, 0x6f, 0x6f, // "foo"
              0x09, // key: 9 [ueid]
              0x47, // value: bstr(7),
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
              0x0a, // key: 10 [uuid]
              0x50, // value: bstr(16),
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
              0x0b, // key: 11 [name]
              0x63, // value: tstr(3)
                0x62, 0x61, 0x72, // "bar"
              0x0d, // key: 13 [cryptokeys]
              0x81, // value: array(1)
                0xd9, 0x02, 0x2d, // tag(557) [thumbprint]
                  0x82, // array(2)
                    0x07, // 7 [sha-384]
                    0x43, // bstr(3)
                      0x07, 0x08, 0x09,
              0x0e, // key: 14 [integrity-registers]
              0xa1, // value: map(1)
                0x01, // key: 1
                0x81, // value: array(1)
                  0x82, // array(2)
                    0x01, // 1 [sha-256]
                    0x43, // bstr(3)
                      0x01, 0x02, 0x03,
              0x20, // key: -1 
              0x43, // value: bstr(3),
                0x0a, 0x0b, 0x0c,
            0xff, // break
        ];

        assert_eq!(actual, expected);

        let mvm_de: MeasurementValuesMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(mvm_de, mvm);

        let actual = serde_json::to_string(&mvm).unwrap();

        let expected = r#"{"version":{"version":"1.2","version-scheme":"decimal"},"svn":1,"digests":["sha-256;AQID"],"flags":{"is-configured":true},"raw-value":{"type":"bytes","value":"BAUG"},"mac-addr":"01-02-03-04-05-06","ip-addr":"127.0.0.1","serial-number":"foo","ueid":"AQIDBAUGBw","uuid":"01020304-0506-0708-090a-0b0c0d0e0f10","name":"bar","cryptokeys":[{"type":"thumbprint","value":"sha-384;BwgJ"}],"integrity-registers":{"1":["sha-256;AQID"]},"-1":"CgsM"}"#;

        assert_eq!(actual, expected);

        let mvm_de: MeasurementValuesMap = serde_json::from_str(expected).unwrap();

        assert_eq!(mvm_de, mvm);
    }

    #[test]
    fn test_measured_element_type_choice_serde() {
        let metc = MeasuredElementTypeChoice::UInt(Integer(1));

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&metc, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0x01, // 1
        ];

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice =
            ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(metc_de, metc);

        let actual = serde_json::to_string(&metc).unwrap();

        let expected = "1";

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(metc_de, metc);

        let metc = MeasuredElementTypeChoice::Tstr("foo".into());

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&metc, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0x63, // tstr(3)
              0x66, 0x6f, 0x6f, // "foo"
        ];

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice =
            ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(metc_de, metc);

        let actual = serde_json::to_string(&metc).unwrap();

        let expected = "\"foo\"";

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(metc_de, metc);

        let metc = MeasuredElementTypeChoice::Oid(
            OidType::try_from([0x55, 0x04, 0x03].as_slice()).unwrap(),
        );

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&metc, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xd8, 0x6f, // tag(111)
              0x43, // bstr(3)
                0x55, 0x04, 0x03,
        ];

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice =
            ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(metc_de, metc);

        let actual = serde_json::to_string(&metc).unwrap();

        let expected = r#"{"type":"oid","value":"2.5.4.3"}"#;

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(metc_de, metc);

        let metc = MeasuredElementTypeChoice::Uuid(
            TaggedUuidType::try_from(
                [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10,
                ]
                .as_slice(),
            )
            .unwrap(),
        );

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&metc, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xd8, 0x25, // tag(37)
              0x50, // bstr(16)
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice =
            ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(metc_de, metc);

        let actual = serde_json::to_string(&metc).unwrap();

        let expected = r#"{"type":"uuid","value":"01020304-0506-0708-090a-0b0c0d0e0f10"}"#;

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(metc_de, metc);

        let metc = MeasuredElementTypeChoice::Extension(ExtensionValue::Tag(
            1337,
            Box::new(ExtensionValue::Text("test value".into())),
        ));

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&metc, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xd9, 0x05, 0x39, // tag(1337)
              0x6a, // tstr(10)
                0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x61, 0x6c, // "test val"
                0x75, 0x65,                                     // "ue"
        ];

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice =
            ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(metc_de, metc);

        let actual = serde_json::to_string(&metc).unwrap();

        let expected = r#"{"tag":1337,"value":"test value"}"#;

        assert_eq!(actual, expected);

        let metc_de: MeasuredElementTypeChoice = serde_json::from_str(expected).unwrap();

        assert_eq!(metc_de, metc);
    }

    #[test]
    fn test_measurement_map_serde() {
        let mm = MeasurementMap {
            mkey: Some(MeasuredElementTypeChoice::UInt(Integer(1))),
            mval: MeasurementValuesMapBuilder::default()
                .name("foo".into())
                .build()
                .unwrap(),
            authorized_by: Some(vec![CryptoKeyTypeChoice::Bytes(
                TaggedBytes::from([0x01, 0x02, 0x03].as_slice())
            )]),
        };

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&mm, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [mkey]
              0x01, // value: 1
              0x01, // key: 1 [mval]
              0xbf, // value: map(indef)
                0x0b, // key: 11 [name]
                0x63, // value: tstr(3)
                 0x66, 0x6f, 0x6f, // "foo"
              0xff, // break
              0x02, // key: 2 [authorized-by]
              0x81, // value: array(1)
                0xd9, 0x02, 0x30, // tag(560) [tagged-bytes]
                  0x43, // bstr(3)
                    0x01, 0x02, 0x03,
            0xff, // break
        ];

        assert_eq!(actual, expected);

        let mm_de: MeasurementMap = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(mm_de, mm);

        let actual = serde_json::to_string(&mm).unwrap();

        let expected =
            r#"{"mkey":1,"mval":{"name":"foo"},"authorized-by":[{"type":"bytes","value":"AQID"}]}"#;

        assert_eq!(actual, expected);

        let mm_de: MeasurementMap = serde_json::from_str(expected).unwrap();

        assert_eq!(mm_de, mm);
    }

    #[test]
    fn test_domain_type_choice_serde() {
        let test_cases = vec! [
            SerdeTestCase{
                value: DomainTypeChoice::Uint(1.into()),
                expected_cbor: vec![0x01],
                expected_json: "1",
            },
            SerdeTestCase{
                value: DomainTypeChoice::Text("foo".into()),
                expected_cbor: vec![
                    0x63, // tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                ],
                expected_json: "\"foo\"",
            },
            SerdeTestCase{
                value: DomainTypeChoice::Oid("1.2.3.4".try_into().unwrap()),
                expected_cbor: vec![
                    0xd8, 0x6f, // tag(111) [oid]
                      0x43, // bstr(3)
                        0x2a, 0x03, 0x04, // OID bytes
                ],
                expected_json: r#"{"type":"oid","value":"1.2.3.4"}"#,
            },
            SerdeTestCase{
                value: DomainTypeChoice::Uuid("550e8400-e29b-41d4-a716-446655440000".try_into().unwrap()),
                expected_cbor: vec![
                    0xd8, 0x25, // tag(37) [uuid]
                      0x50, // bstr(16)
                        0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, // UUID bytes
                        0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
                ],
                expected_json: r#"{"type":"uuid","value":"550e8400-e29b-41d4-a716-446655440000"}"#,
            },
            SerdeTestCase{
                value: DomainTypeChoice::Extension(
                    ExtensionValue::Tag(1337, Box::new(ExtensionValue::Bool(true))),
                ),
                expected_cbor: vec![
                    0xd9, 0x05, 0x39, // tag(1337)
                      0xf5, // true
                ],
                expected_json: r#"{"tag":1337,"value":true}"#,
            }
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }
}
