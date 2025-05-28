// SPDX-License-Identifier: MIT

//! Concise Module Identifier (CoMID) Implementation
//!
//! This module implements the CoMID (Concise Module Identifier) data structure as defined in the
//! IETF CoRIM specification. CoMID provides a structured way to identify and describe software
//! modules using CBOR-encoded tags.
//!
//! # Key Components
//!
//! * [`ConciseMidTag`] - The main CoMID structure, tagged with CBOR tag 506
//! * [`TagIdentityMap`] - Identification information for a tag
//! * [`ComidEntityMap`] - Information about entities associated with the tag
//! * [`TriplesMap`] - Collection of triples describing module characteristics
//!
//! # Example
//!
//! Creating a basic CoMID tag with entity and identity information:
//!
//! ```rust
//! use corim_rs::{
//!     comid::{
//!         ConciseMidTag, TagIdentityMap, ComidEntityMap, TriplesMap,
//!         TagIdTypeChoice, ComidRoleTypeChoice
//!     },
//!     numbers::Integer,
//!     core::{Text, Tstr},
//! };
//!
//! // Create a tag identity
//! let tag_identity = TagIdentityMap {
//!     tag_id: TagIdTypeChoice::Tstr(Tstr::from("example-tag-id")),
//!     tag_version: Some(Integer(1u32.into())),
//! };
//!
//! // Create an entity
//! let entity = ComidEntityMap {
//!     entity_name: Text::from("Example Corp"),
//!     reg_id: None,
//!     role: vec![ComidRoleTypeChoice::TagCreator],
//!     extensions: None,
//! };
//!
//! // Create an empty triples map
//! let triples = TriplesMap {
//!     reference_triples: None,
//!     endorsed_triples: None,
//!     identity_triples: None,
//!     attest_key_triples: None,
//!     dependency_triples: None,
//!     membership_triples: None,
//!     coswid_triples: None,
//!     conditional_endorsement_series_triples: None,
//!     conditional_endorsement_triples: None,
//!     extensions: None,
//! };
//!
//! // Create the CoMID tag
//! let comid = ConciseMidTag {
//!     language: None,
//!     tag_identity,
//!     entities: Some(vec![entity].into()),
//!     linked_tags: None,
//!     triples,
//!     extensions: None,
//! };
//! ```
//!
//! # Features
//!
//! * CBOR-based serialization using tag 506
//! * Support for multiple entity roles
//! * Extensible triple records for various module characteristics
//! * Optional language support
//! * Linking between related tags
//!
//! # Architecture
//!
//! The module is structured around the main [`ConciseMidTag`] type, which contains:
//!
//! 1. Tag identity information via [`TagIdentityMap`]
//! 2. Associated entities via [`ComidEntityMap`]
//! 3. Optional links to related tags via [`LinkedTagMap`]
//! 4. Triple records describing the module via [`TriplesMap`]
//!
//! All components support optional extensions through [`ExtensionMap`] for future expandability.

use crate::{
    core::{RawValueType, TaggedBytes},
    generate_tagged,
    triples::{EnvironmentMap, MeasuredElementTypeChoice, MeasurementMap, MeasurementValuesMap},
    AttestKeyTripleRecord, ComidError, ConditionalEndorsementSeriesTripleRecord,
    ConditionalEndorsementTripleRecord, CoswidTripleRecord, DomainDependencyTripleRecord,
    DomainMembershipTripleRecord, Empty as _, EndorsedTripleRecord, ExtensionMap, ExtensionValue,
    IdentityTripleRecord, Integer, ReferenceTripleRecord, Result, Text, Tstr, Uint, Uri, UuidType,
};
use derive_more::{Constructor, From, TryFrom};
use serde::{
    de::{self, Visitor},
    ser::SerializeMap,
    Deserialize, Serialize,
};
use std::{borrow::Cow, fmt::Display, marker::PhantomData};

/// A tag version number represented as an unsigned integer
pub type TagVersionType = Uint;

generate_tagged!((
    506,
    TaggedConciseMidTag,
    ConciseMidTag<'a>,
    'a,
    "comid",
    "A Concise Module Identifier (CoMID) structured tag"
),);
/// A Concise Module Identifier (CoMID) tag structure tagged with CBOR tag 506
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConciseMidTag<'a> {
    /// Optional language identifier for the tag content
    pub language: Option<Text<'a>>,
    /// Identity information for this tag
    pub tag_identity: TagIdentityMap<'a>,
    /// List of entities associated with this tag
    pub entities: Option<Vec<ComidEntityMap<'a>>>,
    /// Optional references to other related tags
    pub linked_tags: Option<Vec<LinkedTagMap<'a>>>,
    /// Collection of triples describing the module
    pub triples: TriplesMap<'a>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl<'a> ConciseMidTag<'a> {
    /// Creates a new default ConciseMidTag instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::comid::ConciseMidTag;
    /// use corim_rs::comid::TagIdentityMap;
    /// use corim_rs::comid::TagIdTypeChoice;
    /// use corim_rs::core::Tstr;
    ///
    /// let mut comid = ConciseMidTag::default();
    ///
    /// // Set required tag identity
    /// comid.tag_identity = TagIdentityMap {
    ///     tag_id: TagIdTypeChoice::Tstr(Tstr::from("example-id")),
    ///     tag_version: Some(1),
    /// };
    /// ```
    ///
    /// Adds a reference value to the CoMID tag's reference triples.
    ///
    /// This method serializes the provided value to CBOR bytes and adds it as a raw measurement value
    /// within a reference triple. If a reference triple with the same environment already exists,
    /// the measurement is added to that triple. Otherwise, a new reference triple is created.
    ///
    /// # Arguments
    ///
    /// * `environment` - The environment map that describes the context for this reference value
    /// * `mkey` - Measurement element type that identifies what is being measured
    /// * `value` - The value to serialize and store as the reference value
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if successful, or an `std::io::Error` if serialization fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::{
    ///     comid::{ConciseMidTag, TagIdentityMap, TagIdTypeChoice},
    ///     triples::{EnvironmentMap, MeasuredElementTypeChoice},
    /// };
    /// use corim_rs::core::Tstr;
    ///
    /// let mut comid = ConciseMidTag::default();
    /// comid.tag_identity = TagIdentityMap {
    ///     tag_id: TagIdTypeChoice::Tstr(Tstr::from("example-id")),
    ///     tag_version: Some(1),
    /// };
    ///
    /// // Add a reference value
    /// let env = EnvironmentMap::default();
    /// let mkey = MeasuredElementTypeChoice::from("measured-component");
    /// let reference_data = "example reference value";
    /// comid.add_reference_raw_value(&env, mkey, &reference_data)
    ///     .expect("Failed to add reference value");
    /// ```
    pub fn add_reference_raw_value<T>(
        &mut self,
        environment: &EnvironmentMap<'a>,
        mkey: MeasuredElementTypeChoice<'a>,
        value: &T,
    ) -> std::io::Result<()>
    where
        T: ?Sized + Serialize,
    {
        let mut raw_bytes = vec![];
        ciborium::into_writer(value, &mut raw_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let raw_value = TaggedBytes::new(raw_bytes.into());

        let measurement = MeasurementMap {
            mkey: Some(mkey),
            mval: MeasurementValuesMap {
                raw: Some(RawValueType {
                    raw_value: raw_value.into(),
                    raw_value_mask: None,
                }),
                ..Default::default()
            },
            authorized_by: None,
        };

        match &mut self.triples.reference_triples {
            None => {
                let new_record = ReferenceTripleRecord {
                    ref_env: environment.clone(),
                    ref_claims: vec![measurement],
                };
                self.triples.reference_triples = Some(vec![new_record]);
            }
            Some(vec) => {
                if let Some(record) = vec.iter_mut().find(|r| r.ref_env == *environment) {
                    record.ref_claims.push(measurement);
                } else {
                    let new_record = ReferenceTripleRecord {
                        ref_env: environment.clone(),
                        ref_claims: vec![measurement],
                    };
                    vec.push(new_record);
                }
            }
        }
        Ok(())
    }
    /// Adds an endorsement value to the CoMID tag's endorsed triples.
    ///
    /// This method serializes the provided value to CBOR bytes and adds it as a raw measurement value
    /// within an endorsed triple. If an endorsed triple with the same environment already exists,
    /// the measurement is added to that triple. Otherwise, a new endorsed triple is created.
    ///
    /// Endorsed triples represent expected measurements that should be used to validate
    /// actual measurements during verification.
    ///
    /// # Arguments
    ///
    /// * `environment` - The environment map that describes the context for this endorsement value
    /// * `mkey` - Measurement element type that identifies what is being measured
    /// * `value` - The value to serialize and store as the endorsement value
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if successful, or an `std::io::Error` if serialization fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::{
    ///     comid::{ConciseMidTag, TagIdentityMap, TagIdTypeChoice},
    ///     triples::{EnvironmentMap, MeasuredElementTypeChoice},
    /// };
    /// use corim_rs::core::Tstr;
    ///
    /// let mut comid = ConciseMidTag::default();
    /// comid.tag_identity = TagIdentityMap {
    ///     tag_id: TagIdTypeChoice::Tstr(Tstr::from("example-id")),
    ///     tag_version: Some(1),
    /// };
    ///
    /// // Add an endorsement value
    /// let env = EnvironmentMap::default();
    /// let mkey = MeasuredElementTypeChoice::from("software-component");
    /// let endorsement_data = "example endorsement value";
    /// comid.add_endorsement_raw_value(&env, mkey, &endorsement_data)
    ///     .expect("Failed to add endorsement value");
    /// ```
    pub fn add_endorsement_raw_value<T>(
        &mut self,
        environment: &EnvironmentMap<'a>,
        mkey: MeasuredElementTypeChoice<'a>,
        value: &T,
    ) -> std::io::Result<()>
    where
        T: ?Sized + Serialize,
    {
        let mut raw_bytes = vec![];
        ciborium::into_writer(value, &mut raw_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let raw_value = TaggedBytes::new(raw_bytes.into());

        let measurement = MeasurementMap {
            mkey: Some(mkey),
            mval: MeasurementValuesMap {
                raw: Some(RawValueType {
                    raw_value: raw_value.into(),
                    raw_value_mask: None,
                }),
                ..Default::default()
            },
            authorized_by: None,
        };

        match &mut self.triples.endorsed_triples {
            None => {
                let new_record = EndorsedTripleRecord {
                    condition: environment.clone(),
                    endorsement: vec![measurement],
                };
                self.triples.endorsed_triples = Some(vec![new_record]);
            }

            Some(vec) => {
                if let Some(record) = vec.iter_mut().find(|r| r.condition == *environment) {
                    record.endorsement.push(measurement);
                } else {
                    let new_record = EndorsedTripleRecord {
                        condition: environment.clone(),
                        endorsement: vec![measurement],
                    };
                    vec.push(new_record);
                }
            }
        }
        Ok(())
    }
}

impl Serialize for ConciseMidTag<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(language) = &self.language {
                map.serialize_entry("language", language)?;
            }

            map.serialize_entry("tag-identity", &self.tag_identity)?;

            if let Some(entities) = &self.entities {
                map.serialize_entry("entities", entities)?;
            }

            if let Some(linked_tags) = &self.linked_tags {
                map.serialize_entry("linked-tags", linked_tags)?;
            }

            map.serialize_entry("triples", &self.triples)?;
        } else {
            if let Some(language) = &self.language {
                map.serialize_entry(&0, language)?;
            }

            map.serialize_entry(&1, &self.tag_identity)?;

            if let Some(entities) = &self.entities {
                map.serialize_entry(&2, entities)?;
            }

            if let Some(linked_tags) = &self.linked_tags {
                map.serialize_entry(&3, linked_tags)?;
            }

            map.serialize_entry(&4, &self.triples)?;
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ConciseMidTag<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct ConciseMidTagVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for ConciseMidTagVisitor<'a> {
            type Value = ConciseMidTag<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing ConciseMidTag fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = ConciseMidTagBuilder::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("language") => {
                                builder = builder.language(map.next_value::<Text>()?);
                            }
                            Some("tag-identity") => {
                                builder = builder.tag_identity(map.next_value::<TagIdentityMap>()?);
                            }
                            Some("entities") => {
                                builder =
                                    builder.entities(map.next_value::<Vec<ComidEntityMap>>()?);
                            }
                            Some("linked-tags") => {
                                builder =
                                    builder.linked_tags(map.next_value::<Vec<LinkedTagMap>>()?);
                            }
                            Some("triples") => {
                                builder = builder.triples(map.next_value::<TriplesMap>()?);
                            }
                            Some(s) => {
                                let ext_field: i128 = s.parse().map_err(|_| {
                                    de::Error::unknown_field(
                                        s,
                                        &[
                                            "langauge",
                                            "tag-identity",
                                            "entities",
                                            "linked-tags",
                                            "triples",
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
                                builder = builder.language(map.next_value::<Text>()?);
                            }
                            Some(1) => {
                                builder = builder.tag_identity(map.next_value::<TagIdentityMap>()?);
                            }
                            Some(2) => {
                                builder =
                                    builder.entities(map.next_value::<Vec<ComidEntityMap>>()?);
                            }
                            Some(3) => {
                                builder =
                                    builder.linked_tags(map.next_value::<Vec<LinkedTagMap>>()?);
                            }
                            Some(4) => {
                                builder = builder.triples(map.next_value::<TriplesMap>()?);
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
        deserializer.deserialize_map(ConciseMidTagVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Debug, Default)]
pub struct ConciseMidTagBuilder<'a> {
    /// Optional language identifier for the tag content
    language: Option<Text<'a>>,
    /// Identity information for this tag
    tag_identity: Option<TagIdentityMap<'a>>,
    /// List of entities associated with this tag
    entities: Option<Vec<ComidEntityMap<'a>>>,
    /// Optional references to other related tags
    linked_tags: Option<Vec<LinkedTagMap<'a>>>,
    /// Collection of triples describing the module
    triples: Option<TriplesMap<'a>>,
    /// Optional extensible attributes
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> ConciseMidTagBuilder<'a> {
    pub fn language(mut self, value: Text<'a>) -> Self {
        self.language = Some(value);
        self
    }

    pub fn tag_identity(mut self, value: TagIdentityMap<'a>) -> Self {
        self.tag_identity = Some(value);
        self
    }

    pub fn entities(mut self, value: Vec<ComidEntityMap<'a>>) -> Self {
        self.entities = Some(value);
        self
    }

    pub fn linked_tags(mut self, value: Vec<LinkedTagMap<'a>>) -> Self {
        self.linked_tags = Some(value);
        self
    }

    pub fn triples(mut self, value: TriplesMap<'a>) -> Self {
        self.triples = Some(value);
        self
    }

    pub fn extensions(mut self, value: ExtensionMap<'a>) -> Self {
        self.extensions = Some(value);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::default();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn build(self) -> Result<ConciseMidTag<'a>> {
        if self.tag_identity.is_none() {
            return Err(ComidError::UnsetMandatoryField(
                "ConciseMidTag".to_string(),
                "tag_identity".to_string(),
            ))?;
        }

        if self.triples.is_none() {
            return Err(ComidError::UnsetMandatoryField(
                "ConciseMidTag".to_string(),
                "triples".to_string(),
            ))?;
        }

        Ok(ConciseMidTag {
            language: self.language,
            tag_identity: self.tag_identity.unwrap(),
            entities: self.entities,
            linked_tags: self.linked_tags,
            triples: self.triples.unwrap(),
            extensions: self.extensions,
        })
    }
}

/// Identification information for a tag
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct TagIdentityMap<'a> {
    /// Unique identifier for the tag
    pub tag_id: TagIdTypeChoice<'a>,
    /// Optional version number for the tag
    pub tag_version: Option<TagVersionType>,
}

impl Serialize for TagIdentityMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("tag-id", &self.tag_id)?;

            if let Some(tag_version) = &self.tag_version {
                map.serialize_entry("tag-version", tag_version)?;
            }
        } else {
            map.serialize_entry(&0, &self.tag_id)?;

            if let Some(tag_version) = &self.tag_version {
                map.serialize_entry(&1, tag_version)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for TagIdentityMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct TagIdentityMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for TagIdentityMapVisitor<'a> {
            type Value = TagIdentityMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing TagIdentityMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut tag_id: Option<TagIdTypeChoice> = None;
                let mut tag_version: Option<TagVersionType> = None;

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("tag-id") => {
                                tag_id = Some(map.next_value::<TagIdTypeChoice>()?);
                            }
                            Some("tag-version") => {
                                tag_version = Some(map.next_value::<TagVersionType>()?);
                            }
                            Some(s) => {
                                return Err(de::Error::unknown_field(s, &["tag-id", "tag-version"]))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                tag_id = Some(map.next_value::<TagIdTypeChoice>()?);
                            }
                            Some(1) => {
                                tag_version = Some(map.next_value::<TagVersionType>()?);
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

                if tag_id.is_none() {
                    return Err(de::Error::missing_field("tag-id"));
                }

                Ok(TagIdentityMap {
                    tag_id: tag_id.unwrap(),
                    tag_version,
                })
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(TagIdentityMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

/// Represents either a string or UUID tag identifier
///
/// This enum allows CoMID tags to be identified by either a text string
/// or a UUID, following the schema definition in the CoRIM specification.
/// Tag identifiers are used in the tag identity map and for linking between tags.
#[derive(Debug, Serialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum TagIdTypeChoice<'a> {
    /// Text string identifier
    Tstr(Tstr<'a>),
    /// UUID identifier
    Uuid(UuidType),
}

impl TagIdTypeChoice<'_> {
    /// Returns the tag identifier as a string, if it is a text value
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Tstr(tstr) => Some(tstr),
            _ => None,
        }
    }

    /// Returns a clone of the UUID if this is a UUID type identifier
    ///
    /// # Returns
    ///
    /// * `Some(UuidType)` - If this is a UUID identifier, returns a clone of the UUID
    /// * `None` - If this is a text string identifier
    ///
    /// # Example
    ///
    /// ```
    /// use corim_rs::{
    ///     comid::TagIdTypeChoice,
    ///     core::UuidType,
    /// };
    /// use corim_rs::fixed_bytes::FixedBytes;
    ///
    /// // Create a UUID type tag ID
    /// let uuid_bytes = [0; 16]; // All zeros for example
    /// let uuid = UuidType::from(FixedBytes::from(uuid_bytes));
    /// let tag_id = TagIdTypeChoice::Uuid(uuid);
    ///
    /// // Extract the UUID
    /// let extracted_uuid = tag_id.as_uuid();
    /// assert!(extracted_uuid.is_some());
    /// ```
    pub fn as_uuid(&self) -> Option<UuidType> {
        match self {
            Self::Uuid(uuid) => Some((*uuid).clone()),
            _ => None,
        }
    }
}

impl<'a> From<&'a str> for TagIdTypeChoice<'a> {
    fn from(value: &'a str) -> Self {
        match UuidType::try_from(value) {
            Ok(uuid) => TagIdTypeChoice::Uuid(uuid),
            Err(_) => TagIdTypeChoice::Tstr(value.into()),
        }
    }
}

impl From<[u8; 16]> for TagIdTypeChoice<'_> {
    fn from(value: [u8; 16]) -> Self {
        TagIdTypeChoice::Uuid(UuidType::from(value))
    }
}

impl TryFrom<&[u8]> for TagIdTypeChoice<'_> {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(TagIdTypeChoice::Uuid(UuidType::try_from(value)?))
    }
}

impl<'de> Deserialize<'de> for TagIdTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct TagIdTypeChoiceVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for TagIdTypeChoiceVisitor<'a> {
            type Value = TagIdTypeChoice<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or 16 bytes of a UUID")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_string(v.to_string())
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                TagIdTypeChoice::try_from(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                match UuidType::try_from(v.as_str()) {
                    Ok(uuid) => Ok(TagIdTypeChoice::Uuid(uuid)),
                    Err(_) => Ok(TagIdTypeChoice::Tstr(Tstr::from(Cow::Owned::<str>(v)))),
                }
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(v)
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(v)
            }
        }

        deserializer.deserialize_any(TagIdTypeChoiceVisitor {
            marker: PhantomData,
        })
    }
}

/// Information about an entity associated with the tag
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ComidEntityMap<'a> {
    /// Name of the entity
    pub entity_name: Text<'a>,
    /// Optional registration identifier
    pub reg_id: Option<Uri<'a>>,
    /// One or more roles this entity fulfills
    pub role: Vec<ComidRoleTypeChoice>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Serialize for ComidEntityMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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

impl<'de> Deserialize<'de> for ComidEntityMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct ComidEntityMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for ComidEntityMapVisitor<'a> {
            type Value = ComidEntityMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing ComidEntityMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = ComidEntityMapBuilder::default();

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
                                    builder.role(map.next_value::<Vec<ComidRoleTypeChoice>>()?);
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
                                    builder.role(map.next_value::<Vec<ComidRoleTypeChoice>>()?);
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
        deserializer.deserialize_map(ComidEntityMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

pub struct ComidEntityMapBuilder<'a> {
    entity_name: Option<Text<'a>>,
    reg_id: Option<Uri<'a>>,
    role: Option<Vec<ComidRoleTypeChoice>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> ComidEntityMapBuilder<'a> {
    pub fn new() -> Self {
        ComidEntityMapBuilder {
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

    pub fn role(mut self, roles: Vec<ComidRoleTypeChoice>) -> Self {
        self.role = Some(roles);
        self
    }

    pub fn add_role(mut self, role: ComidRoleTypeChoice) -> Self {
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

    pub fn build(self) -> Result<ComidEntityMap<'a>> {
        if self.entity_name.is_none()
            || self.role.is_none()
            || self.role.as_ref().unwrap().is_empty()
        {
            return Err(ComidError::UnsetMandatoryField(
                "ComidEntityMap".to_string(),
                "entity_name and role".to_string(),
            ))?;
        }

        Ok(ComidEntityMap {
            entity_name: self.entity_name.unwrap(),
            reg_id: self.reg_id,
            role: self.role.unwrap(),
            extensions: self.extensions,
        })
    }
}

impl Default for ComidEntityMapBuilder<'_> {
    fn default() -> Self {
        ComidEntityMapBuilder::new()
    }
}

/// Role types that can be assigned to entities
///
/// Each role type represents a specific responsibility that an entity
/// may have in relation to a module or tag.
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub enum ComidRoleTypeChoice {
    /// Entity that created the tag (value: 0)
    ///
    /// This role indicates the entity responsible for creating and
    /// signing the CoMID tag itself, not necessarily the module it describes.
    TagCreator = 0,
    /// Entity that created the module (value: 1)
    ///
    /// This role indicates the entity responsible for developing or
    /// manufacturing the module described by the tag.
    Creator = 1,
    /// Entity that maintains the module (value: 2)
    ///
    /// This role indicates the entity responsible for ongoing maintenance,
    /// updates, and support for the module described by the tag.
    Maintainer = 2,
}

impl From<&ComidRoleTypeChoice> for i64 {
    fn from(value: &ComidRoleTypeChoice) -> Self {
        match value {
            ComidRoleTypeChoice::TagCreator => 0,
            ComidRoleTypeChoice::Creator => 1,
            ComidRoleTypeChoice::Maintainer => 2,
        }
    }
}

impl TryFrom<i64> for ComidRoleTypeChoice {
    type Error = ComidError;

    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ComidRoleTypeChoice::TagCreator),
            1 => Ok(ComidRoleTypeChoice::Creator),
            2 => Ok(ComidRoleTypeChoice::Maintainer),
            i => Err(ComidError::InvalidComidRole(i.into())),
        }
    }
}

impl TryFrom<&str> for ComidRoleTypeChoice {
    type Error = ComidError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "tag-creator" => Ok(ComidRoleTypeChoice::TagCreator),
            "creator" => Ok(ComidRoleTypeChoice::Creator),
            "maintainer" => Ok(ComidRoleTypeChoice::Maintainer),
            s => Err(ComidError::InvalidComidRole(s.to_string().into())),
        }
    }
}

impl Display for ComidRoleTypeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ComidRoleTypeChoice::TagCreator => "tag-creator",
            ComidRoleTypeChoice::Creator => "creator",
            ComidRoleTypeChoice::Maintainer => "maintainer",
        })
    }
}

impl Serialize for ComidRoleTypeChoice {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            i64::from(self).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ComidRoleTypeChoice {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .as_str()
                .try_into()
                .map_err(de::Error::custom)
        } else {
            i64::deserialize(deserializer)?
                .try_into()
                .map_err(de::Error::custom)
        }
    }
}

/// Reference to another tag and its relationship to this one
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct LinkedTagMap<'a> {
    /// Identifier of the linked tag
    pub linked_tag_id: TagIdTypeChoice<'a>,
    /// Relationship type between the tags
    pub tag_rel: TagRelTypeChoice,
}

impl Serialize for LinkedTagMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("linked-tag-id", &self.linked_tag_id)?;
            map.serialize_entry("tag-rel", &self.tag_rel)?;
        } else {
            map.serialize_entry(&0, &self.linked_tag_id)?;
            map.serialize_entry(&1, &self.tag_rel)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for LinkedTagMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct LinkedTagMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for LinkedTagMapVisitor<'a> {
            type Value = LinkedTagMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing LinkedTagMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut tag_id: Option<TagIdTypeChoice> = None;
                let mut tag_rel: Option<TagRelTypeChoice> = None;

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("linked-tag-id") => {
                                tag_id = Some(map.next_value::<TagIdTypeChoice>()?);
                            }
                            Some("tag-rel") => {
                                tag_rel = Some(map.next_value::<TagRelTypeChoice>()?);
                            }
                            Some(s) => {
                                return Err(de::Error::unknown_field(
                                    s,
                                    &["linked-tag-id", "tag-rel"],
                                ))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                tag_id = Some(map.next_value::<TagIdTypeChoice>()?);
                            }
                            Some(1) => {
                                tag_rel = Some(map.next_value::<TagRelTypeChoice>()?);
                            }
                            Some(n) => {
                                return Err(de::Error::unknown_field(
                                    n.to_string().as_str(),
                                    &["linked-tag-id", "tag-rel"],
                                ))
                            }
                            None => break,
                        }
                    }
                }

                if tag_id.is_none() {
                    return Err(de::Error::missing_field("linked-tag-id"));
                }

                if tag_rel.is_none() {
                    return Err(de::Error::missing_field("tag-rel"));
                }

                Ok(LinkedTagMap {
                    linked_tag_id: tag_id.unwrap(),
                    tag_rel: tag_rel.unwrap(),
                })
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(LinkedTagMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

/// Types of relationships between tags
///
/// This enum defines how tags can be related to each other,
/// supporting versioning and supplemental information scenarios.
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub enum TagRelTypeChoice {
    /// This tag supplements the linked tag by providing additional information
    /// without replacing or invalidating the linked tag's content
    ///
    /// Use this relationship type when adding complementary information to an existing tag.
    Supplements,
    /// This tag completely replaces the linked tag, indicating that the linked
    /// tag should no longer be considered valid or current
    ///
    /// Use this relationship type when creating a new version of a tag that supersedes
    /// an older version.
    Replaces,
}

impl TryFrom<i64> for TagRelTypeChoice {
    type Error = ComidError;

    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(TagRelTypeChoice::Supplements),
            1 => Ok(TagRelTypeChoice::Replaces),
            n => Err(ComidError::InvalidTagRelationship(n.into())),
        }
    }
}

impl From<&TagRelTypeChoice> for i64 {
    fn from(value: &TagRelTypeChoice) -> Self {
        match value {
            TagRelTypeChoice::Supplements => 0,
            TagRelTypeChoice::Replaces => 1,
        }
    }
}

impl TryFrom<&str> for TagRelTypeChoice {
    type Error = ComidError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "supplements" => Ok(TagRelTypeChoice::Supplements),
            "replaces" => Ok(TagRelTypeChoice::Replaces),
            s => Err(ComidError::InvalidTagRelationship(s.to_string().into())),
        }
    }
}

impl Display for TagRelTypeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TagRelTypeChoice::Supplements => "supplements",
            TagRelTypeChoice::Replaces => "replaces",
        })
    }
}

impl Serialize for TagRelTypeChoice {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            i64::from(self).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for TagRelTypeChoice {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .as_str()
                .try_into()
                .map_err(de::Error::custom)
        } else {
            i64::deserialize(deserializer)?
                .try_into()
                .map_err(de::Error::custom)
        }
    }
}

/// Collection of different types of triples describing the module characteristics. It is
/// **HIGHLY** recommended to use the TriplesMapBuilder, to ensure the CDDL enforcement of
/// at least one field being present.
#[derive(Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct TriplesMap<'a> {
    /// Optional reference triples that link to external references
    pub reference_triples: Option<Vec<ReferenceTripleRecord<'a>>>,

    /// Optional endorsement triples that contain verification information
    pub endorsed_triples: Option<Vec<EndorsedTripleRecord<'a>>>,

    /// Optional identity triples that provide identity information
    pub identity_triples: Option<Vec<IdentityTripleRecord<'a>>>,

    /// Optional attestation key triples containing cryptographic keys
    pub attest_key_triples: Option<Vec<AttestKeyTripleRecord<'a>>>,

    /// Optional domain dependency triples describing relationships between domains
    pub dependency_triples: Option<Vec<DomainDependencyTripleRecord<'a>>>,

    /// Optional domain membership triples describing domain associations
    pub membership_triples: Option<Vec<DomainMembershipTripleRecord<'a>>>,

    /// Optional SWID triples containing software identification data
    pub coswid_triples: Option<Vec<CoswidTripleRecord<'a>>>,

    /// Optional conditional endorsement series triples for complex endorsement chains
    pub conditional_endorsement_series_triples:
        Option<Vec<ConditionalEndorsementSeriesTripleRecord<'a>>>,

    /// Optional conditional endorsement triples for conditional verification
    pub conditional_endorsement_triples: Option<Vec<ConditionalEndorsementTripleRecord<'a>>>,

    /// Optional extensible attributes for future expansion
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Serialize for TriplesMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(reference_triples) = &self.reference_triples {
                map.serialize_entry("reference-triples", reference_triples)?;
            }
            if let Some(endorsed_triples) = &self.endorsed_triples {
                map.serialize_entry("endorsed-triples", endorsed_triples)?;
            }
            if let Some(identity_triples) = &self.identity_triples {
                map.serialize_entry("identity-triples", identity_triples)?;
            }
            if let Some(attest_key_triples) = &self.attest_key_triples {
                map.serialize_entry("attest-key-triples", attest_key_triples)?;
            }
            if let Some(dependency_triples) = &self.dependency_triples {
                map.serialize_entry("dependency-triples", dependency_triples)?;
            }
            if let Some(membership_triples) = &self.membership_triples {
                map.serialize_entry("membership-triples", membership_triples)?;
            }
            if let Some(coswid_triples) = &self.coswid_triples {
                map.serialize_entry("coswid-triples", coswid_triples)?;
            }
            if let Some(conditional_endorsement_series_triples) =
                &self.conditional_endorsement_series_triples
            {
                map.serialize_entry(
                    "conditional-endorsement-series-triples",
                    conditional_endorsement_series_triples,
                )?;
            }
            if let Some(conditional_endorsement_triples) = &self.conditional_endorsement_triples {
                map.serialize_entry(
                    "conditional-endorsement-triples",
                    conditional_endorsement_triples,
                )?;
            }
        } else {
            if let Some(reference_triples) = &self.reference_triples {
                map.serialize_entry(&0, reference_triples)?;
            }
            if let Some(endorsed_triples) = &self.endorsed_triples {
                map.serialize_entry(&1, endorsed_triples)?;
            }
            if let Some(identity_triples) = &self.identity_triples {
                map.serialize_entry(&2, identity_triples)?;
            }
            if let Some(attest_key_triples) = &self.attest_key_triples {
                map.serialize_entry(&3, attest_key_triples)?;
            }
            if let Some(dependency_triples) = &self.dependency_triples {
                map.serialize_entry(&4, dependency_triples)?;
            }
            if let Some(membership_triples) = &self.membership_triples {
                map.serialize_entry(&5, membership_triples)?;
            }
            if let Some(coswid_triples) = &self.coswid_triples {
                map.serialize_entry(&6, coswid_triples)?;
            }
            if let Some(conditional_endorsement_series_triples) =
                &self.conditional_endorsement_series_triples
            {
                map.serialize_entry(&8, conditional_endorsement_series_triples)?;
            }
            if let Some(conditional_endorsement_triples) = &self.conditional_endorsement_triples {
                map.serialize_entry(&10, conditional_endorsement_triples)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for TriplesMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct TriplesMapVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for TriplesMapVisitor<'a> {
            type Value = TriplesMap<'a>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing TriplesMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = TriplesMapBuilder::default();
                let mut extensions = ExtensionMap::default();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("reference-triples") => {
                                builder = builder.reference_triples(
                                    map.next_value::<Vec<ReferenceTripleRecord>>()?,
                                );
                            }
                            Some("endorsed-triples") => {
                                builder = builder.endorsed_triples(
                                    map.next_value::<Vec<EndorsedTripleRecord>>()?,
                                );
                            }
                            Some("identity-triples") => {
                                builder = builder.identity_triples(
                                    map.next_value::<Vec<IdentityTripleRecord>>()?,
                                );
                            }
                            Some("attest-key-triples") => {
                                builder = builder.attest_key_triples(
                                    map.next_value::<Vec<AttestKeyTripleRecord>>()?,
                                );
                            }
                            Some("dependency-triples") => {
                                builder = builder.dependency_triples(
                                    map.next_value::<Vec<DomainDependencyTripleRecord>>()?,
                                );
                            }
                            Some("membership-triples") => {
                                builder = builder.membership_triples(
                                    map.next_value::<Vec<DomainMembershipTripleRecord>>()?,
                                );
                            }
                            Some("coswid-triples") => {
                                builder = builder
                                    .coswid_triples(map.next_value::<Vec<CoswidTripleRecord>>()?);
                            }
                            Some("conditional-endorsement-series-triples") => {
                                builder = builder.conditional_endorsement_series_triples(
                                    map.next_value::<Vec<ConditionalEndorsementSeriesTripleRecord>>()?,
                                );
                            }
                            Some("conditional-endorsement-triples") => {
                                builder = builder.conditional_endorsement_triples(
                                    map.next_value::<Vec<ConditionalEndorsementTripleRecord>>()?,
                                );
                            }
                            Some(name) => {
                                extensions.insert(
                                    name.parse::<Integer>().map_err(de::Error::custom)?,
                                    map.next_value::<ExtensionValue>()?,
                                );
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                builder = builder.reference_triples(
                                    map.next_value::<Vec<ReferenceTripleRecord>>()?,
                                );
                            }
                            Some(1) => {
                                builder = builder.endorsed_triples(
                                    map.next_value::<Vec<EndorsedTripleRecord>>()?,
                                );
                            }
                            Some(2) => {
                                builder = builder.identity_triples(
                                    map.next_value::<Vec<IdentityTripleRecord>>()?,
                                );
                            }
                            Some(3) => {
                                builder = builder.attest_key_triples(
                                    map.next_value::<Vec<AttestKeyTripleRecord>>()?,
                                );
                            }
                            Some(4) => {
                                builder = builder.dependency_triples(
                                    map.next_value::<Vec<DomainDependencyTripleRecord>>()?,
                                );
                            }
                            Some(5) => {
                                builder = builder.membership_triples(
                                    map.next_value::<Vec<DomainMembershipTripleRecord>>()?,
                                );
                            }
                            Some(6) => {
                                builder = builder
                                    .coswid_triples(map.next_value::<Vec<CoswidTripleRecord>>()?);
                            }
                            Some(8) => {
                                builder = builder.conditional_endorsement_series_triples(
                                    map.next_value::<Vec<ConditionalEndorsementSeriesTripleRecord>>()?,
                                );
                            }
                            Some(10) => {
                                builder = builder.conditional_endorsement_triples(
                                    map.next_value::<Vec<ConditionalEndorsementTripleRecord>>()?,
                                );
                            }
                            Some(key) => {
                                extensions.insert(key.into(), map.next_value()?);
                            }
                            None => break,
                        }
                    }
                }

                if !extensions.is_empty() {
                    builder = builder.extensions(extensions);
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(TriplesMapVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct TriplesMapBuilder<'a> {
    reference_triples: Option<Vec<ReferenceTripleRecord<'a>>>,
    endorsed_triples: Option<Vec<EndorsedTripleRecord<'a>>>,
    identity_triples: Option<Vec<IdentityTripleRecord<'a>>>,
    attest_key_triples: Option<Vec<AttestKeyTripleRecord<'a>>>,
    dependency_triples: Option<Vec<DomainDependencyTripleRecord<'a>>>,
    membership_triples: Option<Vec<DomainMembershipTripleRecord<'a>>>,
    coswid_triples: Option<Vec<CoswidTripleRecord<'a>>>,
    conditional_endorsement_series_triples:
        Option<Vec<ConditionalEndorsementSeriesTripleRecord<'a>>>,
    conditional_endorsement_triples: Option<Vec<ConditionalEndorsementTripleRecord<'a>>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> TriplesMapBuilder<'a> {
    /// Creates an empty TriplesMapBuilder
    ///
    /// # Example
    ///
    /// ```
    /// use corim_rs::comid::TriplesMapBuilder;
    ///
    /// let builder = TriplesMapBuilder::default();
    /// ```
    /// Adds reference triples to the builder
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of reference triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    ///
    /// # Example
    ///
    /// ```
    /// # use corim_rs::comid::TriplesMapBuilder;
    /// # use corim_rs::triples::{ReferenceTripleRecord, EnvironmentMap};
    /// #
    /// let env = EnvironmentMap::default();
    /// let triple = ReferenceTripleRecord {
    ///     ref_env: env,
    ///     ref_claims: vec![].into(), // Empty for example
    /// };
    ///
    /// let builder = TriplesMapBuilder::default()
    ///     .reference_triples(vec![triple]);
    /// ```
    pub fn reference_triples(mut self, value: Vec<ReferenceTripleRecord<'a>>) -> Self {
        self.reference_triples = Some(value);
        self
    }
    /// Adds endorsed triples to the builder
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of endorsed triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    ///
    /// # Example
    ///
    /// ```
    /// # use corim_rs::comid::TriplesMapBuilder;
    /// # use corim_rs::triples::{EndorsedTripleRecord, EnvironmentMap};
    /// #
    /// let env = EnvironmentMap::default();
    /// let triple = EndorsedTripleRecord {
    ///     condition: env,
    ///     endorsement: vec![].into(), // Empty for example
    /// };
    ///
    /// let builder = TriplesMapBuilder::default()
    ///     .endorsed_triples(vec![triple]);
    /// ```
    pub fn endorsed_triples(mut self, value: Vec<EndorsedTripleRecord<'a>>) -> Self {
        self.endorsed_triples = Some(value);
        self
    }
    /// Adds identity triples to the builder
    ///
    /// Identity triples associate cryptographic keys with environments.
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of identity triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    pub fn identity_triples(mut self, value: Vec<IdentityTripleRecord<'a>>) -> Self {
        self.identity_triples = Some(value);
        self
    }
    /// Adds attestation key triples to the builder
    ///
    /// Attestation key triples define keys used for attestation purposes.
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of attestation key triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    pub fn attest_key_triples(mut self, value: Vec<AttestKeyTripleRecord<'a>>) -> Self {
        self.attest_key_triples = Some(value);
        self
    }
    /// Adds domain dependency triples to the builder
    ///
    /// Domain dependency triples express relationships between different domains.
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of domain dependency triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    pub fn dependency_triples(mut self, value: Vec<DomainDependencyTripleRecord<'a>>) -> Self {
        self.dependency_triples = Some(value);
        self
    }
    /// Adds domain membership triples to the builder
    ///
    /// Domain membership triples define which entities belong to which domains.
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of domain membership triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    pub fn membership_triples(mut self, value: Vec<DomainMembershipTripleRecord<'a>>) -> Self {
        self.membership_triples = Some(value);
        self
    }
    /// Adds CoSWID triples to the builder
    ///
    /// CoSWID triples link to software identification tags.
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of CoSWID triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    pub fn coswid_triples(mut self, value: Vec<CoswidTripleRecord<'a>>) -> Self {
        self.coswid_triples = Some(value);
        self
    }
    /// Adds conditional endorsement series triples to the builder
    ///
    /// These triples define a series of conditional endorsements for complex
    /// verification scenarios.
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of conditional endorsement series triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    pub fn conditional_endorsement_series_triples(
        mut self,
        value: Vec<ConditionalEndorsementSeriesTripleRecord<'a>>,
    ) -> Self {
        self.conditional_endorsement_series_triples = Some(value);
        self
    }
    /// Adds conditional endorsement triples to the builder
    ///
    /// Conditional endorsement triples express verification requirements that
    /// must be satisfied under specific conditions.
    ///
    /// # Arguments
    ///
    /// * `value` - Vector of conditional endorsement triple records
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    pub fn conditional_endorsement_triples(
        mut self,
        value: Vec<ConditionalEndorsementTripleRecord<'a>>,
    ) -> Self {
        self.conditional_endorsement_triples = Some(value);
        self
    }
    /// Adds extension data to the builder
    ///
    /// Extensions allow for future expandability of the triples map.
    ///
    /// # Arguments
    ///
    /// * `value` - Extension map containing additional data
    ///
    /// # Returns
    ///
    /// Returns self for method chaining
    pub fn extensions(mut self, value: ExtensionMap<'a>) -> Self {
        self.extensions = Some(value);
        self
    }

    /// Builds the TriplesMap, ensuring at least one field is set
    ///
    /// According to the CoRIM specification, a TriplesMap must contain at least
    /// one type of triple. This method enforces that requirement.
    ///
    /// # Returns
    ///
    /// * `Ok(TriplesMap)` - If at least one field is set
    /// * `Err(ComidError::EmptyTriplesMap)` - If no fields are set
    ///
    /// # Example
    ///
    /// ```
    /// # use corim_rs::comid::TriplesMapBuilder;
    /// # use corim_rs::triples::{ReferenceTripleRecord, EnvironmentMap};
    /// #
    /// let env = EnvironmentMap::default();
    /// let triple = ReferenceTripleRecord {
    ///     ref_env: env,
    ///     ref_claims: vec![].into(),
    /// };
    ///
    /// let triples_map = TriplesMapBuilder::default()
    ///     .reference_triples(vec![triple])
    ///     .build()
    ///     .expect("Failed to build TriplesMap");
    /// ```
    pub fn build(self) -> Result<TriplesMap<'a>> {
        if self.reference_triples.is_none()
            && self.endorsed_triples.is_none()
            && self.identity_triples.is_none()
            && self.attest_key_triples.is_none()
            && self.dependency_triples.is_none()
            && self.membership_triples.is_none()
            && self.coswid_triples.is_none()
            && self.conditional_endorsement_series_triples.is_none()
            && self.conditional_endorsement_triples.is_none()
            && self.extensions.is_none()
        {
            return Err(ComidError::EmptyTriplesMap)?;
        }

        Ok(TriplesMap {
            reference_triples: self.reference_triples,
            endorsed_triples: self.endorsed_triples,
            identity_triples: self.identity_triples,
            attest_key_triples: self.attest_key_triples,
            dependency_triples: self.dependency_triples,
            membership_triples: self.membership_triples,
            coswid_triples: self.coswid_triples,
            conditional_endorsement_series_triples: self.conditional_endorsement_series_triples,
            conditional_endorsement_triples: self.conditional_endorsement_triples,
            extensions: self.extensions,
        })
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(vec)]
mod tests {
    use super::*;
    use crate::{
        triples::{
            ConditionalSeriesRecord, DomainTypeChoice, MeasurementValuesMapBuilder,
            StatefulEnvironmentRecord, SvnTypeChoice,
        },
        CryptoKeyTypeChoice, EnvironmentMapBuilder, InstanceIdTypeChoice, TextOrBytesSized,
        TriplesRecordCondition,
    };

    #[test]
    fn test_comid_role_serde() {
        struct TestCase {
            role: ComidRoleTypeChoice,
            expected_json: &'static str,
            expected_cbor: Vec<u8>,
        }

        let test_cases: Vec<TestCase> = vec![
            TestCase {
                role: ComidRoleTypeChoice::TagCreator,
                expected_json: "\"tag-creator\"",
                expected_cbor: vec![0x00],
            },
            TestCase {
                role: ComidRoleTypeChoice::Creator,
                expected_json: "\"creator\"",
                expected_cbor: vec![0x01],
            },
            TestCase {
                role: ComidRoleTypeChoice::Maintainer,
                expected_json: "\"maintainer\"",
                expected_cbor: vec![0x02],
            },
        ];

        for tc in test_cases.into_iter() {
            let actual_json = serde_json::to_string(&tc.role).unwrap();

            assert_eq!(actual_json, tc.expected_json);

            let role_de: ComidRoleTypeChoice = serde_json::from_str(actual_json.as_str()).unwrap();

            assert_eq!(role_de, tc.role);

            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&tc.role, &mut actual_cbor).unwrap();

            assert_eq!(actual_cbor, tc.expected_cbor);

            let role_de: ComidRoleTypeChoice =
                ciborium::from_reader(actual_cbor.as_slice()).unwrap();

            assert_eq!(role_de, tc.role);
        }

        let actual_err = serde_json::from_str::<ComidRoleTypeChoice>("\"foo\"")
            .err()
            .unwrap()
            .to_string();

        assert_eq!(actual_err, "invalid CoMID role foo");

        let actual_err = serde_json::from_str::<ComidRoleTypeChoice>("1")
            .err()
            .unwrap()
            .to_string();

        assert_eq!(
            actual_err,
            "invalid type: integer `1`, expected a string at line 1 column 1"
        );

        let actual_err = ciborium::from_reader::<ComidRoleTypeChoice, _>([0x03].as_slice())
            .err()
            .unwrap()
            .to_string();

        assert_eq!(actual_err, "Semantic(None, \"invalid CoMID role 3\")");

        let actual_err = ciborium::from_reader::<ComidRoleTypeChoice, _>([0xf4].as_slice())
            .err()
            .unwrap()
            .to_string();

        assert_eq!(
            actual_err,
            "Semantic(None, \"invalid type: boolean `false`, expected integer\")"
        );
    }

    #[test]
    fn test_comid_entity_map_serde() {
        let entity_map = ComidEntityMapBuilder::default()
            .entity_name("foo".into())
            .reg_id("https://example.com".into())
            .add_role(ComidRoleTypeChoice::Maintainer)
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
                0x02, // 2 [maintainer]
              0x20, // key: -1 [extension]
              0x6a, // value: tstr(10)
                0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x61, 0x6c, // "test val"
                0x75, 0x65,                                     // "ue"
            0xff, // break
        ];

        assert_eq!(actual_cbor, expected_cbor);

        let entity_map_de: ComidEntityMap = ciborium::from_reader(actual_cbor.as_slice()).unwrap();

        assert_eq!(entity_map_de, entity_map);

        let actual_json = serde_json::to_string(&entity_map).unwrap();

        let expected_json = r#"{"entity-name":"foo","reg-id":{"type":"uri","value":"https://example.com"},"role":["maintainer"],"-1":"test value"}"#;

        assert_eq!(actual_json, expected_json);

        let entity_map_de: ComidEntityMap = serde_json::from_str(actual_json.as_str()).unwrap();

        assert_eq!(entity_map_de, entity_map);
    }

    #[test]
    fn test_tag_identity_map() {
        let tag_identity = TagIdentityMap {
            tag_id: TagIdTypeChoice::Tstr("foo".into()),
            tag_version: Some(1.into()),
        };

        let mut actual_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&tag_identity, &mut actual_cbor).unwrap();

        let expected_cbor: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [tag-id]
              0x63, // value: tstr(3)
                0x66, 0x6f, 0x6f, // "foo"
              0x01, // key: 1 [tag-version]
              0x01, // value: 1
            0xff,
        ];

        assert_eq!(actual_cbor, expected_cbor);

        let tag_identity_de: TagIdentityMap =
            ciborium::from_reader(actual_cbor.as_slice()).unwrap();

        assert_eq!(tag_identity_de, tag_identity);

        let actual_json = serde_json::to_string(&tag_identity).unwrap();

        let expected_json = r#"{"tag-id":"foo","tag-version":1}"#;

        assert_eq!(actual_json, expected_json);

        let tag_identity_de: TagIdentityMap = serde_json::from_str(actual_json.as_str()).unwrap();

        assert_eq!(tag_identity_de, tag_identity);
    }

    #[test]
    fn test_tag_rel_type_choice_serde() {
        struct TestCase {
            tag_rel: TagRelTypeChoice,
            expected_json: &'static str,
            expected_cbor: Vec<u8>,
        }

        let test_cases: Vec<TestCase> = vec![
            TestCase {
                tag_rel: TagRelTypeChoice::Supplements,
                expected_json: "\"supplements\"",
                expected_cbor: vec![0x00],
            },
            TestCase {
                tag_rel: TagRelTypeChoice::Replaces,
                expected_json: "\"replaces\"",
                expected_cbor: vec![0x01],
            },
        ];

        for tc in test_cases.into_iter() {
            let actual_json = serde_json::to_string(&tc.tag_rel).unwrap();

            assert_eq!(actual_json, tc.expected_json);

            let tag_rel_de: TagRelTypeChoice = serde_json::from_str(actual_json.as_str()).unwrap();

            assert_eq!(tag_rel_de, tc.tag_rel);

            let mut actual_cbor: Vec<u8> = vec![];
            ciborium::into_writer(&tc.tag_rel, &mut actual_cbor).unwrap();

            assert_eq!(actual_cbor, tc.expected_cbor);

            let tag_rel_de: TagRelTypeChoice =
                ciborium::from_reader(actual_cbor.as_slice()).unwrap();

            assert_eq!(tag_rel_de, tc.tag_rel);
        }

        let actual_err = serde_json::from_str::<TagRelTypeChoice>("\"foo\"")
            .err()
            .unwrap()
            .to_string();

        assert_eq!(actual_err, "invalid tag relationship foo");

        let actual_err = serde_json::from_str::<TagRelTypeChoice>("1")
            .err()
            .unwrap()
            .to_string();

        assert_eq!(
            actual_err,
            "invalid type: integer `1`, expected a string at line 1 column 1"
        );

        let actual_err = ciborium::from_reader::<TagRelTypeChoice, _>([0x03].as_slice())
            .err()
            .unwrap()
            .to_string();

        assert_eq!(actual_err, "Semantic(None, \"invalid tag relationship 3\")");

        let actual_err = ciborium::from_reader::<TagRelTypeChoice, _>([0xf4].as_slice())
            .err()
            .unwrap()
            .to_string();

        assert_eq!(
            actual_err,
            "Semantic(None, \"invalid type: boolean `false`, expected integer\")"
        );
    }

    #[test]
    fn test_linked_tag_map_serde() {
        let linked_tag_map = LinkedTagMap {
            linked_tag_id: TagIdTypeChoice::Uuid(
                "550e8400-e29b-41d4-a716-446655440000".try_into().unwrap(),
            ),
            tag_rel: TagRelTypeChoice::Replaces,
        };

        let mut actual_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&linked_tag_map, &mut actual_cbor).unwrap();

        let expected_cbor: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [linked-tag-id]
              0x50, // value: bstr(16)
                0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
                0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
              0x01, // key: 1 [tag-rel]
              0x01, // value: 1 [replaces]
            0xff, // break
        ];

        assert_eq!(actual_cbor, expected_cbor);

        let linked_tag_map_de: LinkedTagMap =
            ciborium::from_reader(actual_cbor.as_slice()).unwrap();

        assert_eq!(linked_tag_map_de, linked_tag_map);

        let actual_json = serde_json::to_string(&linked_tag_map).unwrap();

        let expected_json =
            r#"{"linked-tag-id":"550e8400-e29b-41d4-a716-446655440000","tag-rel":"replaces"}"#;

        assert_eq!(actual_json, expected_json);

        let linked_tag_map_de: LinkedTagMap = serde_json::from_str(actual_json.as_str()).unwrap();

        assert_eq!(linked_tag_map_de, linked_tag_map);
    }

    #[test]
    fn test_triples_map_serde() {
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

        let crypto_key =
            CryptoKeyTypeChoice::Bytes(TaggedBytes::from([0x04, 0x05, 0x06].as_slice()));

        let mut extensions = ExtensionMap::default();
        extensions.insert(1337.into(), ExtensionValue::Bool(true));

        let triples_map = TriplesMapBuilder::default()
            .reference_triples(vec![ReferenceTripleRecord{
                ref_env: env.clone(),
                ref_claims: vec![measurement_map.clone()],
            }])
            .endorsed_triples(vec![EndorsedTripleRecord{
                condition: env.clone(),
                endorsement: vec![measurement_map.clone()],
            }])
            .identity_triples(vec![IdentityTripleRecord{
                environment: env.clone(),
                key_list: vec![crypto_key.clone()],
                conditions: Some(TriplesRecordCondition{
                    mkey: Some(MeasuredElementTypeChoice::Tstr("foo".into())),
                    authorized_by: Some(vec![crypto_key.clone()]),
                })
            }])
            .attest_key_triples(vec![AttestKeyTripleRecord{
                environment: env.clone(),
                key_list: vec![crypto_key.clone()],
                conditions: Some(TriplesRecordCondition{
                    mkey: Some(MeasuredElementTypeChoice::Tstr("foo".into())),
                    authorized_by: Some(vec![crypto_key.clone()]),
                })
            }])
            .dependency_triples(vec![DomainDependencyTripleRecord{
                domain_choice: DomainTypeChoice::Oid("1.2.3.4".try_into().unwrap()),
                environment_map: vec![env.clone()],
            }])
            .membership_triples(vec![DomainMembershipTripleRecord{
                domain_choice: DomainTypeChoice::Oid("1.2.3.4".try_into().unwrap()),
                environment_map: vec![env.clone()],
            }])
            .coswid_triples(vec![CoswidTripleRecord{
                environment_map: env.clone(),
                coswid_tags: vec![TextOrBytesSized::Text("bar".into())],
            }])
            .conditional_endorsement_series_triples(vec![ConditionalEndorsementSeriesTripleRecord{
                condition: StatefulEnvironmentRecord {
                    environment: env.clone(),
                    claims_list: vec![measurement_map.clone()],
                },
                series: vec![ConditionalSeriesRecord{
                    selection: vec![measurement_map.clone()],
                    addition: vec![measurement_map.clone()]
                }],
            }])
            .conditional_endorsement_triples(vec![ConditionalEndorsementTripleRecord{
                conditions: vec![StatefulEnvironmentRecord {
                    environment: env.clone(),
                    claims_list: vec![measurement_map.clone()],
                }],
                endorsements: vec![EndorsedTripleRecord{
                    condition: env.clone(),
                    endorsement: vec![measurement_map.clone()]
                }],
            }])
            .extensions(extensions)
            .build()
            .unwrap();

        let mut actual_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&triples_map, &mut actual_cbor).unwrap();

        let expected_cbor: Vec<u8> = vec![
            0xbf, // map(indef)
              0x00, // key: 0 [reference-triples]
              0x81, // value: array(1)
                0x82, // [0]array(2) [reference-triples-record]
                  0xbf, // [0]map(indef) [ref-env]
                    0x01, // key: 1 [instance]
                    0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                      0x43, // bstr(3)
                        0x01, 0x02, 0x03,
                  0xff, // break
                  0x81, // [1]array(1) [rev-claims]
                    0xbf, // [0]map(indef) [measurement-values-map]
                      0x01, // key: 1 [mval]
                      0xbf, // value: map(indef)
                        0x01, // key: 1 [svn]
                        0x01, // value: 1
                      0xff, // break
                    0xff, // break
              0x01, // key: 1 [endorsement-triples]
              0x81, // value: array(1)
                0x82, // [0]array(2)  [endorsed-triples-record]
                  0xbf, // [0]map(indef) [condition]
                    0x01, // key: 1 [instance]
                    0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                      0x43, // bstr(3)
                        0x01, 0x02, 0x03,
                  0xff, // break
                  0x81, // [1]array(1) [endorsement]
                    0xbf, // [0]map(indef) [measurement-values-map]
                      0x01, // key: 1 [mval]
                      0xbf, // value: map(indef)
                        0x01, // key: 1 [svn]
                        0x01, // value: 1
                      0xff, // break
                    0xff, // break
              0x02, // key: 2 [identity-triples]
              0x81, // value: array(1)
                0x83, // [0]array(3) [identity-triple-record]
                  0xbf, // [0]map(indef) [environment]
                    0x01, // key: 1 [instance]
                    0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                      0x43, // bstr(3)
                        0x01, 0x02, 0x03,
                  0xff, // break
                  0x81, // [1]array(1) [key_list]
                    0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                      0x43, // bstr(3)
                        0x04, 0x05, 0x06,
                  0xbf, // [2]map(indef) [conditions]
                    0x00, // key: 0 [mkey]
                    0x63, // value: tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                    0x01, // key: 1 [authorized-by]
                    0x81, // value: array(1)
                      0xd9, 0x02, 0x30, // [0]tag(560) [tagged-bytes]
                        0x43, // bstr(3)
                          0x04, 0x05, 0x06,
                  0xff, // break
              0x03, // key: 3 [attest-key-triples]
              0x81, // value: array(1)
                0x83, // [0]array(3) [attest-key-triple-record]
                  0xbf, // [0]map(indef) [environment]
                    0x01, // key: 1 [instance]
                    0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                      0x43, // bstr(3)
                        0x01, 0x02, 0x03,
                  0xff, // break
                  0x81, // [1]array(1) [key_list]
                    0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                      0x43, // bstr(3)
                        0x04, 0x05, 0x06,
                  0xbf, // [2]map(indef) [conditions]
                    0x00, // key: 0 [mkey]
                    0x63, // value: tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                    0x01, // key: 1 [authorized-by]
                    0x81, // value: array(1)
                      0xd9, 0x02, 0x30, // [0]tag(560) [tagged-bytes]
                        0x43, // bstr(3)
                          0x04, 0x05, 0x06,
                  0xff, // break
              0x04, // key: 4 [dependency-triples]
              0x81, // value: array(1)
                0x82, // [0]array(2) [domain-dependency-triple-record]
                  0xd8, 0x6f, // [0]tag(111) [oid]
                    0x43, // bstr(3)
                      0x2a, 0x03, 0x04,
                  0x81, // [1]array(1)
                    0xbf, // [1]map(indef) [environment-map]
                      0x01, // key: 1 [instance]
                      0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                        0x43, // bstr(3)
                          0x01, 0x02, 0x03,
                    0xff, // break
              0x05, // key: 5 [membership-triples]
              0x81, // value: array(1)
                0x82, // [0]array(2) [domain-membership-triple-record]
                  0xd8, 0x6f, // [0]tag(111) [oid]
                    0x43, // bstr(3)
                      0x2a, 0x03, 0x04,
                  0x81, // [1]array(1)
                    0xbf, // [0]map(indef) [environment-map]
                      0x01, // key: 1 [instance]
                      0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                        0x43, // bstr(3)
                          0x01, 0x02, 0x03,
                    0xff, // break
              0x06, // key: 6 [coswid-triples]
              0x81, // value: array(1)
                0x82, // [0]array(2) [coswid-triple-record]
                  0xbf, // [0]map(indef) [environment-map]
                    0x01, // key: 1 [instance]
                    0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                      0x43, // bstr(3)
                        0x01, 0x02, 0x03,
                  0xff, // break
                  0x81, // [1]array(1)
                    0x63, // [0]tstr(3)
                     0x62, 0x61, 0x72, // "bar"
              0x08, // key: 8 [conditional-endorsement-series-triples]
              0x81, // value: array(1)
                0x82, // [0]array(2) [conditional-endorsement-series-triple-record]
                  0x82,  // [0]array(2) [stateful-environment-record]
                    0xbf, // [0]map(indef) [environment]
                      0x01, // key: 1 [instance]
                      0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                        0x43, // bstr(3)
                          0x01, 0x02, 0x03,
                    0xff, // break
                    0x81, // [1]array(1) [claims_list]
                      0xbf, // [0]map(indef) [measurement-map]
                        0x01, // key: 1 [mval]
                        0xbf, // value: map(indef) [measurement-values-map]
                          0x01,  // key: 1 [svn]
                          0x01,  // value: 1
                        0xff, // break
                      0xff, // break
                  0x81, // [1]array(1) [series]
                    0x82, // [0]array(2) [conditional-series-record]
                      0x81, // [0]array(1) [selection]
                        0xbf, // [0]map(indef) [measurement-map]
                          0x01, // key: 1 [mval]
                          0xbf, // value: map(indef) [measurement-values-map]
                            0x01, // key: 1 [svn]
                            0x01, // value: 1
                          0xff, // break
                        0xff, // break
                      0x81, // [1]array(1) [addition]
                        0xbf, // [0]map(indef) [measurement-map]
                          0x01, // key: 1 [mval]
                          0xbf, // value: map(indef) [measurement-values-map]
                            0x01, // key: 1 [svn]
                            0x01, // value: 1
                          0xff, // break
                       0xff, // break
              0x0a, // key: 10 [conditional-endorsement-triples]
              0x81, // value: array(1)
                0x82, // [0]array(2) [conditional-endorsement-triple-record]
                  0x81, // [0]array(1) [conditions]
                    0x82, // [0]array(2) [stateful-environment-record]
                      0xbf, // [0]map(indef) [environment]
                        0x01, // key: 1 [instance]
                        0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
                          0x43, // bstr(3)
                            0x01, 0x02, 0x03,
                      0xff, // break
                      0x81, // [1]array(1) [claims-list]
                        0xbf, // [0]map(indef) [measurement-map]
                          0x01, // key: 1 [mval]
                          0xbf, // value: map(indef) [measurement-values-map]
                            0x01, // key: 1 [svn]
                            0x01, // value: 1
                          0xff, // break
                        0xff, // break
                  0x81, // [1]array(1) [endorsements]
                    0x82, // [0]array(2) [endorsed-triple-record]
                      0xbf, // [0]map(indef) [condition]
                        0x01, // key: 1 [instance]
                        0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes]
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
              0x19, 0x05, 0x39, // key: 1337 [extension(1337)]
              0xf5, // value: true
            0xff, // break
        ];

        assert_eq!(actual_cbor, expected_cbor);

        let triples_map_de: TriplesMap = ciborium::from_reader(actual_cbor.as_slice()).unwrap();

        assert_eq!(triples_map_de, triples_map);

        let actual_json = serde_json::to_string(&triples_map).unwrap();

        let expected_json = r#"{"reference-triples":[[{"instance":{"type":"bytes","value":"AQID"}},[{"mval":{"svn":1}}]]],"endorsed-triples":[[{"instance":{"type":"bytes","value":"AQID"}},[{"mval":{"svn":1}}]]],"identity-triples":[[{"instance":{"type":"bytes","value":"AQID"}},[{"type":"bytes","value":"BAUG"}],{"mkey":"foo","authorized-by":[{"type":"bytes","value":"BAUG"}]}]],"attest-key-triples":[[{"instance":{"type":"bytes","value":"AQID"}},[{"type":"bytes","value":"BAUG"}],{"mkey":"foo","authorized-by":[{"type":"bytes","value":"BAUG"}]}]],"dependency-triples":[[{"type":"oid","value":"1.2.3.4"},[{"instance":{"type":"bytes","value":"AQID"}}]]],"membership-triples":[[{"type":"oid","value":"1.2.3.4"},[{"instance":{"type":"bytes","value":"AQID"}}]]],"coswid-triples":[[{"instance":{"type":"bytes","value":"AQID"}},["bar"]]],"conditional-endorsement-series-triples":[[[{"instance":{"type":"bytes","value":"AQID"}},[{"mval":{"svn":1}}]],[[[{"mval":{"svn":1}}],[{"mval":{"svn":1}}]]]]],"conditional-endorsement-triples":[[[[{"instance":{"type":"bytes","value":"AQID"}},[{"mval":{"svn":1}}]]],[[{"instance":{"type":"bytes","value":"AQID"}},[{"mval":{"svn":1}}]]]]],"1337":true}"#;

        assert_eq!(actual_json, expected_json);
    }

    #[test]
    fn test_concise_mid_tag_serde() {
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

        let comid = ConciseMidTagBuilder::default()
            .language("en-GB".into())
            .tag_identity(TagIdentityMap {
                tag_id: TagIdTypeChoice::Tstr("foo".into()),
                tag_version: None,
            })
            .entities(vec![
                ComidEntityMapBuilder::default()
                    .entity_name("foo".into())
                    .add_role(ComidRoleTypeChoice::Creator)
                    .build()
                    .unwrap()
            ])
            .linked_tags(vec![
                LinkedTagMap{
                    linked_tag_id: TagIdTypeChoice::Tstr("bar".into()),
                    tag_rel: TagRelTypeChoice::Supplements,
                }
            ])
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
            .add_extension(1337, ExtensionValue::Bool(false))
            .build()
            .unwrap();

        let mut actual_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&comid, &mut actual_cbor).unwrap();

        let expected_cbor: Vec<u8> = vec![
            0xbf, // map(indef) [concise-mid-tag]
              0x00, // key: 0 [language]
              0x65, // value: tstr(5)
                0x65, 0x6e, 0x2d, 0x47, 0x42, // "en-GB"
              0x01, // key: 1 [tag-identity]
              0xbf, // value: map(indef) [tag-identity-map]
                0x00, // key: 0 [tag-id]
                0x63, // value: tstr(3)
                  0x66, 0x6f, 0x6f, // "foo"
              0xff, // break
              0x02, // key: 2 [entities]
              0x81, // value: array(1)
                0xbf, // [0]map(indef) [comid-entity-map]
                  0x00, // key: 0 [entity-name]
                  0x63, // value: tstr(3)
                    0x66, 0x6f, 0x6f, // "foo"
                  0x02, // key: 2 [role]
                  0x81, // value: array(1)
                    0x01, // [0]1 [creator]
                0xff, // break
              0x03, // key: 3 [linked-tags]
              0x81, // value: array(0)
                0xbf, // [0]map(indef) [linked-tag-map]
                  0x00, // key: 0 [linked-tag-id]
                  0x63, // value: tstr(3)
                    0x62, 0x61, 0x72, // "bar"
                  0x01, // key: 1 [tag-rel]
                  0x00, // value: 0 [supplements]
                0xff, // break
              0x04, // key: 4 [triples]
              0xbf, // value: map(indef) [triples-map]
                0x01, //  key: 1 [endorsed-triples]
                0x81, // value: array(1)
                  0x82, // [0]array(2) [endorsed-triple-record]
                    0xbf, // [0]map(indef) [environment-map]
                      0x01, // key: 1 [instance]
                      0xd9, 0x02, 0x30, // value: tag(560) [tagged-bytes[
                        0x43, // bstr(3)
                          0x01, 0x02, 0x03,
                    0xff, // break
                    0x81, // [1]array(1)
                      0xbf, // [0]map(indef) [measurement-map]
                        0x01, // key: 1 [mval]
                        0xbf, // value: map(indef) [measurement-values-map]
                          0x01, // key: 1 [svn]
                          0x01, // value: 1
                        0xff, // break
                      0xff, // break
              0xff, //break
              0x19, 0x05, 0x39, // key: 1337 [extension(1337)]
              0xf4, // value: false
            0xff, // break
        ];

        assert_eq!(actual_cbor, expected_cbor);

        let actual_json = serde_json::to_string(&comid).unwrap();

        let expected_json = r#"{"language":"en-GB","tag-identity":{"tag-id":"foo"},"entities":[{"entity-name":"foo","role":["creator"]}],"linked-tags":[{"linked-tag-id":"bar","tag-rel":"supplements"}],"triples":{"endorsed-triples":[[{"instance":{"type":"bytes","value":"AQID"}},[{"mval":{"svn":1}}]]]},"1337":false}"#;

        assert_eq!(actual_json, expected_json);
    }
}
