// SPDX-License-Identifier: MIT

//! Module for handling Concise Software Identity (CoSWID) tags.
//!
//! This module implements the CoSWID specification (RFC 9393), providing structures and types for
//! describing software identity and inventory information in a concise format using CBOR encoding.
//!
//! # Key Components
//!
//! - [`ConciseSwidTag`]: The main CoSWID tag structure (CBOR tag 505)
//! - [`SoftwareMetaEntry`]: Additional metadata about software
//! - [`EntityEntry`]: Information about entities involved with the software
//! - [`LinkEntry`]: References to related resources
//!
//! # Tag Types
//!
//! CoSWID tags can be one of several types:
//! - **Corpus**: Describes the intended state of a software product
//! - **Patch**: Describes a software update or patch
//! - **Supplemental**: Provides additional information about software
//!
//! # Evidence and Payload Support
//!
//! CoSWID tags can contain either:
//! - **Payload data**: Describes intended software state
//! - **Evidence data**: Describes observed software state
//!
//! # Resource Types
//!
//! Supported resource descriptions include:
//! - Files and directories with cryptographic hashes
//! - Running processes with PIDs
//! - Generic resources with extensible attributes
//! - Integrity measurements
//!
//! # Example
//!
//! ```rust
//! use corim_rs::{
//!   coswid::{ConciseSwidTag, SoftwareMetaEntry},
//!   numbers::Integer,
//! };
//!
//! // Create a basic CoSWID tag
//! let tag = ConciseSwidTag {
//!     tag_id: "example-software".into(),
//!     tag_version: Integer(1),
//!     software_name: "Example Software".to_string().into(),
//!     entity: vec![].into(),  // Add entities here
//!     corpus: None,
//!     patch: None,
//!     supplemental: None,
//!     software_version: None,
//!     version_scheme: None,
//!     media: None,
//!     software_meta: None,
//!     link: None,
//!     payload: None,
//!     evidence: None,
//!     extensions: None,
//!     global_attributes: None,
//! };
//! ```
//!
//! # CBOR Tags
//!
//! This implementation uses CBOR tag 505 for CoSWID tags.
//!
//! # Specification Compliance
//!
//! This implementation adheres to RFC 9393 (CoSWID) and supports all mandatory
//! and optional fields defined in the standard.

use std::{fmt::Display, marker::PhantomData};

use crate::{
    error::CoswidError, generate_tagged, AnyUri, AttributeValue, Empty, ExtensionMap,
    ExtensionValue, GlobalAttributes, HashEntry, Int, Integer, IntegerTime, Label, OneOrMore, Text,
    TextOrBytes, TextOrBytesSized, Uint, Uri, VersionScheme,
};
use derive_more::{Constructor, From, TryFrom};
use serde::{
    de::{self, Visitor},
    ser::{self, SerializeMap},
    Deserialize, Serialize,
};

generate_tagged!((
    505,
    TaggedConciseSwidTag,
    ConciseSwidTag<'a>,
    'a,
    "coswid",
    "Represents a CoSWID tag wrapped with CBOR tag 505"
));

/// A Concise Software Identity (CoSWID) tag structure as defined in RFC 9393
///
/// CoSWID tags provide a standardized way to identify and describe software
/// components, including their metadata, contents, and relationships.
#[derive(Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConciseSwidTag<'a> {
    /// Unique identifier for the tag
    pub tag_id: TextOrBytes<'a>,
    /// Version number for the tag
    pub tag_version: Int,
    /// Indicates if this is a base (corpus) tag
    pub corpus: Option<bool>,
    /// Indicates if this is a patch tag
    pub patch: Option<bool>,
    /// Indicates if this is a supplemental tag
    pub supplemental: Option<bool>,
    /// Name of the software product
    pub software_name: Text<'a>,
    /// Version of the software product
    pub software_version: Option<Text<'a>>,
    /// Scheme used for version numbering
    pub version_scheme: Option<VersionScheme<'a>>,
    /// Media type or environment context
    pub media: Option<Text<'a>>,
    /// Additional metadata about the software
    pub software_meta: Option<OneOrMore<SoftwareMetaEntry<'a>>>,
    /// List of entities associated with the software
    pub entity: OneOrMore<EntityEntry<'a>>,
    /// Optional links to related resources
    pub link: Option<OneOrMore<LinkEntry<'a>>>,
    /// Optional payload data (mutually exclusive with evidence)
    pub payload: Option<PayloadEntry<'a>>,
    /// Optional evidence data (mutually exclusive with payload)
    pub evidence: Option<EvidenceEntry<'a>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to the whole tag
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for ConciseSwidTag<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("tag-id", &self.tag_id)?;
            map.serialize_entry("tag-version", &self.tag_version)?;

            if let Some(corpus) = &self.corpus {
                map.serialize_entry("corpus", corpus)?;
            }

            if let Some(patch) = &self.patch {
                map.serialize_entry("patch", patch)?;
            }

            if let Some(supplemental) = &self.supplemental {
                map.serialize_entry("supplemental", supplemental)?;
            }

            map.serialize_entry("software-name", &self.software_name)?;

            if let Some(software_version) = &self.software_version {
                map.serialize_entry("software-version", software_version)?;
            }

            if let Some(version_scheme) = &self.version_scheme {
                map.serialize_entry("version-scheme", version_scheme)?;
            }

            if let Some(media) = &self.media {
                map.serialize_entry("media", media)?;
            }

            if let Some(software_meta) = &self.software_meta {
                map.serialize_entry("software-meta", software_meta)?;
            }

            map.serialize_entry("entity", &self.entity)?;

            if let Some(link) = &self.link {
                map.serialize_entry("link", link)?;
            }

            if let Some(payload) = &self.payload {
                map.serialize_entry("payload", payload)?;
            }

            if let Some(evidence) = &self.evidence {
                map.serialize_entry("evidence", evidence)?;
            }
        } else {
            map.serialize_entry(&0, &self.tag_id)?;
            map.serialize_entry(&12, &self.tag_version)?;

            if let Some(corpus) = &self.corpus {
                map.serialize_entry(&8, corpus)?;
            }

            if let Some(patch) = &self.patch {
                map.serialize_entry(&9, patch)?;
            }

            if let Some(supplemental) = &self.supplemental {
                map.serialize_entry(&11, supplemental)?;
            }

            map.serialize_entry(&1, &self.software_name)?;

            if let Some(software_version) = &self.software_version {
                map.serialize_entry(&13, software_version)?;
            }

            if let Some(version_scheme) = &self.version_scheme {
                map.serialize_entry(&14, version_scheme)?;
            }

            if let Some(media) = &self.media {
                map.serialize_entry(&10, media)?;
            }

            if let Some(software_meta) = &self.software_meta {
                map.serialize_entry(&5, software_meta)?;
            }

            map.serialize_entry(&2, &self.entity)?;

            if let Some(link) = &self.link {
                map.serialize_entry(&4, link)?;
            }

            if let Some(payload) = &self.payload {
                map.serialize_entry(&6, payload)?;
            }

            if let Some(evidence) = &self.evidence {
                map.serialize_entry(&3, evidence)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ConciseSwidTag<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct ConciseSwidTagVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for ConciseSwidTagVisitor<'a> {
            type Value = ConciseSwidTag<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing ConciseSwidTag fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = ConciseSwidTagBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("tag-id") => {
                                builder = builder.tag_id(map.next_value::<TextOrBytes>()?);
                            }
                            Some("tag-version") => {
                                builder = builder.tag_version(map.next_value::<Int>()?);
                            }
                            Some("corpus") => {
                                builder = builder.corpus(map.next_value::<bool>()?);
                            }
                            Some("patch") => {
                                builder = builder.patch(map.next_value::<bool>()?);
                            }
                            Some("supplemental") => {
                                builder = builder.supplemental(map.next_value::<bool>()?);
                            }
                            Some("software-name") => {
                                builder = builder.software_name(map.next_value::<Text>()?);
                            }
                            Some("software-version") => {
                                builder = builder.software_version(map.next_value::<Text>()?);
                            }
                            Some("version-scheme") => {
                                builder =
                                    builder.version_scheme(map.next_value::<VersionScheme>()?);
                            }
                            Some("media") => {
                                builder = builder.media(map.next_value::<Text>()?);
                            }
                            Some("software-meta") => {
                                builder = builder.software_meta(
                                    map.next_value::<OneOrMore<SoftwareMetaEntry>>()?,
                                );
                            }
                            Some("entity") => {
                                builder =
                                    builder.entity(map.next_value::<OneOrMore<EntityEntry>>()?);
                            }
                            Some("link") => {
                                builder = builder.link(map.next_value::<OneOrMore<LinkEntry>>()?);
                            }
                            Some("payload") => {
                                builder = builder.payload(map.next_value::<PayloadEntry>()?);
                            }
                            Some("evidence") => {
                                builder = builder.evidence(map.next_value::<EvidenceEntry>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            );
                                        } else if n.is_u64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            );
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        builder = builder.add_global_attribute(
                                            Label::parse(entry),
                                            s.into(),
                                        );
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                builder = builder.add_extension(
                                                    i,
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid LinkEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                0 => {
                                    builder = builder.tag_id(map.next_value::<TextOrBytes>()?);
                                }
                                12 => {
                                    builder = builder.tag_version(map.next_value::<Int>()?);
                                }
                                8 => {
                                    builder = builder.corpus(map.next_value::<bool>()?);
                                }
                                9 => {
                                    builder = builder.patch(map.next_value::<bool>()?);
                                }
                                11 => {
                                    builder = builder.supplemental(map.next_value::<bool>()?);
                                }
                                1 => {
                                    builder = builder.software_name(map.next_value::<Text>()?);
                                }
                                13 => {
                                    builder = builder.software_version(map.next_value::<Text>()?);
                                }
                                14 => {
                                    builder =
                                        builder.version_scheme(map.next_value::<VersionScheme>()?);
                                }
                                10 => {
                                    builder = builder.media(map.next_value::<Text>()?);
                                }
                                5 => {
                                    builder = builder.software_meta(
                                        map.next_value::<OneOrMore<SoftwareMetaEntry>>()?,
                                    );
                                }
                                2 => {
                                    builder =
                                        builder.entity(map.next_value::<OneOrMore<EntityEntry>>()?);
                                }
                                4 => {
                                    builder =
                                        builder.link(map.next_value::<OneOrMore<LinkEntry>>()?);
                                }
                                6 => {
                                    builder = builder.payload(map.next_value::<PayloadEntry>()?);
                                }
                                3 => {
                                    builder = builder.evidence(map.next_value::<EvidenceEntry>()?);
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => {
                                builder = builder.add_global_attribute(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(ConciseSwidTagVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct ConciseSwidTagBuilder<'a> {
    tag_id: Option<TextOrBytes<'a>>,
    tag_version: Option<Int>,
    corpus: Option<bool>,
    patch: Option<bool>,
    supplemental: Option<bool>,
    software_name: Option<Text<'a>>,
    software_version: Option<Text<'a>>,
    version_scheme: Option<VersionScheme<'a>>,
    media: Option<Text<'a>>,
    software_meta: Option<OneOrMore<SoftwareMetaEntry<'a>>>,
    entity: Option<OneOrMore<EntityEntry<'a>>>,
    link: Option<OneOrMore<LinkEntry<'a>>>,
    payload: Option<PayloadEntry<'a>>,
    evidence: Option<EvidenceEntry<'a>>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> ConciseSwidTagBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tag_id(mut self, tag_id: TextOrBytes<'a>) -> Self {
        self.tag_id = Some(tag_id);
        self
    }

    pub fn tag_version(mut self, tag_version: Int) -> Self {
        self.tag_version = Some(tag_version);
        self
    }

    pub fn corpus(mut self, corpus: bool) -> Self {
        self.corpus = Some(corpus);
        self
    }

    pub fn patch(mut self, patch: bool) -> Self {
        self.patch = Some(patch);
        self
    }

    pub fn supplemental(mut self, supplemental: bool) -> Self {
        self.supplemental = Some(supplemental);
        self
    }

    pub fn software_name(mut self, software_name: Text<'a>) -> Self {
        self.software_name = Some(software_name);
        self
    }

    pub fn software_version(mut self, software_version: Text<'a>) -> Self {
        self.software_version = Some(software_version);
        self
    }

    pub fn version_scheme(mut self, version_scheme: VersionScheme<'a>) -> Self {
        self.version_scheme = Some(version_scheme);
        self
    }

    pub fn media(mut self, media: Text<'a>) -> Self {
        self.media = Some(media);
        self
    }

    pub fn software_meta(mut self, software_meta: OneOrMore<SoftwareMetaEntry<'a>>) -> Self {
        self.software_meta = Some(software_meta);
        self
    }

    pub fn add_software_meta(mut self, software_meta: SoftwareMetaEntry<'a>) -> Self {
        match self.software_meta {
            Some(existing) => {
                self.software_meta = Some(existing + software_meta.into());
            }
            None => self.software_meta = Some(software_meta.into()),
        }
        self
    }

    pub fn entity(mut self, entity: OneOrMore<EntityEntry<'a>>) -> Self {
        self.entity = Some(entity);
        self
    }

    pub fn add_entity(mut self, entity: EntityEntry<'a>) -> Self {
        match self.entity {
            Some(existing) => {
                self.entity = Some(existing + entity.into());
            }
            None => self.entity = Some(entity.into()),
        }
        self
    }

    pub fn link(mut self, link: OneOrMore<LinkEntry<'a>>) -> Self {
        self.link = Some(link);
        self
    }

    pub fn add_link(mut self, link: LinkEntry<'a>) -> Self {
        match self.link {
            Some(existing) => {
                self.link = Some(existing + link.into());
            }
            None => self.link = Some(link.into()),
        }
        self
    }

    pub fn payload(mut self, payload: PayloadEntry<'a>) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn evidence(mut self, evidence: EvidenceEntry<'a>) -> Self {
        self.evidence = Some(evidence);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "ProcessEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<ConciseSwidTag<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.tag_id.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "ConciseSwidTag".to_string(),
                "tag_id".to_string(),
            ))?;
        }

        if self.tag_version.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "ConciseSwidTag".to_string(),
                "tag_version".to_string(),
            ))?;
        }

        if self.software_name.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "ConciseSwidTag".to_string(),
                "software_name".to_string(),
            ))?;
        }

        if self.entity.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "ConciseSwidTag".to_string(),
                "entity".to_string(),
            ))?;
        }

        if self.payload.is_none() && self.evidence.is_none() {
            return Err(CoswidError::custom(
                "either payload or evidence must be set",
            ));
        } else if self.payload.is_some() && self.evidence.is_some() {
            return Err(CoswidError::custom(
                "payload and evidence can't both be set",
            ));
        }

        Ok(ConciseSwidTag {
            tag_id: self.tag_id.unwrap(),
            tag_version: self.tag_version.unwrap(),
            corpus: self.corpus,
            patch: self.patch,
            supplemental: self.supplemental,
            software_name: self.software_name.unwrap(),
            software_version: self.software_version,
            version_scheme: self.version_scheme,
            media: self.media,
            software_meta: self.software_meta,
            entity: self.entity.unwrap(),
            link: self.link,
            payload: self.payload,
            evidence: self.evidence,
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Additional metadata about the software component
///
/// This structure contains supplementary information about software that may be
/// useful for identification, deployment, or management purposes. All fields
/// are optional except for global attributes.
#[repr(C)]
#[derive(Default, Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct SoftwareMetaEntry<'a> {
    /// Current activation status of the software (e.g., "trial", "full", "deleted")
    pub activation_status: Option<Text<'a>>,
    /// Distribution channel type (e.g., "retail", "enterprise", "beta")
    pub channel_type: Option<Text<'a>>,
    /// Informal or marketing version name
    pub coloquial_version: Option<Text<'a>>,
    /// Detailed description of the software
    pub description: Option<Text<'a>>,
    /// Edition or variation of the software
    pub edition: Option<Text<'a>>,
    /// Indicates if entitlement data is required to use the software
    pub entitlement_data_required: Option<bool>,
    /// Key used for software entitlement
    pub entitlement_key: Option<Text<'a>>,
    /// Tool that generated this metadata (16 bytes max)
    pub generator: Option<TextOrBytesSized<'a, 16>>,
    /// Persistent identifier for the software
    pub persistent_id: Option<Text<'a>>,
    /// Product name
    pub product: Option<Text<'a>>,
    /// Product family name
    pub product_family: Option<Text<'a>>,
    /// Revision identifier
    pub revision: Option<Text<'a>>,
    /// Brief description of the software
    pub summary: Option<Text<'a>>,
    /// UNSPSC classification code
    pub unspsc_code: Option<Text<'a>>,
    /// Version of UNSPSC codeset used
    pub unspsc_version: Option<Text<'a>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this metadata entry
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for SoftwareMetaEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(activation_status) = &self.activation_status {
                map.serialize_entry("activation-status", activation_status)?;
            }

            if let Some(channel_type) = &self.channel_type {
                map.serialize_entry("channel-type", channel_type)?;
            }

            if let Some(coloquial_version) = &self.coloquial_version {
                map.serialize_entry("coloquial-version", coloquial_version)?;
            }

            if let Some(description) = &self.description {
                map.serialize_entry("description", description)?;
            }

            if let Some(edition) = &self.edition {
                map.serialize_entry("edition", edition)?;
            }

            if let Some(entitlement_data_required) = &self.entitlement_data_required {
                map.serialize_entry("entitlement-data-required", entitlement_data_required)?;
            }

            if let Some(entitlement_key) = &self.entitlement_key {
                map.serialize_entry("entitlement-key", entitlement_key)?;
            }

            if let Some(generator) = &self.generator {
                map.serialize_entry("generator", generator)?;
            }

            if let Some(persistent_id) = &self.persistent_id {
                map.serialize_entry("persistent-id", persistent_id)?;
            }

            if let Some(product) = &self.product {
                map.serialize_entry("product", product)?;
            }

            if let Some(product_family) = &self.product_family {
                map.serialize_entry("product-family", product_family)?;
            }

            if let Some(revision) = &self.revision {
                map.serialize_entry("revision", revision)?;
            }

            if let Some(summary) = &self.summary {
                map.serialize_entry("summary", summary)?;
            }

            if let Some(unspsc_code) = &self.unspsc_code {
                map.serialize_entry("unspsc-code", unspsc_code)?;
            }

            if let Some(unspsc_version) = &self.unspsc_version {
                map.serialize_entry("unspsc-version", unspsc_version)?;
            }
        } else {
            if let Some(activation_status) = &self.activation_status {
                map.serialize_entry(&43, activation_status)?;
            }

            if let Some(channel_type) = &self.channel_type {
                map.serialize_entry(&44, channel_type)?;
            }

            if let Some(coloquial_version) = &self.coloquial_version {
                map.serialize_entry(&45, coloquial_version)?;
            }

            if let Some(description) = &self.description {
                map.serialize_entry(&46, description)?;
            }

            if let Some(edition) = &self.edition {
                map.serialize_entry(&47, edition)?;
            }

            if let Some(entitlement_data_required) = &self.entitlement_data_required {
                map.serialize_entry(&48, entitlement_data_required)?;
            }

            if let Some(entitlement_key) = &self.entitlement_key {
                map.serialize_entry(&49, entitlement_key)?;
            }

            if let Some(generator) = &self.generator {
                map.serialize_entry(&50, generator)?;
            }

            if let Some(persistent_id) = &self.persistent_id {
                map.serialize_entry(&51, persistent_id)?;
            }

            if let Some(product) = &self.product {
                map.serialize_entry(&52, product)?;
            }

            if let Some(product_family) = &self.product_family {
                map.serialize_entry(&53, product_family)?;
            }

            if let Some(revision) = &self.revision {
                map.serialize_entry(&54, revision)?;
            }

            if let Some(summary) = &self.summary {
                map.serialize_entry(&55, summary)?;
            }

            if let Some(unspsc_code) = &self.unspsc_code {
                map.serialize_entry(&56, unspsc_code)?;
            }

            if let Some(unspsc_version) = &self.unspsc_version {
                map.serialize_entry(&57, unspsc_version)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for SoftwareMetaEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct SoftwareMetaEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for SoftwareMetaEntryVisitor<'a> {
            type Value = SoftwareMetaEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing SoftwareMetaEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = SoftwareMetaEntryBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("activation-status") => {
                                builder = builder.activation_status(map.next_value::<Text>()?);
                            }
                            Some("channel-type") => {
                                builder = builder.channel_type(map.next_value::<Text>()?);
                            }
                            Some("coloquial-version") => {
                                builder = builder.coloquial_version(map.next_value::<Text>()?);
                            }
                            Some("description") => {
                                builder = builder.description(map.next_value::<Text>()?);
                            }
                            Some("edition") => {
                                builder = builder.edition(map.next_value::<Text>()?);
                            }
                            Some("entitlement-data-required") => {
                                builder =
                                    builder.entitlement_data_required(map.next_value::<bool>()?);
                            }
                            Some("entitlement-key") => {
                                builder = builder.entitlement_key(map.next_value::<Text>()?);
                            }
                            Some("generator") => {
                                builder =
                                    builder.generator(map.next_value::<TextOrBytesSized<16>>()?);
                            }
                            Some("persistent-id") => {
                                builder = builder.persistent_id(map.next_value::<Text>()?);
                            }
                            Some("product") => {
                                builder = builder.product(map.next_value::<Text>()?);
                            }
                            Some("product-family") => {
                                builder = builder.product_family(map.next_value::<Text>()?);
                            }
                            Some("revision") => {
                                builder = builder.revision(map.next_value::<Text>()?);
                            }
                            Some("summary") => {
                                builder = builder.summary(map.next_value::<Text>()?);
                            }
                            Some("unspsc-code") => {
                                builder = builder.unspsc_code(map.next_value::<Text>()?);
                            }
                            Some("unspsc-version") => {
                                builder = builder.unspsc_version(map.next_value::<Text>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            );
                                        } else if n.is_u64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            );
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        builder = builder.add_global_attribute(
                                            Label::parse(entry),
                                            s.into(),
                                        );
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                builder = builder.add_extension(
                                                    i,
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid LinkEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                43 => {
                                    builder = builder.activation_status(map.next_value::<Text>()?);
                                }
                                44 => {
                                    builder = builder.channel_type(map.next_value::<Text>()?);
                                }
                                45 => {
                                    builder = builder.coloquial_version(map.next_value::<Text>()?);
                                }
                                46 => {
                                    builder = builder.description(map.next_value::<Text>()?);
                                }
                                47 => {
                                    builder = builder.edition(map.next_value::<Text>()?);
                                }
                                48 => {
                                    builder = builder
                                        .entitlement_data_required(map.next_value::<bool>()?);
                                }
                                49 => {
                                    builder = builder.entitlement_key(map.next_value::<Text>()?);
                                }
                                50 => {
                                    builder = builder
                                        .generator(map.next_value::<TextOrBytesSized<16>>()?);
                                }
                                51 => {
                                    builder = builder.persistent_id(map.next_value::<Text>()?);
                                }
                                52 => {
                                    builder = builder.product(map.next_value::<Text>()?);
                                }
                                53 => {
                                    builder = builder.product_family(map.next_value::<Text>()?);
                                }
                                54 => {
                                    builder = builder.revision(map.next_value::<Text>()?);
                                }
                                55 => {
                                    builder = builder.summary(map.next_value::<Text>()?);
                                }
                                56 => {
                                    builder = builder.unspsc_code(map.next_value::<Text>()?);
                                }
                                57 => {
                                    builder = builder.unspsc_version(map.next_value::<Text>()?);
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => {
                                builder = builder.add_global_attribute(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(SoftwareMetaEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct SoftwareMetaEntryBuilder<'a> {
    activation_status: Option<Text<'a>>,
    channel_type: Option<Text<'a>>,
    coloquial_version: Option<Text<'a>>,
    description: Option<Text<'a>>,
    edition: Option<Text<'a>>,
    entitlement_data_required: Option<bool>,
    entitlement_key: Option<Text<'a>>,
    generator: Option<TextOrBytesSized<'a, 16>>,
    persistent_id: Option<Text<'a>>,
    product: Option<Text<'a>>,
    product_family: Option<Text<'a>>,
    revision: Option<Text<'a>>,
    summary: Option<Text<'a>>,
    unspsc_code: Option<Text<'a>>,
    unspsc_version: Option<Text<'a>>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> SoftwareMetaEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn activation_status(mut self, activation_status: Text<'a>) -> Self {
        self.activation_status = Some(activation_status);
        self
    }

    pub fn channel_type(mut self, channel_type: Text<'a>) -> Self {
        self.channel_type = Some(channel_type);
        self
    }

    pub fn coloquial_version(mut self, coloquial_version: Text<'a>) -> Self {
        self.coloquial_version = Some(coloquial_version);
        self
    }

    pub fn description(mut self, description: Text<'a>) -> Self {
        self.description = Some(description);
        self
    }

    pub fn edition(mut self, edition: Text<'a>) -> Self {
        self.edition = Some(edition);
        self
    }

    pub fn entitlement_data_required(mut self, entitlement_data_required: bool) -> Self {
        self.entitlement_data_required = Some(entitlement_data_required);
        self
    }

    pub fn entitlement_key(mut self, entitlement_key: Text<'a>) -> Self {
        self.entitlement_key = Some(entitlement_key);
        self
    }

    pub fn generator(mut self, generator: TextOrBytesSized<'a, 16>) -> Self {
        self.generator = Some(generator);
        self
    }

    pub fn persistent_id(mut self, persistent_id: Text<'a>) -> Self {
        self.persistent_id = Some(persistent_id);
        self
    }

    pub fn product(mut self, product: Text<'a>) -> Self {
        self.product = Some(product);
        self
    }

    pub fn product_family(mut self, product_family: Text<'a>) -> Self {
        self.product_family = Some(product_family);
        self
    }

    pub fn revision(mut self, revision: Text<'a>) -> Self {
        self.revision = Some(revision);
        self
    }

    pub fn summary(mut self, summary: Text<'a>) -> Self {
        self.summary = Some(summary);
        self
    }

    pub fn unspsc_code(mut self, unspsc_code: Text<'a>) -> Self {
        self.unspsc_code = Some(unspsc_code);
        self
    }

    pub fn unspsc_version(mut self, unspsc_version: Text<'a>) -> Self {
        self.unspsc_version = Some(unspsc_version);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "EntityEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<SoftwareMetaEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.activation_status.is_none()
            && self.channel_type.is_none()
            && self.coloquial_version.is_none()
            && self.description.is_none()
            && self.edition.is_none()
            && self.entitlement_data_required.is_none()
            && self.entitlement_key.is_none()
            && self.generator.is_none()
            && self.persistent_id.is_none()
            && self.product.is_none()
            && self.product_family.is_none()
            && self.revision.is_none()
            && self.summary.is_none()
            && self.unspsc_code.is_none()
            && self.unspsc_version.is_none()
            && (self.extensions.is_none() || self.extensions.as_ref().unwrap().is_empty())
            && (self.global_attributes.is_none()
                || self.global_attributes.as_ref().unwrap().is_empty())
        {
            return Err(CoswidError::custom("SoftwareMetaEntry cannot be empty"));
        }

        Ok(SoftwareMetaEntry {
            activation_status: self.activation_status,
            channel_type: self.channel_type,
            coloquial_version: self.coloquial_version,
            description: self.description,
            edition: self.edition,
            entitlement_data_required: self.entitlement_data_required,
            entitlement_key: self.entitlement_key,
            generator: self.generator,
            persistent_id: self.persistent_id,
            product: self.product,
            product_family: self.product_family,
            revision: self.revision,
            summary: self.summary,
            unspsc_code: self.unspsc_code,
            unspsc_version: self.unspsc_version,
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
pub enum Role<'a> {
    TagCreator = 1,
    SoftwareCreator = 2,
    Aggregator = 3,
    Distributor = 4,
    Licensor = 5,
    Maintainer = 6,
    IntOrText(Label<'a>),
}

impl From<i64> for Role<'_> {
    fn from(value: i64) -> Self {
        (value as i128).into()
    }
}

impl From<i128> for Role<'_> {
    fn from(value: i128) -> Self {
        match value {
            1 => Self::TagCreator,
            2 => Self::SoftwareCreator,
            3 => Self::Aggregator,
            4 => Self::Distributor,
            5 => Self::Licensor,
            6 => Self::Maintainer,
            i => Self::IntOrText(i.into()),
        }
    }
}

impl TryFrom<&Role<'_>> for i64 {
    type Error = CoswidError;

    fn try_from(value: &Role<'_>) -> Result<Self, Self::Error> {
        match i128::try_from(value) {
            Ok(i) => {
                if i >= i64::MIN as i128 && i <= i64::MAX as i128 {
                    Ok(i as i64)
                } else {
                    Err(CoswidError::InvalidValue(format!("out of i64 bounds: {i}")))
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl TryFrom<&Role<'_>> for i128 {
    type Error = CoswidError;

    fn try_from(value: &Role<'_>) -> Result<Self, Self::Error> {
        match value {
            Role::TagCreator => Ok(1),
            Role::SoftwareCreator => Ok(2),
            Role::Aggregator => Ok(3),
            Role::Distributor => Ok(4),
            Role::Licensor => Ok(5),
            Role::Maintainer => Ok(6),
            Role::IntOrText(label) => match label {
                Label::Int(i) => Ok(i.0),
                Label::Text(text) => {
                    Err(CoswidError::InvalidValue(format!("not an integer: {text}")))
                }
            },
        }
    }
}

impl<'a> From<&'a str> for Role<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "tag-creator" => Self::TagCreator,
            "software-creator" => Self::SoftwareCreator,
            "aggregator" => Self::Aggregator,
            "distributor" => Self::Distributor,
            "licensor" => Self::Licensor,
            "maintainer" => Self::Maintainer,
            other => match other.parse::<i128>() {
                Ok(i) => i.into(),
                Err(_) => Self::IntOrText(value.into()),
            },
        }
    }
}

impl From<String> for Role<'_> {
    fn from(value: String) -> Self {
        match value.as_str() {
            "tag-creator" => Self::TagCreator,
            "software-creator" => Self::SoftwareCreator,
            "aggregator" => Self::Aggregator,
            "distributor" => Self::Distributor,
            "licensor" => Self::Licensor,
            "maintainer" => Self::Maintainer,
            other => match other.parse::<i128>() {
                Ok(i) => i.into(),
                Err(_) => Self::IntOrText(value.into()),
            },
        }
    }
}

impl Display for Role<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s;

        f.write_str(match self {
            Self::TagCreator => "tag-creator",
            Self::SoftwareCreator => "software-creator",
            Self::Aggregator => "aggregator",
            Self::Distributor => "distributor",
            Self::Licensor => "licensor",
            Self::Maintainer => "maintainer",
            Self::IntOrText(label) => {
                s = label.to_string();
                s.as_str()
            }
        })
    }
}

impl Serialize for Role<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::IntOrText(label) => label.serialize(serializer),
                other => serializer.serialize_str(other.to_string().as_str()),
            }
        } else {
            match i128::try_from(self) {
                Ok(i) => i.serialize(serializer),
                Err(_) => self.to_string().serialize(serializer),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Role<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let label = Label::deserialize(deserializer)?;

        match label {
            Label::Int(i) => Ok(i.0.into()),
            Label::Text(text) => Ok(text.to_string().into()),
        }
    }
}

/// Information about an entity involved in software development or distribution
#[repr(C)]
#[derive(Debug, Constructor, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct EntityEntry<'a> {
    /// Name of the entity
    pub entity_name: Text<'a>,
    /// Optional registration identifier URI for the entity
    pub reg_id: Option<Uri<'a>>,
    /// One or more roles this entity fulfills
    pub role: OneOrMore<Role<'a>>,
    /// Optional cryptographic hash for entity verification
    pub thumbprint: Option<HashEntry>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this entity
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for EntityEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
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

            if let Some(thumbprint) = &self.thumbprint {
                map.serialize_entry("thumbprint", thumbprint)?;
            }
        } else {
            map.serialize_entry(&31, &self.entity_name)?;

            if let Some(reg_id) = &self.reg_id {
                map.serialize_entry(&32, reg_id)?;
            }

            map.serialize_entry(&33, &self.role)?;

            if let Some(thumbprint) = &self.thumbprint {
                map.serialize_entry(&34, thumbprint)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for EntityEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct EntityEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for EntityEntryVisitor<'a> {
            type Value = EntityEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing EntityEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = EntityEntryBuilder::new();

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
                                builder = builder.role(map.next_value::<OneOrMore<Role>>()?);
                            }
                            Some("thumbprint") => {
                                builder = builder.thumbprint(map.next_value::<HashEntry>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            );
                                        } else if n.is_u64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            );
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        builder = builder.add_global_attribute(
                                            Label::parse(entry),
                                            s.into(),
                                        );
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                builder = builder.add_extension(
                                                    i,
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid EntityEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                31 => {
                                    builder = builder.entity_name(map.next_value::<Text>()?);
                                }
                                32 => {
                                    builder = builder.reg_id(map.next_value::<Uri>()?);
                                }
                                33 => {
                                    builder = builder.role(map.next_value::<OneOrMore<Role>>()?);
                                }
                                34 => {
                                    builder = builder.thumbprint(map.next_value::<HashEntry>()?);
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => {
                                builder = builder.add_global_attribute(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(EntityEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct EntityEntryBuilder<'a> {
    entity_name: Option<Text<'a>>,
    reg_id: Option<Uri<'a>>,
    role: Option<OneOrMore<Role<'a>>>,
    thumbprint: Option<HashEntry>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> EntityEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entity_name(mut self, entity_name: Text<'a>) -> Self {
        self.entity_name = Some(entity_name);
        self
    }

    pub fn reg_id(mut self, reg_id: Uri<'a>) -> Self {
        self.reg_id = Some(reg_id);
        self
    }

    pub fn role(mut self, role: OneOrMore<Role<'a>>) -> Self {
        self.role = Some(role);
        self
    }

    pub fn add_role(mut self, role: Role<'a>) -> Self {
        match self.role {
            Some(existing) => {
                self.role = Some(existing + role.into());
            }
            None => self.role = Some(role.into()),
        }
        self
    }

    pub fn thumbprint(mut self, thumbprint: HashEntry) -> Self {
        self.thumbprint = Some(thumbprint);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "EntityEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<EntityEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.entity_name.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "EntityEntry".to_string(),
                "entity_name".to_string(),
            ))?;
        }

        if self.role.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "EntityEntry".to_string(),
                "role".to_string(),
            ))?;
        }

        Ok(EntityEntry {
            entity_name: self.entity_name.unwrap(),
            reg_id: self.reg_id,
            role: self.role.unwrap(),
            thumbprint: self.thumbprint,
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Link to external resources related to the software
#[repr(C)]
#[derive(Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct LinkEntry<'a> {
    /// Optional identifier for the linked artifact
    pub artifact: Option<Text<'a>>,
    /// URI reference to the linked resource
    pub href: AnyUri<'a>,
    /// Optional media type or context
    pub media: Option<Text<'a>>,
    /// Optional ownership status of the linked resource
    pub ownership: Option<Ownership<'a>>,
    /// Relationship type between this tag and the linked resource
    pub rel: Rel<'a>,
    /// Optional MIME type of the linked resource
    pub media_type: Option<Text<'a>>,
    /// Optional usage requirement level
    pub r#use: Option<Use<'a>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this link
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for LinkEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(artifact) = &self.artifact {
                map.serialize_entry("artifact", artifact)?;
            }

            map.serialize_entry("href", &self.href)?;

            if let Some(media) = &self.media {
                map.serialize_entry("media", media)?;
            }

            if let Some(ownership) = &self.ownership {
                map.serialize_entry("ownership", ownership)?;
            }

            map.serialize_entry("rel", &self.rel)?;

            if let Some(media_type) = &self.media_type {
                map.serialize_entry("media-type", media_type)?;
            }

            if let Some(r#use) = &self.r#use {
                map.serialize_entry("use", r#use)?;
            }
        } else {
            if let Some(artifact) = &self.artifact {
                map.serialize_entry(&37, artifact)?;
            }

            map.serialize_entry(&38, &self.href)?;

            if let Some(media) = &self.media {
                map.serialize_entry(&10, media)?;
            }

            if let Some(ownership) = &self.ownership {
                map.serialize_entry(&39, ownership)?;
            }

            map.serialize_entry(&40, &self.rel)?;

            if let Some(media_type) = &self.media_type {
                map.serialize_entry(&41, media_type)?;
            }

            if let Some(r#use) = &self.r#use {
                map.serialize_entry(&42, r#use)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for LinkEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct LinkEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for LinkEntryVisitor<'a> {
            type Value = LinkEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing LinkEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = LinkEntryBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("artifact") => {
                                builder = builder.artifact(map.next_value::<Text>()?);
                            }
                            Some("href") => {
                                builder = builder.href(map.next_value::<AnyUri>()?);
                            }
                            Some("media") => {
                                builder = builder.media(map.next_value::<Text>()?);
                            }
                            Some("ownership") => {
                                builder = builder.ownership(map.next_value::<Ownership>()?);
                            }
                            Some("rel") => {
                                builder = builder.rel(map.next_value::<Rel>()?);
                            }
                            Some("media-type") => {
                                builder = builder.media_type(map.next_value::<Text>()?);
                            }
                            Some("use") => {
                                builder = builder.r#use(map.next_value::<Use>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            );
                                        } else if n.is_u64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            );
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        builder = builder.add_global_attribute(
                                            Label::parse(entry),
                                            s.into(),
                                        );
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                builder = builder.add_extension(
                                                    i,
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid LinkEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                37 => {
                                    builder = builder.artifact(map.next_value::<Text>()?);
                                }
                                38 => {
                                    builder = builder.href(map.next_value::<AnyUri>()?);
                                }
                                10 => {
                                    builder = builder.media(map.next_value::<Text>()?);
                                }
                                39 => {
                                    builder = builder.ownership(map.next_value::<Ownership>()?);
                                }
                                40 => {
                                    builder = builder.rel(map.next_value::<Rel>()?);
                                }
                                41 => {
                                    builder = builder.media_type(map.next_value::<Text>()?);
                                }
                                42 => {
                                    builder = builder.r#use(map.next_value::<Use>()?);
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => {
                                builder = builder.add_global_attribute(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(LinkEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct LinkEntryBuilder<'a> {
    artifact: Option<Text<'a>>,
    href: Option<AnyUri<'a>>,
    media: Option<Text<'a>>,
    ownership: Option<Ownership<'a>>,
    rel: Option<Rel<'a>>,
    media_type: Option<Text<'a>>,
    r#use: Option<Use<'a>>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> LinkEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn artifact(mut self, artifact: Text<'a>) -> Self {
        self.artifact = Some(artifact);
        self
    }

    pub fn href(mut self, href: AnyUri<'a>) -> Self {
        self.href = Some(href);
        self
    }

    pub fn media(mut self, media: Text<'a>) -> Self {
        self.media = Some(media);
        self
    }

    pub fn ownership(mut self, ownership: Ownership<'a>) -> Self {
        self.ownership = Some(ownership);
        self
    }

    pub fn rel(mut self, rel: Rel<'a>) -> Self {
        self.rel = Some(rel);
        self
    }

    pub fn media_type(mut self, media_type: Text<'a>) -> Self {
        self.media_type = Some(media_type);
        self
    }

    pub fn r#use(mut self, r#use: Use<'a>) -> Self {
        self.r#use = Some(r#use);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "LinkEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<LinkEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.href.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "LinkEntry".to_string(),
                "herf".to_string(),
            ))?;
        }

        if self.rel.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "LinkEntry".to_string(),
                "rel".to_string(),
            ))?;
        }

        Ok(LinkEntry {
            artifact: self.artifact,
            href: self.href.unwrap(),
            media: self.media,
            ownership: self.ownership,
            rel: self.rel.unwrap(),
            media_type: self.media_type,
            r#use: self.r#use,
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Ownership status enumeration for linked resources
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
pub enum Ownership<'a> {
    /// Resource is no longer maintained
    Abandon = 1,
    /// Resource is privately owned
    Private = 2,
    /// Resource is shared among multiple parties
    Shared = 3,
    /// Custom ownership type using integer or text label
    IntOrText(Label<'a>),
}

impl From<i64> for Ownership<'_> {
    fn from(value: i64) -> Self {
        (value as i128).into()
    }
}

impl From<i128> for Ownership<'_> {
    fn from(value: i128) -> Self {
        match value {
            1 => Self::Abandon,
            2 => Self::Private,
            3 => Self::Shared,
            i => Self::IntOrText(i.into()),
        }
    }
}

impl TryFrom<&Ownership<'_>> for i64 {
    type Error = CoswidError;

    fn try_from(value: &Ownership<'_>) -> Result<Self, Self::Error> {
        match i128::try_from(value) {
            Ok(i) => {
                if i >= i64::MIN as i128 && i <= i64::MAX as i128 {
                    Ok(i as i64)
                } else {
                    Err(CoswidError::InvalidValue(format!("out of i64 bounds: {i}")))
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl TryFrom<&Ownership<'_>> for i128 {
    type Error = CoswidError;

    fn try_from(value: &Ownership<'_>) -> Result<Self, Self::Error> {
        match value {
            Ownership::Abandon => Ok(1),
            Ownership::Private => Ok(2),
            Ownership::Shared => Ok(3),
            Ownership::IntOrText(label) => match label {
                Label::Int(i) => Ok(i.0),
                Label::Text(text) => {
                    Err(CoswidError::InvalidValue(format!("not an integer: {text}")))
                }
            },
        }
    }
}

impl<'a> From<&'a str> for Ownership<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "abandon" => Self::Abandon,
            "private" => Self::Private,
            "shared" => Self::Shared,
            other => match other.parse::<i128>() {
                Ok(i) => i.into(),
                Err(_) => Self::IntOrText(value.into()),
            },
        }
    }
}

impl From<String> for Ownership<'_> {
    fn from(value: String) -> Self {
        match value.as_str() {
            "abandon" => Self::Abandon,
            "private" => Self::Private,
            "shared" => Self::Shared,
            other => match other.parse::<i128>() {
                Ok(i) => i.into(),
                Err(_) => Self::IntOrText(value.into()),
            },
        }
    }
}

impl Display for Ownership<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s;

        f.write_str(match self {
            Self::Abandon => "abandon",
            Self::Private => "private",
            Self::Shared => "shared",
            Self::IntOrText(label) => {
                s = label.to_string();
                s.as_str()
            }
        })
    }
}

impl Serialize for Ownership<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::IntOrText(label) => label.serialize(serializer),
                other => serializer.serialize_str(other.to_string().as_str()),
            }
        } else {
            match i128::try_from(self) {
                Ok(i) => i.serialize(serializer),
                Err(_) => self.to_string().serialize(serializer),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Ownership<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let label = Label::deserialize(deserializer)?;

        match label {
            Label::Int(i) => Ok(i.0.into()),
            Label::Text(text) => Ok(text.to_string().into()),
        }
    }
}

/// Relationship types between resources in CoSWID tags
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
pub enum Rel<'a> {
    /// Previous version of the software
    Ancestor = 1,
    /// Part of the software
    Component = 2,
    /// Optional feature
    Feature = 3,
    /// Installation media for the software
    InstallationMedia = 4,
    /// Package installer for the software
    PackageInstaller = 5,
    /// Parent software package
    Parent = 6,
    /// Patches or updates the software
    Patches = 7,
    /// Required dependency
    Requires = 8,
    /// Related reference material
    SeeAlso = 9,
    /// Replaces older version
    Supersedes = 10,
    /// Additional content
    Supplemental = 11,
    /// Custom relationship type
    IntOrText(Label<'a>),
}

impl TryFrom<i64> for Rel<'_> {
    type Error = CoswidError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        (value as i128).try_into()
    }
}

impl TryFrom<i128> for Rel<'_> {
    type Error = CoswidError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ancestor),
            2 => Ok(Self::Component),
            3 => Ok(Self::Feature),
            4 => Ok(Self::InstallationMedia),
            5 => Ok(Self::PackageInstaller),
            6 => Ok(Self::Parent),
            7 => Ok(Self::Patches),
            8 => Ok(Self::Requires),
            9 => Ok(Self::SeeAlso),
            10 => Ok(Self::Supersedes),
            11 => Ok(Self::Supplemental),
            i => {
                if i >= -256 && i <= u16::MAX as i128 {
                    Ok(Self::IntOrText(i.into()))
                } else {
                    Err(CoswidError::InvalidValue(format!("invalid rel: {i}")))
                }
            }
        }
    }
}

impl TryFrom<&Rel<'_>> for i64 {
    type Error = CoswidError;

    fn try_from(value: &Rel<'_>) -> Result<Self, Self::Error> {
        let i: i128 = value.try_into()?;

        if i <= i64::MAX as i128 {
            Ok(i as i64)
        } else {
            Err(CoswidError::InvalidValue(format!("too large for i64: {i}")))
        }
    }
}

impl TryFrom<&Rel<'_>> for i128 {
    type Error = CoswidError;

    fn try_from(value: &Rel<'_>) -> Result<Self, Self::Error> {
        match value {
            Rel::Ancestor => Ok(1),
            Rel::Component => Ok(2),
            Rel::Feature => Ok(3),
            Rel::InstallationMedia => Ok(4),
            Rel::PackageInstaller => Ok(5),
            Rel::Parent => Ok(6),
            Rel::Patches => Ok(7),
            Rel::Requires => Ok(8),
            Rel::SeeAlso => Ok(9),
            Rel::Supersedes => Ok(10),
            Rel::Supplemental => Ok(11),
            Rel::IntOrText(label) => match label {
                Label::Int(i) => {
                    if i.0 >= -256 && i.0 <= u16::MAX as i128 {
                        Ok(i.0)
                    } else {
                        Err(CoswidError::InvalidValue(format!("invalid rel: {i}")))
                    }
                }
                Label::Text(text) => Err(CoswidError::InvalidValue(format!(
                    "not an integer: \"{text}\""
                ))),
            },
        }
    }
}

impl<'a> TryFrom<&'a str> for Rel<'a> {
    type Error = CoswidError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "ancestor" => Ok(Self::Ancestor),
            "component" => Ok(Self::Component),
            "feature" => Ok(Self::Feature),
            "installation-media" => Ok(Self::InstallationMedia),
            "package-installer" => Ok(Self::PackageInstaller),
            "parent" => Ok(Self::Parent),
            "patches" => Ok(Self::Patches),
            "requires" => Ok(Self::Requires),
            "see-also" => Ok(Self::SeeAlso),
            "supersedes" => Ok(Self::Supersedes),
            "supplemental" => Ok(Self::Supplemental),
            other => match other.parse::<i128>() {
                Ok(i) => i.try_into(),
                Err(_) => Ok(Self::IntOrText(value.into())),
            },
        }
    }
}

impl TryFrom<String> for Rel<'_> {
    type Error = CoswidError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ancestor" => Ok(Self::Ancestor),
            "component" => Ok(Self::Component),
            "feature" => Ok(Self::Feature),
            "installation-media" => Ok(Self::InstallationMedia),
            "package-installer" => Ok(Self::PackageInstaller),
            "parent" => Ok(Self::Parent),
            "patches" => Ok(Self::Patches),
            "requires" => Ok(Self::Requires),
            "see-also" => Ok(Self::SeeAlso),
            "supersedes" => Ok(Self::Supersedes),
            "supplemental" => Ok(Self::Supplemental),
            other => match other.parse::<i128>() {
                Ok(i) => i.try_into(),
                Err(_) => Ok(Self::IntOrText(value.into())),
            },
        }
    }
}

impl Display for Rel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s;

        f.write_str(match self {
            Self::Ancestor => "ancestor",
            Self::Component => "component",
            Self::Feature => "feature",
            Self::InstallationMedia => "installation-media",
            Self::PackageInstaller => "package-installer",
            Self::Parent => "parent",
            Self::Patches => "patches",
            Self::Requires => "requires",
            Self::SeeAlso => "see-also",
            Self::Supersedes => "supersedes",
            Self::Supplemental => "supplemental",
            Self::IntOrText(label) => {
                s = label.to_string();
                s.as_str()
            }
        })
    }
}

impl Serialize for Rel<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::IntOrText(label) => label.serialize(serializer),
                other => serializer.serialize_str(other.to_string().as_str()),
            }
        } else {
            match i128::try_from(self) {
                Ok(i) => i.serialize(serializer),
                Err(_) => self.to_string().serialize(serializer),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Rel<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let label = Label::deserialize(deserializer)?;
        match label {
            Label::Int(i) => Rel::try_from(i.0).map_err(de::Error::custom),
            Label::Text(text) => Rel::try_from(text.to_string()).map_err(de::Error::custom),
        }
    }
}

/// Detailed payload information about software resources
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct PayloadEntry<'a> {
    /// Collection of resources in the software
    pub resource_collection: ResourceCollection<'a>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this payload entry
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl<'a> From<ResourceCollection<'a>> for PayloadEntry<'a> {
    fn from(value: ResourceCollection<'a>) -> Self {
        PayloadEntry {
            resource_collection: value,
            extensions: None,
            global_attributes: None,
        }
    }
}

impl Serialize for PayloadEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        self.resource_collection
            .serialize_map(&mut map, is_human_readable)?;

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for PayloadEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct PayloadEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for PayloadEntryVisitor<'a> {
            type Value = PayloadEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing PayloadEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut rc_builder = ResourceCollectionBuilder::new();
                let mut extensions = ExtensionMap::new();
                let mut global_attributes = GlobalAttributes::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("directory") => {
                                rc_builder = rc_builder
                                    .directory(map.next_value::<OneOrMore<DirectoryEntry<'a>>>()?);
                            }
                            Some("file") => {
                                rc_builder =
                                    rc_builder.file(map.next_value::<OneOrMore<FileEntry<'a>>>()?);
                            }
                            Some("process") => {
                                rc_builder = rc_builder
                                    .process(map.next_value::<OneOrMore<ProcessEntry<'a>>>()?);
                            }
                            Some("resource") => {
                                rc_builder = rc_builder
                                    .resource(map.next_value::<OneOrMore<ResourceEntry<'a>>>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            global_attributes.insert(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            ).map_err(de::Error::custom)?;
                                        } else if n.is_u64() {
                                            global_attributes.insert(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            ).map_err(de::Error::custom)?;
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        global_attributes.insert(
                                            Label::parse(entry),
                                            s.into(),
                                        ).map_err(de::Error::custom)?;
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                extensions.insert(
                                                    i.into(),
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid PayloadEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                16 => {
                                    rc_builder = rc_builder.directory(
                                        map.next_value::<OneOrMore<DirectoryEntry<'a>>>()?,
                                    );
                                }
                                17 => {
                                    rc_builder = rc_builder
                                        .file(map.next_value::<OneOrMore<FileEntry<'a>>>()?);
                                }
                                18 => {
                                    rc_builder = rc_builder
                                        .process(map.next_value::<OneOrMore<ProcessEntry<'a>>>()?);
                                }
                                19 => {
                                    rc_builder = rc_builder.resource(
                                        map.next_value::<OneOrMore<ResourceEntry<'a>>>()?,
                                    );
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            global_attributes
                                                .insert(
                                                    Label::Int(entry.into()),
                                                    i128::from(n).into(),
                                                )
                                                .map_err(de::Error::custom)?;
                                        }
                                        ciborium::Value::Text(s) => {
                                            global_attributes
                                                .insert(Label::Int(entry.into()), s.into())
                                                .map_err(de::Error::custom)?;
                                        }
                                        other => {
                                            extensions.insert(
                                                entry.into(),
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => global_attributes
                                .insert(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                                .map_err(de::Error::custom)?,
                            None => break,
                        }
                    }
                }

                let mut payload_builder = PayloadEntryBuilder::new()
                    .resource_collection(rc_builder.build().map_err(de::Error::custom)?);

                if !extensions.is_empty() {
                    payload_builder = payload_builder.extensions(extensions);
                }

                if !global_attributes.is_empty() {
                    payload_builder = payload_builder.global_attributes(global_attributes);
                }

                payload_builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(PayloadEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct PayloadEntryBuilder<'a> {
    resource_collection: Option<ResourceCollection<'a>>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> PayloadEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resource_collection(mut self, resource_collection: ResourceCollection<'a>) -> Self {
        self.resource_collection = Some(resource_collection);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "EntityEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<PayloadEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.resource_collection.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "PayloadEntry".to_string(),
                "resource_collection".to_string(),
            ))?;
        }

        Ok(PayloadEntry {
            resource_collection: self.resource_collection.unwrap(),
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Collection of resources that make up the software component
///
/// This structure groups together all the resources that are part of the
/// software, including files, directories, processes, and other resource types.
/// It forms the core content description of what comprises the software.
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ResourceCollection<'a> {
    /// Group of file system path elements
    pub path_elements_group: PathElementsGroup<'a>,
    /// Optional list of processes
    pub process: Option<OneOrMore<ProcessEntry<'a>>>,
    /// Optional list of resources
    pub resource: Option<OneOrMore<ResourceEntry<'a>>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl ResourceCollection<'_> {
    pub fn serialize_map<M, O, E>(&self, map: &mut M, is_human_readable: bool) -> Result<(), E>
    where
        M: ser::SerializeMap<Ok = O, Error = E>,
    {
        self.path_elements_group
            .serialize_map(map, is_human_readable)?;

        if is_human_readable {
            if let Some(process) = &self.process {
                map.serialize_entry("process", process)?;
            }

            if let Some(resource) = &self.resource {
                map.serialize_entry("resource", resource)?;
            }
        } else {
            if let Some(process) = &self.process {
                map.serialize_entry(&18, process)?;
            }

            if let Some(resource) = &self.resource {
                map.serialize_entry(&19, resource)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(map, is_human_readable)?;
        }

        Ok(())
    }
}

impl Serialize for ResourceCollection<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        self.serialize_map(&mut map, is_human_readable)?;

        map.end()
    }
}

impl<'de> Deserialize<'de> for ResourceCollection<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct ResourceCollectionVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for ResourceCollectionVisitor<'a> {
            type Value = ResourceCollection<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing ResourceCollection fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = ResourceCollectionBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("directory") => {
                                builder = builder
                                    .directory(map.next_value::<OneOrMore<DirectoryEntry<'a>>>()?);
                            }
                            Some("file") => {
                                builder =
                                    builder.file(map.next_value::<OneOrMore<FileEntry<'a>>>()?);
                            }
                            Some("process") => {
                                builder = builder
                                    .process(map.next_value::<OneOrMore<ProcessEntry<'a>>>()?);
                            }
                            Some("resource") => {
                                builder = builder
                                    .resource(map.next_value::<OneOrMore<ResourceEntry<'a>>>()?);
                            }
                            Some(other) => match other.parse::<i128>() {
                                Ok(i) => {
                                    builder = builder
                                        .add_extension(i, map.next_value::<ExtensionValue>()?);
                                }
                                Err(_) => {
                                    return Err(de::Error::custom(format!(
                                        "unexpected ResourceCollection field: {other}"
                                    )))
                                }
                            },
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(16) => {
                                builder = builder
                                    .directory(map.next_value::<OneOrMore<DirectoryEntry<'a>>>()?);
                            }
                            Some(17) => {
                                builder =
                                    builder.file(map.next_value::<OneOrMore<FileEntry<'a>>>()?);
                            }
                            Some(18) => {
                                builder = builder
                                    .process(map.next_value::<OneOrMore<ProcessEntry<'a>>>()?);
                            }
                            Some(19) => {
                                builder = builder
                                    .resource(map.next_value::<OneOrMore<ResourceEntry<'a>>>()?);
                            }
                            Some(other) => {
                                builder = builder.add_extension(
                                    other as i128,
                                    map.next_value::<ExtensionValue>()?,
                                );
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(ResourceCollectionVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct ResourceCollectionBuilder<'a> {
    directory: Option<OneOrMore<DirectoryEntry<'a>>>,
    file: Option<OneOrMore<FileEntry<'a>>>,
    process: Option<OneOrMore<ProcessEntry<'a>>>,
    resource: Option<OneOrMore<ResourceEntry<'a>>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> ResourceCollectionBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path_elements_group(mut self, path_elements_group: PathElementsGroup<'a>) -> Self {
        self.directory = path_elements_group.directory;
        self.file = path_elements_group.file;
        self
    }

    pub fn directory(mut self, directory: OneOrMore<DirectoryEntry<'a>>) -> Self {
        self.directory = Some(directory);
        self
    }

    pub fn add_directory(mut self, directory: DirectoryEntry<'a>) -> Self {
        match self.directory {
            Some(existing) => {
                self.directory = Some(existing + directory.into());
            }
            None => self.directory = Some(directory.into()),
        }
        self
    }

    pub fn file(mut self, file: OneOrMore<FileEntry<'a>>) -> Self {
        self.file = Some(file);
        self
    }

    pub fn add_file(mut self, file: FileEntry<'a>) -> Self {
        match self.file {
            Some(existing) => {
                self.file = Some(existing + file.into());
            }
            None => self.file = Some(file.into()),
        }
        self
    }

    pub fn process(mut self, process: OneOrMore<ProcessEntry<'a>>) -> Self {
        self.process = Some(process);
        self
    }

    pub fn add_process(mut self, process: ProcessEntry<'a>) -> Self {
        match self.process {
            Some(existing) => {
                self.process = Some(existing + process.into());
            }
            None => self.process = Some(process.into()),
        }
        self
    }

    pub fn resource(mut self, resource: OneOrMore<ResourceEntry<'a>>) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn add_resource(mut self, resource: ResourceEntry<'a>) -> Self {
        match self.resource {
            Some(existing) => {
                self.resource = Some(existing + resource.into());
            }
            None => self.resource = Some(resource.into()),
        }
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn build(self) -> Result<ResourceCollection<'a>, CoswidError> {
        Ok(ResourceCollection {
            path_elements_group: PathElementsGroup {
                directory: self.directory,
                file: self.file,
            },
            process: self.process,
            resource: self.resource,
            extensions: self.extensions,
        })
    }
}

/// Group of file system path elements in a resource collection
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct PathElementsGroup<'a> {
    /// Optional list of directory entries.
    pub directory: Option<OneOrMore<DirectoryEntry<'a>>>,
    /// Optional list of file entries
    pub file: Option<OneOrMore<FileEntry<'a>>>,
}

impl PathElementsGroup<'_> {
    pub fn serialize_map<M, O, E>(&self, map: &mut M, is_human_readable: bool) -> Result<(), E>
    where
        M: ser::SerializeMap<Ok = O, Error = E>,
    {
        if is_human_readable {
            if let Some(directory) = &self.directory {
                map.serialize_entry("directory", directory)?;
            }

            if let Some(file) = &self.file {
                map.serialize_entry("file", file)?;
            }
        } else {
            if let Some(directory) = &self.directory {
                map.serialize_entry(&16, directory)?;
            }

            if let Some(file) = &self.file {
                map.serialize_entry(&17, file)?;
            }
        }

        Ok(())
    }
}

impl Serialize for PathElementsGroup<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        self.serialize_map(&mut map, is_human_readable)?;

        map.end()
    }
}

impl<'de> Deserialize<'de> for PathElementsGroup<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct PathElementsGroupVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for PathElementsGroupVisitor<'a> {
            type Value = PathElementsGroup<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing PathElementsGroup fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = PathElementsGroupBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("directory") => {
                                builder = builder
                                    .directory(map.next_value::<OneOrMore<DirectoryEntry>>()?);
                            }
                            Some("file") => {
                                builder = builder.file(map.next_value::<OneOrMore<FileEntry>>()?);
                            }
                            Some(other) => {
                                return Err(de::Error::unknown_field(
                                    other,
                                    ["directory", "file"].as_slice(),
                                ))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(16) => {
                                builder = builder
                                    .directory(map.next_value::<OneOrMore<DirectoryEntry>>()?);
                            }
                            Some(17) => {
                                builder = builder.file(map.next_value::<OneOrMore<FileEntry>>()?);
                            }
                            Some(other) => {
                                return Err(de::Error::unknown_field(
                                    other.to_string().as_str(),
                                    ["16", "17"].as_slice(),
                                ))
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(PathElementsGroupVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct PathElementsGroupBuilder<'a> {
    directory: Option<OneOrMore<DirectoryEntry<'a>>>,
    file: Option<OneOrMore<FileEntry<'a>>>,
}

impl<'a> PathElementsGroupBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn directory(mut self, directory: OneOrMore<DirectoryEntry<'a>>) -> Self {
        self.directory = Some(directory);
        self
    }

    pub fn add_directory(mut self, directory: DirectoryEntry<'a>) -> Self {
        match self.directory {
            Some(existing) => {
                self.directory = Some(existing + directory.into());
            }
            None => self.directory = Some(directory.into()),
        }
        self
    }

    pub fn file(mut self, file: OneOrMore<FileEntry<'a>>) -> Self {
        self.file = Some(file);
        self
    }

    pub fn add_file(mut self, file: FileEntry<'a>) -> Self {
        match self.file {
            Some(existing) => {
                self.file = Some(existing + file.into());
            }
            None => self.file = Some(file.into()),
        }
        self
    }

    pub fn build(self) -> Result<PathElementsGroup<'a>, CoswidError> {
        Ok(PathElementsGroup {
            directory: self.directory,
            file: self.file,
        })
    }
}

/// Information about a directory in the file system
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct DirectoryEntry<'a> {
    /// Basic file system item information
    pub filesystem_item: FileSystemItem<'a>,
    /// Optional path elements group (boxed to cover possible infinite recursion).
    pub path_elements: Option<Box<PathElementsGroup<'a>>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this directory
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for DirectoryEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        self.filesystem_item
            .serialize_map(&mut map, is_human_readable)?;

        if is_human_readable {
            if let Some(path_elements) = &self.path_elements {
                map.serialize_entry("path-elements", path_elements)?;
            }
        } else if let Some(path_elements) = &self.path_elements {
            map.serialize_entry(&26, path_elements)?;
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for DirectoryEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct DirectoryEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for DirectoryEntryVisitor<'a> {
            type Value = DirectoryEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing DirectoryEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = DirectoryEntryBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("key") => {
                                builder = builder.key(map.next_value::<bool>()?);
                            }
                            Some("location") => {
                                builder = builder.location(map.next_value::<Text>()?);
                            }
                            Some("fs-name") => {
                                builder = builder.fs_name(map.next_value::<Text>()?);
                            }
                            Some("root") => {
                                builder = builder.root(map.next_value::<Text>()?);
                            }
                            Some("path-elements") => {
                                builder = builder
                                    .path_elements(map.next_value::<PathElementsGroup>()?.into());
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            );
                                        } else if n.is_u64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            );
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        builder = builder.add_global_attribute(
                                            Label::parse(entry),
                                            s.into(),
                                        );
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                builder = builder.add_extension(
                                                    i,
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid LinkEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                22 => {
                                    builder = builder.key(map.next_value::<bool>()?);
                                }
                                23 => {
                                    builder = builder.location(map.next_value::<Text>()?);
                                }
                                24 => {
                                    builder = builder.fs_name(map.next_value::<Text>()?);
                                }
                                25 => {
                                    builder = builder.root(map.next_value::<Text>()?);
                                }
                                26 => {
                                    builder = builder.path_elements(
                                        map.next_value::<PathElementsGroup>()?.into(),
                                    );
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => {
                                builder = builder.add_global_attribute(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(DirectoryEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct DirectoryEntryBuilder<'a> {
    key: Option<bool>,
    location: Option<Text<'a>>,
    fs_name: Option<Text<'a>>,
    root: Option<Text<'a>>,
    path_elements: Option<Box<PathElementsGroup<'a>>>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> DirectoryEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn filesystem_item(mut self, filesystem_item: FileSystemItem<'a>) -> Self {
        self.key = filesystem_item.key;
        self.location = filesystem_item.location;
        self.fs_name = Some(filesystem_item.fs_name);
        self.root = filesystem_item.root;
        self
    }

    pub fn key(mut self, key: bool) -> Self {
        self.key = Some(key);
        self
    }

    pub fn location(mut self, location: Text<'a>) -> Self {
        self.location = Some(location);
        self
    }

    pub fn fs_name(mut self, fs_name: Text<'a>) -> Self {
        self.fs_name = Some(fs_name);
        self
    }

    pub fn root(mut self, root: Text<'a>) -> Self {
        self.root = Some(root);
        self
    }

    pub fn path_elements(mut self, path_elements: Box<PathElementsGroup<'a>>) -> Self {
        self.path_elements = Some(path_elements);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "DirectoryEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<DirectoryEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.fs_name.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "DirectoryEntry.FileSystemItem".to_string(),
                "fs_name".to_string(),
            ))?;
        }

        Ok(DirectoryEntry {
            filesystem_item: FileSystemItem {
                key: self.key,
                fs_name: self.fs_name.unwrap(),
                location: self.location,
                root: self.root,
            },
            path_elements: self.path_elements,
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Basic information about a file system item (file or directory)
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct FileSystemItem<'a> {
    /// Indicates if this is a key/critical file system item
    pub key: Option<bool>,
    /// Optional location in the file system
    pub location: Option<Text<'a>>,
    /// Name of the file system item
    pub fs_name: Text<'a>,
    /// Optional root directory path
    pub root: Option<Text<'a>>,
}

impl FileSystemItem<'_> {
    pub fn serialize_map<M, O, E>(&self, map: &mut M, is_human_readable: bool) -> Result<(), E>
    where
        M: ser::SerializeMap<Ok = O, Error = E>,
    {
        if is_human_readable {
            if let Some(key) = &self.key {
                map.serialize_entry("key", key)?;
            }

            if let Some(location) = &self.location {
                map.serialize_entry("location", location)?;
            }

            map.serialize_entry("fs-name", &self.fs_name)?;

            if let Some(root) = &self.root {
                map.serialize_entry("root", root)?;
            }
        } else {
            if let Some(key) = &self.key {
                map.serialize_entry(&22, key)?;
            }

            if let Some(location) = &self.location {
                map.serialize_entry(&23, location)?;
            }

            map.serialize_entry(&24, &self.fs_name)?;

            if let Some(root) = &self.root {
                map.serialize_entry(&25, root)?;
            }
        }

        Ok(())
    }
}

/// Information about a file in the file system
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct FileEntry<'a> {
    /// Basic file system item information
    pub filesystem_item: FileSystemItem<'a>,
    /// Optional file size in bytes
    pub size: Option<Uint>,
    /// Optional version identifier for the file
    pub file_version: Option<Text<'a>>,
    /// Optional cryptographic hash of file contents
    pub hash: Option<HashEntry>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this file
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for FileEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        self.filesystem_item
            .serialize_map(&mut map, is_human_readable)?;

        if is_human_readable {
            if let Some(size) = &self.size {
                map.serialize_entry("size", size)?;
            }

            if let Some(file_version) = &self.file_version {
                map.serialize_entry("file-version", file_version)?;
            }

            if let Some(hash) = &self.hash {
                map.serialize_entry("hash", hash)?;
            }
        } else {
            if let Some(size) = &self.size {
                map.serialize_entry(&20, size)?;
            }

            if let Some(file_version) = &self.file_version {
                map.serialize_entry(&21, file_version)?;
            }

            if let Some(hash) = &self.hash {
                map.serialize_entry(&7, hash)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for FileEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct FileEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for FileEntryVisitor<'a> {
            type Value = FileEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing FileEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = FileEntryBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("key") => {
                                builder = builder.key(map.next_value::<bool>()?);
                            }
                            Some("location") => {
                                builder = builder.location(map.next_value::<Text>()?);
                            }
                            Some("fs-name") => {
                                builder = builder.fs_name(map.next_value::<Text>()?);
                            }
                            Some("root") => {
                                builder = builder.root(map.next_value::<Text>()?);
                            }
                            Some("size") => {
                                builder = builder.size(map.next_value::<Integer>()?);
                            }
                            Some("file-version") => {
                                builder = builder.file_version(map.next_value::<Text>()?);
                            }
                            Some("hash") => {
                                builder = builder.hash(map.next_value::<HashEntry>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            );
                                        } else if n.is_u64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            );
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        builder = builder.add_global_attribute(
                                            Label::parse(entry),
                                            s.into(),
                                        );
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                builder = builder.add_extension(
                                                    i,
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid LinkEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                22 => {
                                    builder = builder.key(map.next_value::<bool>()?);
                                }
                                23 => {
                                    builder = builder.location(map.next_value::<Text>()?);
                                }
                                24 => {
                                    builder = builder.fs_name(map.next_value::<Text>()?);
                                }
                                25 => {
                                    builder = builder.root(map.next_value::<Text>()?);
                                }
                                20 => {
                                    builder = builder.size(map.next_value::<Integer>()?);
                                }
                                21 => {
                                    builder = builder.file_version(map.next_value::<Text>()?);
                                }
                                7 => {
                                    builder = builder.hash(map.next_value::<HashEntry>()?);
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => {
                                builder = builder.add_global_attribute(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(FileEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct FileEntryBuilder<'a> {
    key: Option<bool>,
    location: Option<Text<'a>>,
    fs_name: Option<Text<'a>>,
    root: Option<Text<'a>>,
    size: Option<Uint>,
    file_version: Option<Text<'a>>,
    hash: Option<HashEntry>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> FileEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn filesystem_item(mut self, filesystem_item: FileSystemItem<'a>) -> Self {
        self.key = filesystem_item.key;
        self.location = filesystem_item.location;
        self.fs_name = Some(filesystem_item.fs_name);
        self.root = filesystem_item.root;
        self
    }

    pub fn key(mut self, key: bool) -> Self {
        self.key = Some(key);
        self
    }

    pub fn location(mut self, location: Text<'a>) -> Self {
        self.location = Some(location);
        self
    }

    pub fn fs_name(mut self, fs_name: Text<'a>) -> Self {
        self.fs_name = Some(fs_name);
        self
    }

    pub fn root(mut self, root: Text<'a>) -> Self {
        self.root = Some(root);
        self
    }

    pub fn size(mut self, size: Integer) -> Self {
        self.size = Some(size);
        self
    }

    pub fn file_version(mut self, file_version: Text<'a>) -> Self {
        self.file_version = Some(file_version);
        self
    }

    pub fn hash(mut self, hash: HashEntry) -> Self {
        self.hash = Some(hash);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "FileEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<FileEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.fs_name.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "FileEntry.FileSystemItem".to_string(),
                "fs_name".to_string(),
            ))?;
        }

        Ok(FileEntry {
            filesystem_item: FileSystemItem {
                key: self.key,
                fs_name: self.fs_name.unwrap(),
                location: self.location,
                root: self.root,
            },
            size: self.size,
            file_version: self.file_version,
            hash: self.hash,
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Information about a running process
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ProcessEntry<'a> {
    /// Name of the process
    pub process_name: Text<'a>,
    /// Optional process identifier
    pub pid: Option<Integer>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this process
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for ProcessEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("process-name", &self.process_name)?;

            if let Some(pid) = &self.pid {
                map.serialize_entry("pid", pid)?;
            }
        } else {
            map.serialize_entry(&27, &self.process_name)?;

            if let Some(pid) = &self.pid {
                map.serialize_entry(&28, pid)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ProcessEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct ProcessEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for ProcessEntryVisitor<'a> {
            type Value = ProcessEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing ProcessEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = ProcessEntryBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("process-name") => {
                                builder = builder.process_name(map.next_value::<Text>()?);
                            }
                            Some("pid") => {
                                builder = builder.pid(map.next_value::<Integer>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            );
                                        } else if n.is_u64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            );
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        builder = builder.add_global_attribute(
                                            Label::parse(entry),
                                            s.into(),
                                        );
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                builder = builder.add_extension(
                                                    i,
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid LinkEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                27 => {
                                    builder = builder.process_name(map.next_value::<Text>()?);
                                }
                                28 => {
                                    builder = builder.pid(map.next_value::<Integer>()?);
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => {
                                builder = builder.add_global_attribute(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(ProcessEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct ProcessEntryBuilder<'a> {
    process_name: Option<Text<'a>>,
    pid: Option<Integer>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> ProcessEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_name(mut self, process_name: Text<'a>) -> Self {
        self.process_name = Some(process_name);
        self
    }

    pub fn pid(mut self, pid: Integer) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "ProcessEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<ProcessEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.process_name.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "ProcessEntry".to_string(),
                "process_name".to_string(),
            ))?;
        }

        Ok(ProcessEntry {
            process_name: self.process_name.unwrap(),
            pid: self.pid,
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Information about a general resource
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ResourceEntry<'a> {
    /// Type identifier for the resource
    pub r#type: Text<'a>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this resource
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for ResourceEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("type", &self.r#type)?;
        } else {
            map.serialize_entry(&29, &self.r#type)?;
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ResourceEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct ResourceEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for ResourceEntryVisitor<'a> {
            type Value = ResourceEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing ResourceEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = ResourceEntryBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("type") => {
                                builder = builder.r#type(map.next_value::<Text>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            );
                                        } else if n.is_u64() {
                                            builder = builder.add_global_attribute(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            );
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        builder = builder.add_global_attribute(
                                            Label::parse(entry),
                                            s.into(),
                                        );
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                builder = builder.add_extension(
                                                    i,
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid LinkEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                29 => {
                                    builder = builder.r#type(map.next_value::<Text>()?);
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => {
                                builder = builder.add_global_attribute(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(ResourceEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct ResourceEntryBuilder<'a> {
    r#type: Option<Text<'a>>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> ResourceEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn r#type(mut self, r#type: Text<'a>) -> Self {
        self.r#type = Some(r#type);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "ResourceEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<ResourceEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.r#type.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "ResourceEntry".to_string(),
                "type".to_string(),
            ))?;
        }

        Ok(ResourceEntry {
            r#type: self.r#type.unwrap(),
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Contain/// Detailed evidence information about observed software state
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct EvidenceEntry<'a> {
    /// Collection of observed resources
    pub resource_collection: ResourceCollection<'a>,
    /// Optional timestamp when evidence was collected
    pub date: Option<IntegerTime>,
    /// Optional identifier of the device where evidence was collected
    pub device_id: Option<Text<'a>>,
    /// Optional location where evidence was collected
    pub location: Option<Text<'a>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this evidence entry
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

impl Serialize for EvidenceEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        self.resource_collection
            .serialize_map(&mut map, is_human_readable)?;

        if is_human_readable {
            if let Some(date) = &self.date {
                map.serialize_entry("date", date)?;
            }

            if let Some(device_id) = &self.device_id {
                map.serialize_entry("device-id", device_id)?;
            }

            if let Some(location) = &self.location {
                map.serialize_entry("location", location)?;
            }
        } else {
            if let Some(date) = &self.date {
                map.serialize_entry(&35, date)?;
            }

            if let Some(device_id) = &self.device_id {
                map.serialize_entry(&36, device_id)?;
            }

            if let Some(location) = &self.location {
                map.serialize_entry(&23, location)?;
            }
        }

        if let Some(extensions) = &self.extensions {
            extensions.serialize_map(&mut map, is_human_readable)?;
        }

        if let Some(global_attributes) = &self.global_attributes {
            global_attributes.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for EvidenceEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct EvidenceEntryVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for EvidenceEntryVisitor<'a> {
            type Value = EvidenceEntry<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing EvidenceEntry fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut rc_builder = ResourceCollectionBuilder::new();
                let mut builder = EvidenceEntryBuilder::new();
                let mut extensions = ExtensionMap::new();
                let mut global_attributes = GlobalAttributes::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("directory") => {
                                rc_builder = rc_builder
                                    .directory(map.next_value::<OneOrMore<DirectoryEntry<'a>>>()?);
                            }
                            Some("file") => {
                                rc_builder =
                                    rc_builder.file(map.next_value::<OneOrMore<FileEntry<'a>>>()?);
                            }
                            Some("process") => {
                                rc_builder = rc_builder
                                    .process(map.next_value::<OneOrMore<ProcessEntry<'a>>>()?);
                            }
                            Some("resource") => {
                                rc_builder = rc_builder
                                    .resource(map.next_value::<OneOrMore<ResourceEntry<'a>>>()?);
                            }
                            Some("date") => {
                                builder = builder.date(map.next_value::<IntegerTime>()?);
                            }
                            Some("device-id") => {
                                builder = builder.device_id(map.next_value::<Text<'a>>()?);
                            }
                            Some("location") => {
                                builder = builder.location(map.next_value::<Text<'a>>()?);
                            }
                            Some(entry) => {
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Number(n) => {
                                        if n.is_i64() {
                                            global_attributes.insert(
                                                Label::parse(entry),
                                                n.as_i64().unwrap().into(),
                                            ).map_err(de::Error::custom)?;
                                        } else if n.is_u64() {
                                            global_attributes.insert(
                                                Label::parse(entry),
                                                (n.as_u64().unwrap() as i128).into(),
                                            ).map_err(de::Error::custom)?;
                                        } else {
                                            return Err(de::Error::custom(
                                                "floating point not supported",
                                            ));
                                        }
                                    }
                                    serde_json::Value::String(s) => {
                                        global_attributes.insert(
                                            Label::parse(entry),
                                            s.into(),
                                        ).map_err(de::Error::custom)?;
                                    }
                                    other => {
                                        match entry.parse::<i128>() {
                                            Ok(i) => {
                                                extensions.insert(
                                                    i.into(),
                                                    other.try_into().map_err(de::Error::custom)?,
                                                );
                                            }
                                            Err(_) => {
                                                return Err(de::Error::custom(format!(
                                                    "invalid PayloadEntry entry: key: {entry}, value: {other:?}"
                                                )))
                                            }
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    } else {
                        // ! is_human_readable
                        match map.next_key::<Label>()? {
                            Some(Label::Int(i)) => match i.0 {
                                16 => {
                                    rc_builder = rc_builder.directory(
                                        map.next_value::<OneOrMore<DirectoryEntry<'a>>>()?,
                                    );
                                }
                                17 => {
                                    rc_builder = rc_builder
                                        .file(map.next_value::<OneOrMore<FileEntry<'a>>>()?);
                                }
                                18 => {
                                    rc_builder = rc_builder
                                        .process(map.next_value::<OneOrMore<ProcessEntry<'a>>>()?);
                                }
                                19 => {
                                    rc_builder = rc_builder.resource(
                                        map.next_value::<OneOrMore<ResourceEntry<'a>>>()?,
                                    );
                                }
                                35 => {
                                    builder = builder.date(map.next_value::<IntegerTime>()?);
                                }
                                36 => {
                                    builder = builder.device_id(map.next_value::<Text<'a>>()?);
                                }
                                23 => {
                                    builder = builder.location(map.next_value::<Text<'a>>()?);
                                }
                                entry => {
                                    let value = map.next_value::<ciborium::Value>()?;
                                    match value {
                                        ciborium::Value::Integer(n) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                i128::from(n).into(),
                                            );
                                        }
                                        ciborium::Value::Text(s) => {
                                            builder = builder.add_global_attribute(
                                                Label::Int(entry.into()),
                                                s.into(),
                                            );
                                        }
                                        other => {
                                            builder = builder.add_extension(
                                                entry,
                                                other.try_into().map_err(de::Error::custom)?,
                                            );
                                        }
                                    }
                                }
                            },
                            Some(Label::Text(text)) => global_attributes
                                .insert(
                                    text.into_owned().into(),
                                    map.next_value::<AttributeValue>()?,
                                )
                                .map_err(de::Error::custom)?,
                            None => break,
                        }
                    }
                }

                builder =
                    builder.resource_collection(rc_builder.build().map_err(de::Error::custom)?);

                if !extensions.is_empty() {
                    builder = builder.extensions(extensions);
                }

                if !global_attributes.is_empty() {
                    builder = builder.global_attributes(global_attributes);
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(EvidenceEntryVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct EvidenceEntryBuilder<'a> {
    resource_collection: Option<ResourceCollection<'a>>,
    date: Option<IntegerTime>,
    device_id: Option<Text<'a>>,
    location: Option<Text<'a>>,
    extensions: Option<ExtensionMap<'a>>,
    global_attributes: Option<GlobalAttributes<'a>>,
    ga_error: Option<CoswidError>,
}

impl<'a> EvidenceEntryBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resource_collection(mut self, resource_collection: ResourceCollection<'a>) -> Self {
        self.resource_collection = Some(resource_collection);
        self
    }

    pub fn date(mut self, date: IntegerTime) -> Self {
        self.date = Some(date);
        self
    }

    pub fn device_id(mut self, device_id: Text<'a>) -> Self {
        self.device_id = Some(device_id);
        self
    }

    pub fn location(mut self, location: Text<'a>) -> Self {
        self.location = Some(location);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn add_extension(mut self, key: i128, value: ExtensionValue<'a>) -> Self {
        if let Some(extensions) = &mut self.extensions {
            extensions.insert(key.into(), value);
        } else {
            let mut extensions = ExtensionMap::new();
            extensions.insert(key.into(), value);
            self.extensions = Some(extensions)
        }

        self
    }

    pub fn global_attributes(mut self, global_attributes: GlobalAttributes<'a>) -> Self {
        self.global_attributes = Some(global_attributes);
        self
    }

    pub fn add_global_attribute(mut self, key: Label<'a>, value: AttributeValue<'a>) -> Self {
        let res;

        if let Some(global_attributes) = &mut self.global_attributes {
            res = global_attributes.insert(key, value);
        } else {
            let mut global_attributes = GlobalAttributes::new();
            res = global_attributes.insert(key, value);
            self.global_attributes = Some(global_attributes)
        }

        // since we can't return the error here, save it so that we can return it from build().
        match res {
            Ok(_) => (),
            Err(err) => {
                self.ga_error = Some(CoswidError::InvalidFieldValue(
                    "EntityEntry".to_string(),
                    "global_attributes".to_string(),
                    err.to_string(),
                ))
            }
        }

        self
    }

    pub fn build(self) -> Result<EvidenceEntry<'a>, CoswidError> {
        if let Some(err) = self.ga_error {
            return Err(err);
        }

        if self.resource_collection.is_none() {
            return Err(CoswidError::UnsetMandatoryField(
                "EvidenceEntry".to_string(),
                "resource_collection".to_string(),
            ))?;
        }

        Ok(EvidenceEntry {
            resource_collection: self.resource_collection.unwrap(),
            date: self.date,
            device_id: self.device_id,
            location: self.location,
            extensions: self.extensions,
            global_attributes: self.global_attributes,
        })
    }
}

/// Usage requirement levels for resources
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
pub enum Use<'a> {
    /// Resource is optional
    Optional = 1,
    /// Resource is required
    Required = 2,
    /// Resource is recommended
    Recommended = 3,
    /// Custom usage requirement
    IntOrText(Label<'a>),
}

impl From<i64> for Use<'_> {
    fn from(value: i64) -> Self {
        (value as i128).into()
    }
}

impl From<i128> for Use<'_> {
    fn from(value: i128) -> Self {
        match value {
            1 => Self::Optional,
            2 => Self::Required,
            3 => Self::Recommended,
            i => Self::IntOrText(i.into()),
        }
    }
}

impl TryFrom<&Use<'_>> for i64 {
    type Error = CoswidError;

    fn try_from(value: &Use<'_>) -> Result<Self, Self::Error> {
        match i128::try_from(value) {
            Ok(i) => {
                if i >= i64::MIN as i128 && i <= i64::MAX as i128 {
                    Ok(i as i64)
                } else {
                    Err(CoswidError::InvalidValue(format!("out of i64 bounds: {i}")))
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl TryFrom<&Use<'_>> for i128 {
    type Error = CoswidError;

    fn try_from(value: &Use<'_>) -> Result<Self, Self::Error> {
        match value {
            Use::Optional => Ok(1),
            Use::Required => Ok(2),
            Use::Recommended => Ok(3),
            Use::IntOrText(label) => match label {
                Label::Int(i) => Ok(i.0),
                Label::Text(text) => {
                    Err(CoswidError::InvalidValue(format!("not an integer: {text}")))
                }
            },
        }
    }
}

impl<'a> From<&'a str> for Use<'a> {
    fn from(value: &'a str) -> Self {
        match value {
            "optional" => Self::Optional,
            "required" => Self::Required,
            "recommended" => Self::Recommended,
            other => match other.parse::<i128>() {
                Ok(i) => i.into(),
                Err(_) => Self::IntOrText(value.into()),
            },
        }
    }
}

impl From<String> for Use<'_> {
    fn from(value: String) -> Self {
        match value.as_str() {
            "optional" => Self::Optional,
            "required" => Self::Required,
            "recommended" => Self::Recommended,
            other => match other.parse::<i128>() {
                Ok(i) => i.into(),
                Err(_) => Self::IntOrText(value.into()),
            },
        }
    }
}

impl Display for Use<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s;

        f.write_str(match self {
            Self::Optional => "optional",
            Self::Required => "required",
            Self::Recommended => "recommended",
            Self::IntOrText(label) => {
                s = label.to_string();
                s.as_str()
            }
        })
    }
}

impl Serialize for Use<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                Self::IntOrText(label) => label.serialize(serializer),
                other => serializer.serialize_str(other.to_string().as_str()),
            }
        } else {
            match i128::try_from(self) {
                Ok(i) => i.serialize(serializer),
                Err(_) => self.to_string().serialize(serializer),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Use<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let label = Label::deserialize(deserializer)?;

        match label {
            Label::Int(i) => Ok(i.0.into()),
            Label::Text(text) => Ok(text.to_string().into()),
        }
    }
}

/// Type alias for CoSWID tag identifiers (16 bytes max)
pub type ConciseSwidTagId<'a> = TextOrBytesSized<'a, 16>;

#[cfg(test)]
#[rustfmt::skip::macros(vec)]
mod test {
    use super::*;
    use crate::core::HashAlgorithm;
    use crate::test::SerdeTestCase;

    #[test]
    fn test_rel_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: Rel::Ancestor,
                expected_json: "\"ancestor\"",
                expected_cbor: vec![ 0x01 ],
            },
            SerdeTestCase {
                value: Rel::IntOrText("foo".into()),
                expected_json: "\"foo\"",
                expected_cbor: vec![
                    0x63, // tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                ],
            },
            SerdeTestCase {
                value: Rel::IntOrText(123i64.into()),
                expected_json: "123",
                expected_cbor: vec![
                    0x18, // int(1)
                      0x7b, // 123
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_ownership_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: Ownership::Abandon,
                expected_json: "\"abandon\"",
                expected_cbor: vec![ 0x01 ],
            },
            SerdeTestCase {
                value: Ownership::IntOrText("foo".into()),
                expected_json: "\"foo\"",
                expected_cbor: vec![
                    0x63, // tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                ],
            },
            SerdeTestCase {
                value: Ownership::IntOrText(123i64.into()),
                expected_json: "123",
                expected_cbor: vec![
                    0x18, // int(1)
                      0x7b, // 123
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_use_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: Use::Optional,
                expected_json: "\"optional\"",
                expected_cbor: vec![ 0x01 ],
            },
            SerdeTestCase {
                value: Use::IntOrText("foo".into()),
                expected_json: "\"foo\"",
                expected_cbor: vec![
                    0x63, // tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                ],
            },
            SerdeTestCase {
                value: Use::IntOrText(123i64.into()),
                expected_json: "123",
                expected_cbor: vec![
                    0x18, // int(1)
                      0x7b, // 123
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_link_entry_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: LinkEntryBuilder::new()
                    .artifact("foo".into())
                    .href("bar".into())
                    .media("qux".into())
                    .ownership(Ownership::Private)
                    .rel(Rel::Feature)
                    .media_type("zot".into())
                    .r#use(Use::Optional)
                    .add_extension(-1, true.into())
                    .add_global_attribute("fum".into(), 42i64.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"artifact":"foo","href":{"type":"uri","value":"bar"},"media":"qux","ownership":"private","rel":"feature","media-type":"zot","use":"optional","-1":true,"fum":42}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x18, 0x25, // key: 37 [artificat]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x18, 0x26, // key: 38 [href]
                      0xd8, 0x20, // value: tag(32) [uri]
                        0x63, // tstr(3)
                          0x62, 0x61, 0x72, // "bar"
                      0x0a, // key: 10 [media]
                      0x63, // value: tstr(3)
                        0x71, 0x75, 0x78, // "qux"
                      0x18, 0x27, // key: 39 [ownership]
                      0x02, // value: 2 [private]
                      0x18, 0x28, // key: 40 [rel]
                      0x03, //  value: 3 [feature]
                      0x18, 0x29, // key: 41 [media-type]
                      0x63, // value: tstr(3)
                        0x7a, 0x6f, 0x74, // "zot"
                      0x18, 0x2a, // key: 42 [use]
                      0x01, // value: 1 [optional]
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                      0x63, // key: tstr(3) [global_arg("fum")]
                        0x66, 0x75, 0x6d, // "fum"
                      0x18, 0x2a, // value: 42
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_entity_entry_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: EntityEntryBuilder::new()
                    .entity_name("foo".into())
                    .reg_id("bar".into())
                    .add_role(Role::Maintainer)
                    .thumbprint(HashEntry {
                        alg: HashAlgorithm::Sha256,
                        val: vec![0x01, 0x02, 0x03].into(),
                    })
                    .add_extension(-1, true.into())
                    .add_global_attribute("fum".into(), 42i64.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"entity-name":"foo","reg-id":{"type":"uri","value":"bar"},"role":"maintainer","thumbprint":"sha-256;AQID","-1":true,"fum":42}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x18, 0x1f, // key: 31 [entity-name]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x18, 0x20, // key: 32 [reg-id]
                      0xd8, 0x20, // value: tag(32) [uri]
                        0x63, // tstr(3)
                          0x62, 0x61, 0x72, // "bar"
                      0x18, 0x21, // key: 33 [role]
                      0x06, // value: 6 [maintainer]
                      0x18, 0x22, // key: 34 [thumbprint]
                      0x82, //  value: array(2) [hash-entry]
                        0x01, // [0]1 [sha-256]
                        0x43, // [1]bstr(3) [val]
                          0x01, 0x02, 0x03,
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                      0x63, // key: tstr(3) [global_arg("fum")]
                        0x66, 0x75, 0x6d, // "fum"
                      0x18, 0x2a, // value: 42
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_resource_entry_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: ResourceEntryBuilder::new()
                    .r#type("foo".into())
                    .add_extension(-1, true.into())
                    .add_global_attribute("fum".into(), 42i64.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"type":"foo","-1":true,"fum":42}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x18, 0x1d, // key: 29 [type]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                      0x63, // key: tstr(3) [global_arg("fum")]
                        0x66, 0x75, 0x6d, // "fum"
                      0x18, 0x2a, // value: 42
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_process_entry_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: ProcessEntryBuilder::new()
                    .process_name("foo".into())
                    .pid(1.into())
                    .add_extension(-1, ExtensionValue::Bool(true))
                    .add_global_attribute("fum".into(), 42i64.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"process-name":"foo","pid":1,"-1":true,"fum":42}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x18, 0x1b, // key: 27 [process-name]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x18, 0x1c, // key: 28 [pid]
                      0x01, // value: 1
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                      0x63, // key: tstr(3) [global_arg("fum")]
                        0x66, 0x75, 0x6d, // "fum"
                      0x18, 0x2a, // value: 42
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_file_entry_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: FileEntryBuilder::new()
                    .key(true)
                    .location("foo".into())
                    .fs_name("bar".into())
                    .root("qux".into())
                    .size(1.into())
                    .file_version("zot".into())
                    .hash(HashEntry {
                        alg: HashAlgorithm::Sha256,
                        val: vec![0x01, 0x02, 0x03].into(),
                    })
                    .add_extension(-1, true.into())
                    .add_global_attribute("fum".into(), 42i64.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"key":true,"location":"foo","fs-name":"bar","root":"qux","size":1,"file-version":"zot","hash":"sha-256;AQID","-1":true,"fum":42}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x16, // key: 22 [key]
                      0xf5, // value: true
                      0x17, // key: 23 [location]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x18, 0x18, // key: 24 [fs-name]
                      0x63, // value: tstr(3)
                        0x62, 0x61, 0x72, // "bar"
                      0x18, 0x19, // key: 25 [root]
                      0x63, // value: tstr(3)
                        0x71, 0x75, 0x78, // "qux"
                      0x14, // key: 20 [size]
                      0x01, // value: 1
                      0x15, // key: 21 [file-version]
                      0x63, // value: tstr(3)
                        0x7a, 0x6f, 0x74, // "zot"
                      0x07, // key: 7 [hash]
                      0x82, //  value: array(2) [hash-entry]
                        0x01, // [0]1 [sha-256]
                        0x43, // [1]bstr(3) [val]
                          0x01, 0x02, 0x03,
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                      0x63, // key: tstr(3) [global_arg("fum")]
                        0x66, 0x75, 0x6d, // "fum"
                      0x18, 0x2a, // value: 42
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_directory_entry_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: DirectoryEntryBuilder::new()
                    .key(true)
                    .location("foo".into())
                    .fs_name("bar".into())
                    .root("qux".into())
                    .path_elements(PathElementsGroupBuilder::new()
                        .add_directory(DirectoryEntryBuilder::new()
                            .fs_name("zot".into())
                            .build()
                            .unwrap()
                        )
                        .add_file(FileEntryBuilder::new()
                            .fs_name("baz".into())
                            .build()
                            .unwrap()
                        )
                        .build()
                        .unwrap()
                        .into()
                    )
                    .add_extension(-1, true.into())
                    .add_global_attribute("fum".into(), 42i64.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"key":true,"location":"foo","fs-name":"bar","root":"qux","path-elements":{"directory":{"fs-name":"zot"},"file":{"fs-name":"baz"}},"-1":true,"fum":42}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x16, // key: 22 [key]
                      0xf5, // value: true
                      0x17, // key: 23 [location]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x18, 0x18, // key: 24 [fs-name]
                      0x63, // value: tstr(3)
                        0x62, 0x61, 0x72, // "bar"
                      0x18, 0x19, // key: 25 [root]
                      0x63, // value: tstr(3)
                        0x71, 0x75, 0x78, // "qux"
                      0x18, 0x1a, // key: 26 [path-elements]
                      0xbf, // value: map(indef) [path-elements-group]
                        0x10, // key: 16 [directory]
                        0xbf, // value: map(indef) [directory-entry]
                          0x18, 0x18, // key: 24 [fs-name]
                          0x63, // value: tstr(3)
                            0x7a, 0x6f, 0x74, // "zot"
                        0xff, // break
                        0x11, // key: 17 [file]
                        0xbf, // value: map(indef) [file-entry]
                          0x18, 0x18, // key: 24 [fs-name]
                          0x63, // value: tstr(3)
                            0x62, 0x61, 0x7a, // "baz"
                        0xff, // break
                      0xff, // break
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                      0x63, // key: tstr(3) [global_arg("fum")]
                        0x66, 0x75, 0x6d, // "fum"
                      0x18, 0x2a, // value: 42
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_resource_collection_entry_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: ResourceCollectionBuilder::new()
                    .directory(DirectoryEntryBuilder::new()
                        .fs_name("foo".into())
                        .build()
                        .unwrap()
                        .into()
                    )
                    .file(FileEntryBuilder::new()
                        .fs_name("bar".into())
                        .build()
                        .unwrap()
                        .into()
                    )
                    .process(ProcessEntryBuilder::new()
                        .process_name("qux".into())
                        .pid(1.into())
                        .build()
                        .unwrap()
                        .into()
                    )
                    .resource(ResourceEntryBuilder::new()
                        .r#type("zot".into())
                        .build()
                        .unwrap()
                        .into()
                    )
                    .add_extension(-1, true.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"directory":{"fs-name":"foo"},"file":{"fs-name":"bar"},"process":{"process-name":"qux","pid":1},"resource":{"type":"zot"},"-1":true}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x10, // key: 16 [directory]
                      0xbf, // value: map(indef) [directory-entry]
                        0x18, 0x18, // key: 24 [fs-name]
                        0x63, // value: tstr(3)
                          0x66, 0x6f, 0x6f, // "foo"
                      0xff, // break
                      0x11, // key: 17 [file]
                      0xbf, // value: map(indef) [file-entry]
                        0x18, 0x18, // key: 24 [fs-name]
                        0x63, // value: tstr(3)
                          0x62, 0x61, 0x72, // "bar"
                      0xff, // break
                      0x12, // key: 18 [process]
                      0xbf, // value: map(indef) [process-entry]
                        0x18, 0x1b, // key: 27 [process-name]
                        0x63, // value: tstr(3)
                          0x71, 0x75, 0x78, // "qux"
                        0x18, 0x1c, // key: 28 [pid]
                        0x01, // value: 1
                      0xff, // break
                      0x13, // key: 19 [resource]
                      0xbf, // value: map(indef) [resource-entry]
                        0x18, 0x1d, // key: 29 [type]
                        0x63, // value: tstr(3)
                          0x7a, 0x6f, 0x74, // "zot"
                      0xff, // break
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_software_meta_entry_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: SoftwareMetaEntryBuilder::new()
                    .activation_status("foo".into())
                    .channel_type("bar".into())
                    .coloquial_version("qux".into())
                    .description("zot".into())
                    .edition("baz".into())
                    .entitlement_data_required(false)
                    .entitlement_key("fum".into())
                    .generator("foo".into())
                    .persistent_id("bar".into())
                    .product("qux".into())
                    .product_family("zot".into())
                    .revision("baz".into())
                    .summary("fum".into())
                    .unspsc_code("foo".into())
                    .unspsc_version("bar".into())
                    .add_extension(-1, true.into())
                    .add_global_attribute("qux".into(), 42i64.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"activation-status":"foo","channel-type":"bar","coloquial-version":"qux","description":"zot","edition":"baz","entitlement-data-required":false,"entitlement-key":"fum","generator":"foo","persistent-id":"bar","product":"qux","product-family":"zot","revision":"baz","summary":"fum","unspsc-code":"foo","unspsc-version":"bar","-1":true,"qux":42}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x18, 0x2b, // key: 43 [activation-status]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x18, 0x2c, // key: 44 [channel-type]
                      0x63, // value: tstr(3)
                        0x62, 0x61, 0x72, // "bar"
                      0x18, 0x2d, // key: 45 [coloquial-version]
                      0x63, // value: tstr(3)
                        0x71, 0x75, 0x78, // "qux"
                      0x18, 0x2e, // key: 46 [description]
                      0x63, // value: tstr(3)
                        0x7a, 0x6f, 0x74, // "zot"
                      0x18, 0x2f, // key: 47 [edition]
                      0x63, // value: tstr(3)
                        0x62, 0x61, 0x7a, // "baz"
                      0x18, 0x30, // key: 48 [entitlement-data-required]
                      0xf4, // value: false
                      0x18, 0x31, // key: 49 [entitlement-key]
                      0x63, // value: tstr(3)
                        0x66, 0x75, 0x6d, // "fum"
                      0x18, 0x32, // key: 50 [generator]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x18, 0x33, // key: 51 [persistent-id]
                      0x63, // value: tstr(3)
                        0x62, 0x61, 0x72, // "bar"
                      0x18, 0x34, // key: 52 [product]
                      0x63, // value: tstr(3)
                        0x71, 0x75, 0x78, // "qux"
                      0x18, 0x35, // key: 53 [product-family]
                      0x63, // value: tstr(3)
                        0x7a, 0x6f, 0x74, // "zot"
                      0x18, 0x36, // key: 54 [revision]
                      0x63, // value: tstr(3)
                        0x62, 0x61, 0x7a, // "baz"
                      0x18, 0x37, // key: 55 [summary]
                      0x63, // value: tstr(3)
                        0x66, 0x75, 0x6d, // "fum"
                      0x18, 0x38, // key: 56 [unspsc-code]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x18, 0x39, // key: 57 [unspsc-version]
                      0x63, // value: tstr(3)
                        0x62, 0x61, 0x72, // "bar"
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                      0x63, // key: tstr(3) [global_arg("qux")]
                        0x71, 0x75, 0x78, // "qux"
                      0x18, 0x2a, // value: 42
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_coswid_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: ConciseSwidTagBuilder::new()
                    .tag_id("foo".into())
                    .tag_version(1.into())
                    .corpus(true)
                    .patch(false)
                    .supplemental(true)
                    .software_name("bar".into())
                    .software_version("1.2.3".into())
                    .version_scheme(VersionScheme::Semver)
                    .media("qux".into())
                    .software_meta(SoftwareMetaEntryBuilder::new()
                        .activation_status("zot".into())
                        .build()
                        .unwrap()
                        .into()
                    )
                    .entity(EntityEntryBuilder::new()
                        .entity_name("baz".into())
                        .role(Role::Licensor.into())
                        .build()
                        .unwrap()
                        .into()
                    )
                    .link(LinkEntryBuilder::new()
                        .href("fum".into())
                        .rel(Rel::Feature)
                        .build()
                        .unwrap()
                        .into()
                    )
                    .payload(PayloadEntryBuilder::new()
                        .resource_collection(ResourceCollectionBuilder::new()
                            .process(ProcessEntryBuilder::new()
                                .process_name("foo".into())
                                .build()
                                .unwrap()
                                .into()
                            )
                            .build()
                            .unwrap()
                        )
                        .build()
                        .unwrap()
                    )
                    .add_extension(-1, true.into())
                    .add_global_attribute("bar".into(), 42i64.into())
                    .build()
                    .unwrap(),
                expected_json: r#"{"tag-id":"foo","tag-version":1,"corpus":true,"patch":false,"supplemental":true,"software-name":"bar","software-version":"1.2.3","version-scheme":"semver","media":"qux","software-meta":{"activation-status":"zot"},"entity":{"entity-name":"baz","role":"licensor"},"link":{"href":{"type":"uri","value":"fum"},"rel":"feature"},"payload":{"process":{"process-name":"foo"}},"-1":true,"bar":42}"#,
                expected_cbor: vec![
                    0xbf, // map(indef)
                      0x00, // key: 0 [tag-id]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x0c, // key: 12 [tag-version]
                      0x01, // value: 1
                      0x08, // key: 8 [corpus]
                      0xf5, // value: true
                      0x09, // key: 9 [patch]
                      0xf4, // value: false
                      0x0b, // key: 11 [supplemental]
                      0xf5, // value: true
                      0x01, // key: 1 [software-name]
                      0x63, // value: tstr(3)
                        0x62, 0x61, 0x72, // "bar"
                      0x0d, // key: 13 [software-version]
                      0x65, // value: tstr(5)
                        0x31, 0x2e, 0x32, 0x2e, 0x33, // "1.2.3"
                      0x0e, // key: 14 [version-scheme]
                      0x19, 0x40, 0x00, // value: 16384 [semver]
                      0x0a, // key: 10 [media]
                      0x63, // value: tstr(3)
                        0x71, 0x75, 0x78, // "qux"
                      0x05, // key: 5 [software-meta]
                      0xbf, // value: map(indef) [software-meta-entry]
                        0x18, 0x2b, // key: 43 [activation-status]
                        0x63, // value: tstr(3)
                          0x7a, 0x6f, 0x74, // value: "zot"
                      0xff, // break
                      0x02, // key: 2 [entity]
                      0xbf, // value: map(indef) [entity-entry]
                        0x18, 0x1f,  // key: 31 [entity-name]
                        0x63, // value: tstr(3)
                          0x62, 0x61, 0x7a, // "baz"
                        0x18, 0x21, // key: 33 [role]
                        0x05, // value: 5 [licensor]
                      0xff, // break
                      0x04, // key: 4 [link]
                      0xbf, // value: map(indef) [link-entry]
                        0x18, 0x26, // key: 38 [href]
                        0xd8, 0x20, // value: tag(32) [uri]
                          0x63, // tstr(3)
                            0x66, 0x75, 0x6d, // "fum"
                        0x18, 0x28, // key: 40 [rel]
                        0x03, // value: 3 [feature]
                      0xff, // break
                      0x06, // key: 6 [payload]
                      0xbf, // value: map(indef) [payload-entry]
                        0x12, // key: 18 [process]
                        0xbf, // map(indef) [process-entry]
                          0x18, 0x1b, // key: 27 [process-name]
                          0x63, // value: tstr(3)
                            0x66, 0x6f, 0x6f, // "foo"
                        0xff, // break
                      0xff, // break
                      0x20, // key: -1 [extension(-1)]
                      0xf5, // value: true
                      0x63, // key: tstr(3) [glob_attr("bar")]
                        0x62, 0x61, 0x72, // "bar"
                      0x18, 0x2a, // value: 42
                    0xff, // break
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }

        let err = ConciseSwidTagBuilder::new()
            .tag_id("foo".into())
            .tag_version(1.into())
            .corpus(true)
            .software_name("bar".into())
            .entity(
                EntityEntryBuilder::new()
                    .entity_name("baz".into())
                    .role(Role::Licensor.into())
                    .build()
                    .unwrap()
                    .into(),
            )
            .payload(
                PayloadEntryBuilder::new()
                    .resource_collection(
                        ResourceCollectionBuilder::new()
                            .process(
                                ProcessEntryBuilder::new()
                                    .process_name("foo".into())
                                    .build()
                                    .unwrap()
                                    .into(),
                            )
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )
            .evidence(
                EvidenceEntryBuilder::new()
                    .resource_collection(
                        ResourceCollectionBuilder::new()
                            .process(
                                ProcessEntryBuilder::new()
                                    .process_name("bar".into())
                                    .build()
                                    .unwrap()
                                    .into(),
                            )
                            .build()
                            .unwrap(),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap_err();

        assert_eq!(err.to_string(), "payload and evidence can't both be set");
    }
}
