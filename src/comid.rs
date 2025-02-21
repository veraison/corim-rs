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
//!     core::{OneOrMore, Text, Tstr},
//! };
//!
//! // Create a tag identity
//! let tag_identity = TagIdentityMap {
//!     tag_id: TagIdTypeChoice::Tstr(Tstr::from("example-tag-id")),
//!     tag_version: Some(1u32),
//! };
//!
//! // Create an entity
//! let entity = ComidEntityMap {
//!     entity_name: Text::from("Example Corp"),
//!     reg_id: None,
//!     role: OneOrMore::One(ComidRoleTypeChoice::TagCreator),
//!     extension: None,
//! };
//!
//! // Create an empty triples map
//! let triples = TriplesMap {
//!     reference_triples: None,
//!     endorse_triples: None,
//!     identity_triples: None,
//!     attest_key_triples: None,
//!     dependency_triples: None,
//!     membership_triples: None,
//!     coswid_triples: None,
//!     conditional_endorsement_series_triples: None,
//!     conditional_endorsement_triples: None,
//!     extension: None,
//! };
//!
//! // Create the CoMID tag
//! let comid = ConciseMidTag {
//!     language: None,
//!     tag_identity,
//!     entities: OneOrMore::One(entity),
//!     linked_tags: None,
//!     triples,
//!     extension: None,
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
    generate_tagged, AttestKeyTripleRecord, ConditionalEndorsementSeriesTripleRecord,
    ConditionalEndorsementTripleRecord, CoswidTripleRecord, DomainDependencyTripleRecord,
    DomainMembershipTripleRecord, EndorsedTripleRecord, ExtensionMap, IdentityTripleRecord,
    OneOrMore, ReferenceTripleRecord, Text, Tstr, Uint, Uri, UuidType,
};
use derive_more::{Constructor, From, TryFrom};
use serde::{Deserialize, Serialize};

/// A tag version number represented as an unsigned integer
pub type TagVersionType = Uint;

generate_tagged!((
    506,
    TaggedConciseMidTag,
    ConciseMidTag,
    "A Concise Module Identifier (CoMID) structured tag"
),);
/// A Concise Module Identifier (CoMID) tag structure tagged with CBOR tag 506
#[derive(Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct ConciseMidTag {
    /// Optional language identifier for the tag content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Text>,
    /// Identity information for this tag
    #[serde(rename = "tag-identity")]
    pub tag_identity: TagIdentityMap,
    /// List of entities associated with this tag
    pub entities: OneOrMore<ComidEntityMap>,
    /// Optional references to other related tags
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "linked-tags")]
    pub linked_tags: Option<OneOrMore<LinkedTagMap>>,
    /// Collection of triples describing the module
    pub triples: TriplesMap,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionMap>,
}

/// Identification information for a tag
#[derive(Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct TagIdentityMap {
    /// Unique identifier for the tag
    #[serde(rename = "tag-id")]
    pub tag_id: TagIdTypeChoice,
    /// Optional version number for the tag
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "tag-version")]
    pub tag_version: Option<TagVersionType>,
}

/// Represents either a string or UUID tag identifier
#[derive(Serialize, Deserialize, From, TryFrom)]
#[repr(C)]
pub enum TagIdTypeChoice {
    /// Text string identifier
    Tstr(Tstr),
    /// UUID identifier
    Uuid(UuidType),
}

/// Information about an entity associated with the tag
#[derive(Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct ComidEntityMap {
    /// Name of the entity
    #[serde(rename = "entity-name")]
    pub entity_name: Text,
    /// Optional registration identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "reg-id")]
    pub reg_id: Option<Uri>,
    /// One or more roles this entity fulfills
    pub role: OneOrMore<ComidRoleTypeChoice>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap>,
}

/// Role types that can be assigned to entities
#[derive(Serialize, Deserialize, From, TryFrom)]
#[repr(C)]
pub enum ComidRoleTypeChoice {
    /// Entity that created the tag (value: 0)
    TagCreator = 0,
    /// Entity that created the module (value: 1)
    Creator = 1,
    /// Entity that maintains the module (value: 2)
    Maintainer = 2,
}

/// Reference to another tag and its relationship to this one
#[derive(Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct LinkedTagMap {
    /// Identifier of the linked tag
    #[serde(rename = "linked-tag-id")]
    pub linked_tag_id: TagIdTypeChoice,
    /// Relationship type between the tags
    #[serde(rename = "tag-rel")]
    pub tag_rel: TagRelTypeChoice,
}

/// Types of relationships between tags
#[derive(Serialize, Deserialize, From, TryFrom)]
#[repr(C)]
pub enum TagRelTypeChoice {
    /// This tag supplements the linked tag by providing additional information
    /// without replacing or invalidating the linked tag's content
    Supplements,
    /// This tag completely replaces the linked tag, indicating that the linked
    /// tag should no longer be considered valid or current
    Replaces,
}

/// Collection of different types of triples describing the module characteristics
#[derive(Serialize, Deserialize, From)]
#[repr(C)]
pub struct TriplesMap {
    /// Optional reference triples that link to external references
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "reference-triples")]
    pub reference_triples: Option<OneOrMore<ReferenceTripleRecord>>,

    /// Optional endorsement triples that contain verification information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "endorse-triples")]
    pub endorse_triples: Option<OneOrMore<EndorsedTripleRecord>>,

    /// Optional identity triples that provide identity information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "identity-triples")]
    pub identity_triples: Option<OneOrMore<IdentityTripleRecord>>,

    /// Optional attestation key triples containing cryptographic keys
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "attest_key-triples")]
    pub attest_key_triples: Option<OneOrMore<AttestKeyTripleRecord>>,

    /// Optional domain dependency triples describing relationships between domains
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "dependency-triples")]
    pub dependency_triples: Option<OneOrMore<DomainDependencyTripleRecord>>,

    /// Optional domain membership triples describing domain associations
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "membership-triples")]
    pub membership_triples: Option<OneOrMore<DomainMembershipTripleRecord>>,

    /// Optional SWID triples containing software identification data
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "coswid-triples")]
    pub coswid_triples: Option<OneOrMore<CoswidTripleRecord>>,

    /// Optional conditional endorsement series triples for complex endorsement chains
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "conditional-endorsement-series-triples")]
    pub conditional_endorsement_series_triples:
        Option<OneOrMore<ConditionalEndorsementSeriesTripleRecord>>,

    /// Optional conditional endorsement triples for conditional verification
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "conditional-endorsement-triples")]
    pub conditional_endorsement_triples: Option<OneOrMore<ConditionalEndorsementTripleRecord>>,

    /// Optional extensible attributes for future expansion
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap>,
}
