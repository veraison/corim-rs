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
//! use corim_rs::coswid::{ConciseSwidTag, SoftwareMetaEntry};
//!
//! // Create a basic CoSWID tag
//! let tag = ConciseSwidTag {
//!     tag_id: "example-software".into(),
//!     tag_version: 1,
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
//!     payload_or_evidence: None,
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

use crate::{
    empty_map_as_none, generate_tagged, AnyUri, ExtensionMap, GlobalAttributes, HashEntry, Int,
    Integer, IntegerTime, Label, OneOrMore, Role, Text, TextOrBytes, TextOrBytesSized, Uint, Uri,
    VersionScheme,
};
use derive_more::{Constructor, From, TryFrom};
use serde::{Deserialize, Serialize};

generate_tagged!((505, TaggedConciseSwidTag, ConciseSwidTag<'a>, 'a, "Represents a CoSWID tag wrapped with CBOR tag 505"));

/// A Concise Software Identity (CoSWID) tag structure as defined in RFC 9393
///
/// CoSWID tags provide a standardized way to identify and describe software
/// components, including their metadata, contents, and relationships.
#[derive(Debug, Serialize, Deserialize, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConciseSwidTag<'a> {
    /// Unique identifier for the tag
    #[serde(rename = "0")]
    pub tag_id: TextOrBytes<'a>,
    /// Version number for the tag
    #[serde(rename = "12")]
    pub tag_version: Int,
    /// Indicates if this is a base (corpus) tag
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "8")]
    pub corpus: Option<bool>,
    /// Indicates if this is a patch tag
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "9")]
    pub patch: Option<bool>,
    /// Indicates if this is a supplemental tag
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "11")]
    pub supplemental: Option<bool>,
    /// Name of the software product
    #[serde(rename = "1")]
    pub software_name: Text<'a>,
    /// Version of the software product
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "13")]
    pub software_version: Option<Text<'a>>,
    /// Scheme used for version numbering
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "14")]
    pub version_scheme: Option<VersionScheme>,
    /// Media type or environment context
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "10")]
    pub media: Option<Text<'a>>,
    /// Additional metadata about the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "5")]
    pub software_meta: Option<OneOrMore<SoftwareMetaEntry<'a>>>,
    /// List of entities associated with the software
    #[serde(rename = "2")]
    pub entity: OneOrMore<EntityEntry<'a>>,
    /// Optional links to related resources
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "4")]
    pub link: Option<OneOrMore<LinkEntry<'a>>>,
    /// Optional payload or evidence data
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub payload_or_evidence: Option<PayloadOrEvidence<'a>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to the whole tag
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Additional metadata about the software component
///
/// This structure contains supplementary information about software that may be
/// useful for identification, deployment, or management purposes. All fields
/// are optional except for global attributes.
#[repr(C)]
#[derive(Default, Debug, Serialize, Deserialize, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct SoftwareMetaEntry<'a> {
    /// Current activation status of the software (e.g., "trial", "full", "deleted")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "43")]
    pub activation_status: Option<Text<'a>>,

    /// Distribution channel type (e.g., "retail", "enterprise", "beta")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "44")]
    pub channel_type: Option<Text<'a>>,

    /// Informal or marketing version name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "45")]
    pub coloquial_version: Option<Text<'a>>,

    /// Detailed description of the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "46")]
    pub description: Option<Text<'a>>,

    /// Edition or variation of the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "47")]
    pub edition: Option<Text<'a>>,

    /// Indicates if entitlement data is required to use the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "48")]
    pub entitlement_data_required: Option<bool>,

    /// Key used for software entitlement
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "49")]
    pub entitlement_key: Option<Text<'a>>,

    /// Tool that generated this metadata (16 bytes max)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "50")]
    pub generator: Option<TextOrBytesSized<'a, 16>>,

    /// Persistent identifier for the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "51")]
    pub persistent_id: Option<Text<'a>>,

    /// Product name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "52")]
    pub product: Option<Text<'a>>,

    /// Product family name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "53")]
    pub product_family: Option<Text<'a>>,

    /// Revision identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "54")]
    pub revision: Option<Text<'a>>,

    /// Brief description of the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "55")]
    pub summary: Option<Text<'a>>,

    /// UNSPSC classification code
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "56")]
    pub unspsc_code: Option<Text<'a>>,

    /// Version of UNSPSC codeset used
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "57")]
    pub unspsc_version: Option<Text<'a>>,

    /// Optional extensible attributes
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub extensions: Option<ExtensionMap<'a>>,

    /// Global attributes that apply to this metadata entry
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Information about an entity involved in software development or distribution
#[repr(C)]
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct EntityEntry<'a> {
    /// Name of the entity
    #[serde(rename = "31")]
    pub entity_name: Text<'a>,
    /// Optional registration identifier URI for the entity
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "32")]
    pub reg_id: Option<Uri<'a>>,
    /// One or more roles this entity fulfills
    #[serde(rename = "33")]
    pub role: OneOrMore<Role>,
    /// Optional cryptographic hash for entity verification
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "34")]
    pub thumbprint: Option<HashEntry>,
    /// Optional extensible attributes
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this entity
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Link to external resources related to the software
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct LinkEntry<'a> {
    /// Optional identifier for the linked artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "37")]
    pub artifact: Option<Text<'a>>,
    /// URI reference to the linked resource
    #[serde(rename = "38")]
    pub href: AnyUri<'a>,
    /// Optional media type or context
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "10")]
    pub media: Option<Text<'a>>,
    /// Optional ownership status of the linked resource
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "39")]
    pub ownership: Option<Ownership<'a>>,
    /// Relationship type between this tag and the linked resource
    #[serde(rename = "40")]
    pub rel: Rel<'a>,
    /// Optional MIME type of the linked resource
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "41")]
    pub media_type: Option<Text<'a>>,
    /// Optional usage requirement level
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "42")]
    pub r#use: Option<Use<'a>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub extension: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this link
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Ownership status enumeration for linked resources
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
#[serde(untagged)]
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

/// Relationship types between resources in CoSWID tags
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
#[serde(untagged)]
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

/// Describes either intended (Payload) or observed (Evidence) software state
///
/// This enum represents the two main types of software state information that
/// can be included in a CoSWID tag:
/// - Payload: The intended or expected state of the software
/// - Evidence: The actual observed state of the software
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum PayloadOrEvidence<'a> {
    /// Describes the intended state of the software
    Payload(Payload<'a>),
    /// Describes the observed state of the software
    Evidence(Evidence<'a>),
}

impl<'a> PayloadOrEvidence<'a> {
    pub fn as_payload(&self) -> Option<Payload> {
        match self {
            Self::Payload(payload) => Some(payload.clone()),
            _ => None,
        }
    }
    pub fn as_ref_payload(&self) -> Option<&Payload> {
        match self {
            Self::Payload(payload) => Some(payload),
            _ => None,
        }
    }
    pub fn as_evidence(&self) -> Option<Evidence> {
        match self {
            Self::Evidence(evidence) => Some(evidence.clone()),
            _ => None,
        }
    }
    pub fn as_ref_evidence(&self) -> Option<&Evidence> {
        match self {
            Self::Evidence(evidence) => Some(evidence),
            _ => None,
        }
    }
}

/// Container for payload information
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct Payload<'a> {
    #[serde(rename = "6")]
    /// The payload entry containing resource information
    payload: PayloadEntry<'a>,
}

/// Detailed payload information about software resources
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct PayloadEntry<'a> {
    /// Collection of resources in the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub resource_collection: Option<ResourceCollection<'a>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub extension: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this payload entry
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Collection of resources that make up the software component
///
/// This structure groups together all the resources that are part of the
/// software, including files, directories, processes, and other resource types.
/// It forms the core content description of what comprises the software.
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ResourceCollection<'a> {
    /// Group of filesystem path elements
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub path_elements_group: Option<PathElementsGroup<'a>>,
    /// Optional list of processes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "18")]
    pub process: Option<OneOrMore<ProcessEntry<'a>>>,
    /// Optional list of resources
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "19")]
    pub resource: Option<OneOrMore<ResourceEntry<'a>>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub extensions: Option<ExtensionMap<'a>>,
}

/// Group of filesystem path elements in a resource collection
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct PathElementsGroup<'a> {
    /// Optional list of directory entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "16")]
    pub directory: Option<OneOrMore<DirectoryEntry<'a>>>,
    /// Optional list of file entries
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "17")]
    pub file: Option<OneOrMore<FileEntry<'a>>>,
}

/// Information about a directory in the filesystem
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct DirectoryEntry<'a> {
    /// Basic filesystem item information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub filesystem_item: Option<FileSystemItem<'a>>,
    /// Optional path elements group (boxed to cover possible infinite recursion).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_elements: Option<Box<PathElementsGroup<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this directory
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Basic information about a filesystem item (file or directory)
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct FileSystemItem<'a> {
    /// Indicates if this is a key/critical filesystem item
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "22")]
    pub key: Option<bool>,
    /// Optional location in the filesystem
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "23")]
    pub location: Option<Text<'a>>,
    /// Name of the filesystem item
    #[serde(rename = "24")]
    pub fs_name: Text<'a>,
    /// Optional root directory path
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "25")]
    pub root: Option<Text<'a>>,
}

/// Information about a file in the filesystem
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct FileEntry<'a> {
    /// Basic filesystem item information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub filesystem_item: Option<FileSystemItem<'a>>,
    /// Optional file size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "20")]
    pub size: Option<Uint>,
    /// Optional version identifier for the file
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "21")]
    pub file_version: Option<Text<'a>>,
    /// Optional cryptographic hash of file contents
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "7")]
    pub hash: Option<HashEntry>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this file
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Information about a running process
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ProcessEntry<'a> {
    /// Name of the process
    #[serde(rename = "27")]
    pub process_name: Text<'a>,
    /// Optional process identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "28")]
    pub pid: Option<Integer>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this process
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Information about a general resource
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ResourceEntry<'a> {
    /// Type identifier for the resource
    #[serde(rename = "29")]
    pub r#type: Text<'a>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this resource
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Container for evidence information about observed software state
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct Evidence<'a> {
    #[serde(rename = "3")]
    /// The evidence entry containing observed resource information
    pub evidence: EvidenceEntry<'a>,
}

/// Detailed evidence information about observed software state
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct EvidenceEntry<'a> {
    /// Collection of observed resources
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub resource_collection: Option<ResourceCollection<'a>>,
    /// Optional timestamp when evidence was collected
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "35")]
    pub date: Option<IntegerTime>,
    /// Optional identifier of the device where evidence was collected
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "36")]
    pub device_id: Option<Text<'a>>,
    /// Optional location where evidence was collected
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "23")]
    pub location: Option<Text<'a>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap<'a>>,
    /// Global attributes that apply to this evidence entry
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "empty_map_as_none")]
    pub global_attributes: Option<GlobalAttributes<'a>>,
}

/// Usage requirement levels for resources
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(u8)]
#[serde(untagged)]
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

/// Type alias for CoSWID tag identifiers (16 bytes max)
pub type ConciseSwidTagId<'a> = TextOrBytesSized<'a, 16>;
