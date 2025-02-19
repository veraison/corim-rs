// SPDX-License-Identifier: MIT

//! Module for handling Concise Software Identity (CoSWID) tags.
//!
//! This module implements the CoSWID specification, providing structures and types for
//! describing software identity and inventory information in a concise format.
//!
//! # Key Components
//!
//! - [`ConciseSwidTag`]: The main CoSWID tag structure (CBOR tag 505)
//! - [`SoftwareMetaEntry`]: Additional metadata about software
//! - [`EntityEntry`]: Information about entities involved with the software
//! - [`LinkEntry`]: References to related resources
//!
//! # Evidence and Payload Support
//!
//! CoSWID tags can contain either:
//! - Payload data: Describes intended software state
//! - Evidence data: Describes observed software state
//!
//! # Resource Types
//!
//! Supported resource descriptions include:
//! - Files and directories
//! - Running processes
//! - Generic resources
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
//!     software_name: "Example Software".into(),
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
//!     global_attributes: Default::default(),
//! };
//! ```

use crate::{
    AnyUri, ExtensionMap, GlobalAttributes, HashEntry, Int, Integer, IntegerTime, Label, OneOrMore,
    Role, Text, TextOrBytes, TextOrBytesSized, Uint, Uri, VersionScheme,
};
use serde::{Deserialize, Serialize};

/// A Concise Software Identity (CoSWID) tag structure tagged with CBOR tag 505
#[derive(Serialize, Deserialize)]
#[serde(tag = "505")]
#[repr(C)]
pub struct ConciseSwidTag {
    /// Unique identifier for the tag
    #[serde(rename = "tag-id")]
    pub tag_id: TextOrBytes,
    /// Version number for the tag
    #[serde(rename = "tag-version")]
    pub tag_version: Int,
    /// Indicates if this is a base (corpus) tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corpus: Option<bool>,
    /// Indicates if this is a patch tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<bool>,
    /// Indicates if this is a supplemental tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplemental: Option<bool>,
    /// Name of the software product
    #[serde(rename = "software-name")]
    pub software_name: Text,
    /// Version of the software product
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "software-version")]
    pub software_version: Option<Text>,
    /// Scheme used for version numbering
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "version-scheme")]
    pub version_scheme: Option<VersionScheme>,
    /// Media type or environment context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<Text>,
    /// Additional metadata about the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "software-meta")]
    pub software_meta: Option<OneOrMore<SoftwareMetaEntry>>,
    /// List of entities associated with the software
    pub entity: OneOrMore<EntityEntry>,
    /// Optional links to related resources
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<OneOrMore<LinkEntry>>,
    /// Optional payload or evidence data
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "payload-or-evidence")]
    pub payload_or_evidence: Option<PayloadOrEvidence>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap>,
    /// Global attributes that apply to the whole tag
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Additional metadata about software described in a CoSWID tag
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct SoftwareMetaEntry {
    /// Current activation status of the software (e.g., "trial", "full", "deleted")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "activation-status")]
    pub activation_status: Option<Text>,

    /// Distribution channel type (e.g., "retail", "enterprise", "beta")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "channel-type")]
    pub channel_type: Option<Text>,

    /// Informal or marketing version name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "coloquial-version")]
    pub coloquial_version: Option<Text>,

    /// Detailed description of the software
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Text>,

    /// Edition or variation of the software
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edition: Option<Text>,

    /// Indicates if entitlement data is required to use the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "entitlement-data-required")]
    pub entitlement_data_required: Option<bool>,

    /// Key used for software entitlement
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "entitlement-key")]
    pub entitlement_key: Option<Text>,

    /// Tool that generated this metadata (16 bytes max)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generator: Option<TextOrBytesSized<16>>,

    /// Persistent identifier for the software
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "persistent-id")]
    pub persistent_id: Option<Text>,

    /// Product name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<Text>,

    /// Product family name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "product-family")]
    pub product_family: Option<Text>,

    /// Revision identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<Text>,

    /// Brief description of the software
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<Text>,

    /// UNSPSC classification code
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "unspsc-code")]
    pub unspsc_code: Option<Text>,

    /// Version of UNSPSC codeset used
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "unspsc-version")]
    pub unspsc_version: Option<Text>,

    /// Optional extensible attributes
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionMap>,

    /// Global attributes that apply to this metadata entry
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Information about an entity involved in software development or distribution
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct EntityEntry {
    /// Name of the entity
    #[serde(rename = "entity-name")]
    pub entity_name: Text,
    /// Optional registration identifier URI for the entity
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "reg-id")]
    pub reg_id: Option<Uri>,
    /// One or more roles this entity fulfills
    pub role: OneOrMore<Role>,
    /// Optional cryptographic hash for entity verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<HashEntry>,
    /// Optional extensible attributes
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionMap>,
    /// Global attributes that apply to this entity
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Link to external resources related to the software
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct LinkEntry {
    /// Optional identifier for the linked artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<Text>,
    /// URI reference to the linked resource
    pub href: AnyUri,
    /// Optional media type or context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media: Option<Text>,
    /// Optional ownership status of the linked resource
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership: Option<Ownership>,
    /// Relationship type between this tag and the linked resource
    pub rel: Rel,
    /// Optional MIME type of the linked resource
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "media-type")]
    pub media_type: Option<Text>,
    /// Optional usage requirement level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<Use>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionMap>,
    /// Global attributes that apply to this link
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Ownership status enumeration for linked resources
#[derive(Serialize, Deserialize)]
#[repr(u8)]
pub enum Ownership {
    /// Resource is no longer maintained
    Abandon = 1,
    /// Resource is privately owned
    Private = 2,
    /// Resource is shared among multiple parties
    Shared = 3,
    /// Custom ownership type using integer or text label
    IntOrText(Label),
}

/// Relationship types between resources in CoSWID tags
#[derive(Serialize, Deserialize)]
#[repr(u8)]
pub enum Rel {
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
    IntOrText(Label),
}

/// Contains either payload data or evidence data about the software
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum PayloadOrEvidence {
    /// Describes the intended state of the software
    Payload(Payload),
    /// Describes the observed state of the software
    Evidence(Evidence),
}

/// Container for payload information
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct Payload {
    /// The payload entry containing resource information
    payload: PayloadEntry,
}

/// Detailed payload information about software resources
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct PayloadEntry {
    /// Collection of resources in the software
    #[serde(flatten)]
    #[serde(rename = "resource-collection")]
    pub resource_collection: ResourceCollection,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap>,
    /// Global attributes that apply to this payload entry
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Collection of resources that make up the software
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ResourceCollection {
    /// Group of filesystem path elements
    #[serde(flatten)]
    #[serde(rename = "path-elements-group")]
    pub path_elements_group: PathElementsGroup,
    /// Optional list of processes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<OneOrMore<ProcessEntry>>,
    /// Optional list of resources
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<OneOrMore<ResourceEntry>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap>,
}

/// Group of filesystem path elements in a resource collection
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct PathElementsGroup {
    /// Optional list of directory entries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<OneOrMore<DirectoryEntry>>,
    /// Optional list of file entries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<OneOrMore<FileEntry>>,
}

/// Information about a directory in the filesystem
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct DirectoryEntry {
    /// Basic filesystem item information
    #[serde(flatten)]
    #[serde(rename = "filesystem-item")]
    pub filesystem_item: FileSystemItem,
    /// Optional directory size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<Uint>,
    /// Optional version identifier for the directory
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "file-version")]
    pub file_version: Option<Text>,
    /// Optional cryptographic hash of directory contents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashEntry>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap>,
    /// Global attributes that apply to this directory
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Basic information about a filesystem item (file or directory)
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct FileSystemItem {
    /// Indicates if this is a key/critical filesystem item
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<bool>,
    /// Optional location in the filesystem
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Text>,
    /// Name of the filesystem item
    #[serde(rename = "fs-name")]
    pub fs_name: Text,
    /// Optional root directory path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<Text>,
}

/// Information about a file in the filesystem
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct FileEntry {
    /// Basic filesystem item information
    #[serde(flatten)]
    #[serde(rename = "filesystem-item")]
    pub filesystem_item: FileSystemItem,
    /// Optional file size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<Uint>,
    /// Optional version identifier for the file
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "file-version")]
    pub file_version: Option<Text>,
    /// Optional cryptographic hash of file contents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashEntry>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap>,
    /// Global attributes that apply to this file
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Information about a running process
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ProcessEntry {
    /// Name of the process
    #[serde(rename = "process-name")]
    pub process_name: Text,
    /// Optional process identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<Integer>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap>,
    /// Global attributes that apply to this process
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Information about a general resource
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ResourceEntry {
    /// Type identifier for the resource
    pub r#type: Text,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap>,
    /// Global attributes that apply to this resource
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Container for evidence information about observed software state
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct Evidence {
    /// The evidence entry containing observed resource information
    pub evidence: EvidenceEntry,
}

/// Detailed evidence information about observed software state
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct EvidenceEntry {
    /// Collection of observed resources
    #[serde(flatten)]
    #[serde(rename = "resource-collection")]
    pub resource_collection: ResourceCollection,
    /// Optional timestamp when evidence was collected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<IntegerTime>,
    /// Optional identifier of the device where evidence was collected
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "device-id")]
    pub device_id: Option<Text>,
    /// Optional location where evidence was collected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Text>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap>,
    /// Global attributes that apply to this evidence entry
    #[serde(rename = "global-attributes")]
    pub global_attributes: GlobalAttributes,
}

/// Usage requirement levels for resources
#[derive(Serialize, Deserialize)]
#[repr(u8)]
pub enum Use {
    /// Resource is optional
    Optional = 1,
    /// Resource is required
    Required = 2,
    /// Resource is recommended
    Recommended = 3,
    /// Custom usage requirement
    IntOrText(Label),
}

/// Type alias for CoSWID tag identifiers (16 bytes max)
pub type ConciseSwidTagId = TextOrBytesSized<16>;
