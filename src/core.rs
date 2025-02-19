// SPDX-License-Identifier: MIT

//! Core types and utilities for the CoRIM implementation.
//!
//! This module provides fundamental types and data structures used throughout the CoRIM
//! specification implementation. It includes:
//!
//! # Basic Types
//!
//! - Text and string types ([`Text`], [`Tstr`])
//! - Numeric types ([`Int`], [`Uint`], [`Time`])
//! - URI types ([`Uri`], [`AnyUri`])
//! - Binary types for cryptographic operations
//!
//! # Data Structures
//!
//! - [`ExtensionMap`]: Flexible extension mechanism
//! - [`OneOrMore`]: Container for single or multiple values
//! - [`GlobalAttributes`]: Common attributes across all types
//! - [`HashEntry`]: Cryptographic hash representations
//!
//! # CBOR Tagged Types
//!
//! Several types are wrapped with CBOR tags as defined in the specification:
//! - [`IntegerTime`]: Tag 1
//! - [`OidType`]: Tag 111
//! - [`SvnType`]: Tag 552
//! - [`CoseKeyType`]: Tag 558
//!
//! # Type Registries
//!
//! - [`CorimMapRegistry`]: Valid keys for CoRIM maps
//! - [`ComidMapRegistry`]: Valid keys for CoMID maps
//! - [`CotlMapRegistry`]: Valid keys for CoTL maps
//!
//! # Usage
//!
//! ```rust
//! use corim_rs::core::{Text, HashEntry, Digest};
//!
//! // Create a hash entry
//! let hash = HashEntry {
//!     hash_alg_id: 1,  // SHA-256
//!     hash_value: vec![0, 1, 2, 3],
//! };
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Text represents a UTF-8 string value
pub type Text = String;
/// Tstr represents a text string value
pub type Tstr = String;
/// Uri represents one or more text values that conform to the URI syntax
pub type Uri = OneOrMore<Text>;
/// AnyUri represents a URI that can be relative or absolute
pub type AnyUri = Uri;
/// Time represents an integer value for time measurements
pub type Time = i32;
/// Role represents an unsigned 8-bit integer for role identifiers
pub type Role = u8;
/// Uint represents an unsigned 32-bit integer
pub type Uint = u32;
/// Int represents a signed 32-bit integer
pub type Int = i32;
/// Integer is an alias for Int type
pub type Integer = Int;

/// ExtensionMap represents the possible types that can be used in extensions
#[derive(Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub enum ExtensionMap {
    /// A UTF-8 string value
    Text(Text),
    /// A text string value
    Tstr(Tstr),
    /// A URI value
    Uri(Uri),
    /// Any URI value (relative or absolute)
    AnyUri(AnyUri),
    /// A time value
    Time(Time),
    /// A role identifier
    Role(Role),
    /// An unsigned integer
    Uint(Uint),
    /// A signed integer
    Int(Int),
    /// An integer value
    Integer(Integer),
    /// An array of extension values
    Array(Vec<ExtensionMap>),
    /// A map of extension key-value pairs
    Map(BTreeMap<ExtensionMap, ExtensionMap>),
}

/// UUID type representing a 16-byte unique identifier
#[derive(Serialize, Deserialize)]
pub struct UuidType {
    #[serde(flatten)]
    pub field: [u8; 16],
}

/// UEID type representing a 33-byte Unique Entity Identifier
#[derive(Serialize, Deserialize)]
pub struct UeidType {
    #[serde(with = "serde_arrays")]
    #[serde(flatten)]
    pub field: [u8; 33],
}

macro_rules! generate_tagged {
    ($(($tag_num: expr, $title: ident, $type: ty, $doc_comments: literal)), * $(,)?) => {
        $(
            #[doc = $doc_comments]
            #[derive(Serialize, Deserialize)]
            #[repr(C)]
            #[serde(tag = "$tag_num")]
            pub struct $title {
                /// The wrapped value which will be flattened during serialization
                #[serde(flatten)]
                pub field: $type,
            }
        )*
    };
}

generate_tagged!(
    ("1", IntegerTime, Int, "A representation of time in integer format using CBOR tag 1"),
    ("111", OidType, Bytes, "An Object Identifier (OID) represented as bytes using CBOR tag 111"),
    ("552", SvnType, Uint, "A Security Version Number (SVN) using CBOR tag 552"),
    ("553", MinSvnType, Uint, "A minimum Security Version Number (SVN) using CBOR tag 553"),
    ("554", PkixBase64KeyType, Tstr, "A PKIX key in base64 format using CBOR tag 554"),
    ("555", PkixBase64CertType, Tstr, "A PKIX certificate in base64 format using CBOR tag 555"),
    ("556", PkixBase64CertPathType, Tstr, "A PKIX certificate path in base64 format using CBOR tag 556"),
    ("557", ThumbprintType, Digest, "A cryptographic thumbprint using CBOR tag 557"),
    ("559", CertThumprintType, Digest, "A certificate thumbprint using CBOR tag 559"),
    ("560", Bytes, Vec<u8>, "A generic byte string using CBOR tag 560"),
    ("561", CertPathThumbprintType, Digest, "A certificate path thumbprint using CBOR tag 561"),
    ("562", PkixAsn1DerCertType, Bytes, "A PKIX certificate in ASN.1 DER format using CBOR tag 562"),
);

/// Represents a value that can be either text or bytes
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub enum TextOrBytes {
    /// UTF-8 string value
    Text(Text),
    /// Raw bytes value
    Bytes(Bytes),
}

/// Represents a value that can be either text or fixed-size bytes
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub enum TextOrBytesSized<const N: usize> {
    /// UTF-8 string value
    Text(Text),
    /// Fixed-size byte array
    #[serde(with = "serde_arrays")]
    Bytes([u8; N]),
}

/// Represents a hash entry with algorithm ID and hash value
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct HashEntry {
    /// Algorithm identifier for the hash
    #[serde(rename = "hash-alg-id")]
    pub hash_alg_id: Int,
    /// The hash value as bytes
    #[serde(rename = "hash-value")]
    pub hash_value: Bytes,
}

/// Represents a label that can be either text or integer
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Label {
    /// Text label
    Text(Text),
    /// Integer label
    Int(Int),
}

/// Represents an unsigned label that can be either text or unsigned integer
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Ulabel {
    /// Text label
    Text(Text),
    /// Unsigned integer label
    Uint(Uint),
}

/// Represents one or more values that can be either text or integers
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord)]
#[serde(untagged)]
#[repr(C)]
pub enum OneOrMore<T = ExtensionMap> {
    One(T),
    Many(Vec<T>),
}

/// Represents an attribute value that can be either text or integer, single or multiple
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(untagged)]
#[repr(C)]
pub enum AttributeValue {
    Text(OneOrMore<Text>),
    Int(OneOrMore<Int>),
}

/// Represents global attributes with optional language tag and arbitrary attributes
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[repr(C)]
pub struct GlobalAttributes {
    /// Optional language tag (ex. en_US)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<Text>,
    /// Arbitrary attributes
    #[serde(flatten)]
    pub attributes: BTreeMap<Label, AttributeValue>,
}

/// Registry of valid keys for CoRIM maps according to the specification
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum CorimMapRegistry {
    /// Unique identifier for the CoRIM
    Id,
    /// Collection of tags in the CoRIM
    Tags,
    /// Dependencies on other CoRIMs
    DependentRims,
    /// Profile information
    Profile,
    /// Validity period for the CoRIM
    RimValidity,
    /// Entity information
    Entities,
}

/// Registry of valid keys for CoMID maps according to the specification
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum ComidMapRegistry {
    /// Language identifier
    Language,
    /// Tag identity information
    TagIdentity,
    /// Entity information
    Entity,
    /// Linked tags references
    LinkedTags,
    /// Collection of triples
    Triples,
}

/// Registry of valid keys for CoTL maps according to the specification
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum CotlMapRegistry {
    /// Tag identity information
    TagIdentity,
    /// List of tags in the trust list
    TagsList,
    /// Validity period for the trust list
    TlValidity,
}

/// Represents a digest value with its algorithm identifier
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct Digest {
    /// Algorithm identifier for the digest
    pub alg: Label,
    /// The digest value as bytes
    pub val: Bytes,
}

/// Represents either a COSE key set or a single COSE key
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub enum CoseKeySetOrKey {
    /// A set of COSE keys
    KeySet(OneOrMore<CoseKey>),
    /// A single COSE key
    Key(CoseKey),
}

/// Represents a COSE key structure as defined in RFC 8152
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct CoseKey {
    /// Key type identifier (kty)
    #[serde(rename = "1")]
    pub kty: Label,
    /// Key identifier (kid)
    #[serde(rename = "2")]
    pub kid: Bytes,
    /// Algorithm identifier (alg)
    #[serde(rename = "3")]
    pub alg: Label,
    /// Allowed operations for this key
    #[serde(rename = "4")]
    pub key_ops: OneOrMore<Label>,
    /// Base initialization vector
    #[serde(rename = "5")]
    pub base_iv: Bytes,
    /// Optional extension fields
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap>,
}

/// CBOR tag 558 wrapper for COSE key structures
#[derive(Serialize, Deserialize)]
#[repr(C)]
#[serde(tag = "558")]
pub struct CoseKeyType {
    /// The wrapped COSE key or key set
    #[serde(flatten)]
    pub field: CoseKeySetOrKey,
}

/// Represents a masked raw value with its mask
#[derive(Serialize, Deserialize)]
#[repr(C)]
#[serde(tag = "563")]
pub struct MaskedRawValue {
    /// The raw value
    pub value: Bytes,
    /// The mask to apply to the value
    pub mask: Bytes,
}

/// UUID type wrapped with CBOR tag 37
#[derive(Serialize, Deserialize)]
#[repr(C)]
#[serde(tag = "37")]
pub struct TaggedUuidType {
    /// The wrapped UUID value
    #[serde(flatten)]
    pub bytes: UuidType,
}

/// UEID type wrapped with CBOR tag 550
#[derive(Serialize, Deserialize)]
#[repr(C)]
#[serde(tag = "550")]
pub struct TaggedUeidType {
    /// The wrapped UEID value
    #[serde(flatten)]
    pub bytes: UeidType,
}

/// Alias for MaskedRawValue type
pub type RawValueType = MaskedRawValue;

/// Version scheme enumeration as defined in the specification
#[repr(C)]
#[derive(Serialize, Deserialize)]
pub enum VersionScheme {
    /// Multi-part numeric version (e.g., 1.2.3)
    Multipartnumeric = 1,
    /// Multi-part numeric version with suffix (e.g., 1.2.3-beta)
    MultipartnumericSuffix = 2,
    /// Alphanumeric version (e.g., 1.2.3a)
    Alphanumeric = 3,
    /// Decimal version (e.g., 1.2)
    Decimal = 4,
    /// Semantic versioning (e.g., 1.2.3-beta+build.123)
    Semver = 16384,
}
