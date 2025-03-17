// SPDX-License-Identifier: MIT

//! Core types and structures for CoRIM (Concise Reference Integrity Manifest)
//!
//! This module provides fundamental types and data structures used throughout the CoRIM
//! implementation. It includes:
//!
//! # Basic Types
//! * Text and string representations
//! * Numeric types for various purposes
//! * Byte array and UUID implementations
//! * URI handling types
//!
//! # Data Structures
//! * Extension maps for flexible attribute storage
//! * Hash entries and digest representations
//! * Label types for various identifiers
//! * COSE key structures and algorithms
//!
//! # Enums and Choices
//! * Tagged types for CBOR encoding
//! * Value type choices (text/bytes/integers)
//! * Algorithm identifiers
//! * Version schemes
//!
//! # Registries
//! * CoRIM map registries
//! * CoMID map registries
//! * CoTL map registries
//!
//! # Features
//! * CBOR tagging support
//! * Flexible serialization options
//! * Comprehensive algorithm support
//! * Extensible data structures
//!
//! This module implements core functionality as specified in the IETF CoRIM specification
//! and related standards (RFC 8152 for COSE structures).

use std::{
    borrow::Cow,
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use derive_more::{AsMut, AsRef, Constructor, From, TryFrom};
use serde::{Deserialize, Serialize};

use crate::{generate_tagged, FixedBytes};

/// Text represents a UTF-8 string value
pub type Text<'a> = Cow<'a, str>;
// pub type Text = String;
/// Tstr represents a text string value
pub type Tstr<'a> = Text<'a>;
/// Bytes represents an un-tagged array of bytes.
pub type Bytes = Vec<u8>;
/// Uri represents one or more text values that conform to the URI syntax
pub type Uri<'a> = OneOrMore<Text<'a>>;
/// AnyUri represents a URI that can be relative or absolute
pub type AnyUri<'a> = Uri<'a>;
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
#[derive(Debug, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, From, TryFrom, Clone)]
#[serde(untagged)]
pub enum ExtensionMap<'a> {
    /// A UTF-8 string value
    Text(Text<'a>),
    /// A URI value
    Uri(Uri<'a>),
    /// A role identifier
    Role(Role),
    /// An unsigned integer
    Uint(Uint),
    /// A signed integer
    Int(Int),
    /// An array of extension values
    Array(Vec<Box<ExtensionMap<'a>>>),
    /// A map of extension key-value pairs
    Map(BTreeMap<Box<ExtensionMap<'a>>, Box<ExtensionMap<'a>>>),
}

/// UUID type representing a 16-byte unique identifier
#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    From,
    AsRef,
    AsMut,
    Constructor,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
)]
pub struct UuidType(pub FixedBytes<16>);

impl TryFrom<&[u8]> for UuidType {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(FixedBytes(value.try_into()?)))
    }
}

/// UEID type representing a 33-byte Unique Entity Identifier
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct UeidType(pub FixedBytes<33>);

generate_tagged!(
    (1, IntegerTime, Int, "A representation of time in integer format using CBOR tag 1"),
    (37, TaggedUuidType, UuidType, "UUID type wrapped with CBOR tag 37"),
    (111, OidType, Bytes, "An Object Identifier (OID) represented as bytes using CBOR tag 111"),
    (550, TaggedUeidType, UeidType, "UEID type wrapped with CBOR tag 550"),
    (552, SvnType, Uint, "A Security Version Number (SVN) using CBOR tag 552"),
    (553, MinSvnType, Uint, "A minimum Security Version Number (SVN) using CBOR tag 553"),
    (554, PkixBase64KeyType, Tstr<'a>, 'a, "A PKIX key in base64 format using CBOR tag 554"),
    (555, PkixBase64CertType, Tstr<'a>, 'a, "A PKIX certificate in base64 format using CBOR tag 555"),
    (556, PkixBase64CertPathType, Tstr<'a>, 'a, "A PKIX certificate path in base64 format using CBOR tag 556"),
    (557, ThumbprintType, Digest<'a>, 'a, "A cryptographic thumbprint using CBOR tag 557"),
    (558, CoseKeyType, CoseKeySetOrKey<'a>, 'a, "CBOR tag 558 wrapper for COSE Key Structures"),
    (559, CertThumprintType, Digest<'a>, 'a, "A certificate thumbprint using CBOR tag 559"),
    (560, TaggedBytes, Vec<u8>, "A generic byte string using CBOR tag 560"),
    (561, CertPathThumbprintType, Digest<'a>, 'a, "A certificate path thumbprint using CBOR tag 561"),
    (562, PkixAsn1DerCertType, TaggedBytes, "A PKIX certificate in ASN.1 DER format using CBOR tag 562"),
    (563, TaggedMaskedRawValue, MaskedRawValue, "Represents a masked raw value with its mask"),
);

#[derive(Debug, Serialize, Deserialize, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> NonEmptyVec<T> {
    pub fn new(one: T, more: Vec<T>) -> Self {
        let mut items = Vec::with_capacity(1 + more.len());
        items.push(one);
        items.extend(more);
        Self(items)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push(&mut self, value: T) {
        self.0.push(value)
    }
}

impl<T> From<T> for NonEmptyVec<T> {
    fn from(value: T) -> Self {
        Self(vec![value])
    }
}

impl<T: Clone> From<&[T]> for NonEmptyVec<T> {
    fn from(value: &[T]) -> Self {
        Self(value.to_vec())
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for NonEmptyVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> AsRef<[T]> for NonEmptyVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T> AsMut<[T]> for NonEmptyVec<T> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

/// Represents a value that can be either text or bytes
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]

pub enum TextOrBytes<'a> {
    /// UTF-8 string value
    Text(Text<'a>),
    /// Raw bytes value
    Bytes(TaggedBytes),
}

impl<'a> From<&'a str> for TextOrBytes<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(std::borrow::Cow::Borrowed(value))
    }
}

/// Represents a value that can be either text or fixed-size bytes
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
pub enum TextOrBytesSized<'a, const N: usize> {
    /// UTF-8 string value
    Text(Text<'a>),
    /// Fixed-size byte array
    Bytes(FixedBytes<N>),
}

/// Represents a hash entry with algorithm ID and hash value
#[repr(C)]
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct HashEntry {
    /// Algorithm identifier for the hash
    #[serde(rename = "hash-alg-id")]
    pub hash_alg_id: CoseAlgorithm,
    /// The hash value as bytes
    #[serde(rename = "hash-value")]
    pub hash_value: Bytes,
}

/// Represents a label that can be either text or integer
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, TryFrom)]
#[serde(untagged)]
pub enum Label<'a> {
    /// Text label
    Text(Text<'a>),
    /// Integer label
    Int(Int),
}

impl<'a> From<&'a str> for Label<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(std::borrow::Cow::Borrowed(value))
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, TryFrom)]
#[serde(untagged)]
/// Algorithm label that can be either a text string or a COSE algorithm identifier
pub enum AlgLabel<'a> {
    Text(Text<'a>),
    Int(CoseAlgorithm),
}

/// Represents an unsigned label that can be either text or unsigned integer
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, TryFrom)]
#[serde(untagged)]
pub enum Ulabel<'a> {
    /// Text label
    Text(Text<'a>),
    /// Unsigned integer label
    Uint(Uint),
}

/// Represents one or more values that can be either text or integers
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord, From, TryFrom)]
#[serde(untagged)]
#[repr(C)]
pub enum OneOrMore<T> {
    One(T),
    Many(Vec<T>),
}

/// Represents an attribute value that can be either text or integer, single or multiple
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, TryFrom)]
#[serde(untagged)]
#[repr(C)]
pub enum AttributeValue<'a> {
    Text(OneOrMore<Text<'a>>),
    Int(OneOrMore<Int>),
}

/// Represents global attributes with optional language tag and arbitrary attributes
#[derive(
    Debug, Clone, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord,
)]
#[repr(C)]
pub struct GlobalAttributes<'a> {
    /// Optional language tag (ex. en_US)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<Text<'a>>,
    /// Arbitrary attributes
    #[serde(flatten)]
    pub attributes: ExtensionMap<'a>,
}

/// Registry of valid keys for CoRIM maps according to the specification
#[derive(Debug, Serialize, Deserialize, From, TryFrom)]
#[repr(C)]
#[serde(untagged)]
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
#[derive(Debug, Serialize, Deserialize, From, TryFrom)]
#[repr(C)]
#[serde(untagged)]
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
#[derive(Debug, Serialize, Deserialize, From, TryFrom)]
#[repr(C)]
#[serde(untagged)]
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
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct Digest<'a> {
    /// Algorithm identifier for the digest
    pub alg: AlgLabel<'a>,
    /// The digest value as bytes
    pub val: Bytes,
}

/// Represents either a COSE key set or a single COSE key
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
pub enum CoseKeySetOrKey<'a> {
    /// A set of COSE keys
    KeySet(NonEmptyVec<CoseKey<'a>>),
    /// A single COSE key
    Key(CoseKey<'a>),
}

/// Represents a COSE key structure as defined in RFC 8152
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct CoseKey<'a> {
    /// Key type identifier (kty)
    #[serde(rename = "1")]
    pub kty: Label<'a>,
    /// Key identifier (kid)
    #[serde(rename = "2")]
    pub kid: TaggedBytes,
    /// Algorithm identifier (alg)
    #[serde(rename = "3")]
    pub alg: AlgLabel<'a>,
    /// Allowed operations for this key
    #[serde(rename = "4")]
    pub key_ops: NonEmptyVec<Label<'a>>,
    /// Base initialization vector
    #[serde(rename = "5")]
    pub base_iv: TaggedBytes,
    /// Optional extension fields
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extension: Option<ExtensionMap<'a>>,
}

#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
/// Raw value data structure with associated mask
pub struct MaskedRawValue {
    pub value: Bytes,
    pub mask: Bytes,
}

#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
/// Container for raw values with optional masking
pub struct RawValueType {
    #[serde(rename = "4")]
    pub raw_value: RawValueTypeChoice,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "5")]
    pub raw_value_mask: Option<RawValueMaskType>,
}

/// Type alias for raw value masks
pub type RawValueMaskType = Bytes;

#[derive(Debug, Serialize, Deserialize, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
/// Represents different types of raw values
pub enum RawValueTypeChoice {
    TaggedBytes(TaggedBytes),
    TaggedMaskedRawValue(TaggedMaskedRawValue),
}

/// Version scheme enumeration as defined in the specification
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
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

/// COSE cryptographic algorithms as defined in RFC 8152 and the IANA COSE Registry
///
/// The enum represents all registered algorithm identifiers for:
/// - Digital signatures
/// - Message authentication (MAC)
/// - Content encryption
/// - Key encryption
/// - Key derivation
/// - Hash functions
///
/// # Categories
///
/// - Signature algorithms (e.g., RS256, ES384, EdDSA)
/// - Hash functions (e.g., SHA-256, SHA-512, SHAKE128)
/// - Symmetric encryption (e.g., AES-GCM, ChaCha20-Poly1305)
/// - Key wrapping (e.g., AES-KW)
/// - Key derivation (e.g., HKDF variants)
///
/// # Value Ranges
///
/// - -65536 to -65525: Reserved for private use
/// - -260 to -256: RSA PSS signatures
/// - -47 to -1: ECDSA and other asymmetric algorithms
/// - 0: Reserved
/// - 1 to 65536: Symmetric algorithms
///
/// # Example
///
/// ```rust
/// use corim_rs::core::CoseAlgorithm;
///
/// let alg = CoseAlgorithm::ES256;  // ECDSA with SHA-256
/// let hash_alg = CoseAlgorithm::Sha256;  // SHA-256 hash function
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(i64)]
#[serde(untagged)]
pub enum CoseAlgorithm {
    /// Reserved for private use (-65536)
    Unassigned0 = -65536,
    /// RSASSA-PKCS1-v1_5 using SHA-1
    RS1 = -65535,
    /// AES-CTR with 128-bit key
    A128CTR = -65534,
    /// AES-CTR with 192-bit key
    A192CTR = -65533,
    /// AES-CTR with 256-bit key
    A256CTR = -65532,
    /// AES-CBC with 128-bit key
    A128CBC = -65531,
    /// AES-CBC with 192-bit key
    A192CBC = -65530,
    /// AES-CBC with 256-bit key
    A256CBC = -65529,
    /// Unassigned (-65528)
    Unassigned1 = -65528,
    /// WalnutDSA signature algorithm
    WalnutDSA = -260,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512 = -259,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384 = -258,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256 = -257,
    /// Unassigned (-256)
    Unassigned2 = -256,
    /// ECDSA using secp256k1 curve and SHA-256
    ES256K = -47,
    /// HSS/LMS hash-based signature
    HssLms = -46,
    /// SHAKE256 hash function
    SHAKE256 = -45,
    /// SHA-512 hash function
    Sha512 = -44,
    /// SHA-384 hash function
    Sha384 = -43,
    /// RSAES OAEP w/ SHA-512
    RsaesOaepSha512 = -42,
    /// RSAES OAEP w/ SHA-256
    RsaesOaepSha256 = -41,
    /// RSAES OAEP w/ RFC 8017 default parameters
    RsaesOaepRfc = 8017,
    /// RSASSA-PSS w/ SHA-512
    PS512 = -39,
    /// RSASSA-PSS w/ SHA-384
    PS384 = -38,
    /// RSASSA-PSS w/ SHA-256
    PS256 = -37,
    /// ECDSA w/ SHA-512
    ES512 = -36,
    /// ECDSA w/ SHA-384
    ES384 = -35,
    /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
    EcdhSsA256kw = -34,
    /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
    EcdhSsA192kw = -33,
    /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
    EcdhSsA128kw = -32,
    /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
    EcdhEsA256kw = -31,
    /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
    EcdhEsA192kw = -30,
    /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
    EcdhEsA128kw = -29,
    /// ECDH SS w/ HKDF - SHA-512
    EcdhSsHkdf512 = -28,
    /// ECDH SS w/ HKDF - SHA-256
    EcdhSsHkdf256 = -27,
    /// ECDH ES w/ HKDF - SHA-512
    EcdhEsHkdf512 = -26,
    /// ECDH ES w/ HKDF - SHA-256
    EcdhEsHkdf256 = -25,
    /// Unassigned (-24)
    Unassigned3 = -24,
    /// SHAKE128 hash function
    SHAKE128 = -18,
    /// SHA-512/256 hash function
    Sha512_256 = -17,
    /// SHA-256 hash function
    Sha256 = -16,
    /// SHA-256 hash truncated to 64-bits
    Sha256_64 = -15,
    /// SHA-1 hash function (deprecated)
    Sha1 = -14,
    /// Direct key agreement with HKDF and AES-256
    DirectHkdfAes256 = -13,
    /// Direct key agreement with HKDF and AES-128
    DirectHkdfAes128 = -12,
    /// Direct key agreement with HKDF and SHA-512
    DirectHkdfSha512 = -11,
    /// Direct key agreement with HKDF and SHA-256
    DirectHkdfSha256 = -10,
    /// Unassigned (-9)
    Unassigned4 = -9,
    /// EdDSA signature algorithm
    EdDSA = -8,
    /// ECDSA w/ SHA-256
    ES256 = -7,
    /// Direct use of CEK
    Direct = -6,
    /// AES Key Wrap w/ 256-bit key
    A256KW = -5,
    /// AES Key Wrap w/ 192-bit key
    A192KW = -4,
    /// AES Key Wrap w/ 128-bit key
    A128KW = -3,
    /// Unassigned (-2)
    Unassigned5 = -2,
    /// Reserved (0)
    Reserved = 0,
    /// AES-GCM mode w/ 128-bit key
    A128GCM = 1,
    /// AES-GCM mode w/ 192-bit key
    A192GCM = 2,
    /// AES-GCM mode w/ 256-bit key
    A256GCM = 3,
    /// HMAC w/ SHA-256 truncated to 64-bits
    Hmac256_64 = 4,
    /// HMAC w/ SHA-256
    Hmac256_256 = 5,
    /// HMAC w/ SHA-384
    Hmac384_384 = 6,
    /// HMAC w/ SHA-512
    Hmac512_512 = 7,
    /// Unassigned (8)
    Unassigned6 = 8,
    /// AES-CCM mode 16-byte MAC, 13-byte nonce, 128-bit key
    AesCcm16_64_128 = 10,
    /// AES-CCM mode 16-byte MAC, 13-byte nonce, 256-bit key
    AesCcm16_64_256 = 11,
    /// AES-CCM mode 64-byte MAC, 7-byte nonce, 128-bit key
    AesCcm64_64_128 = 12,
    /// AES-CCM mode 64-byte MAC, 7-byte nonce, 256-bit key
    AesCcm64_64_256 = 13,
    /// AES-MAC 128-bit key, 64-bit tag
    AesMac128_64 = 14,
    /// AES-MAC 256-bit key, 64-bit tag
    AesMac256_64 = 15,
    /// Unassigned (16)
    Unassigned7 = 16,
    /// ChaCha20/Poly1305 w/ 256-bit key
    ChaCha20Poly1305 = 24,
    /// AES-MAC 128-bit key
    AesMac128 = 128,
    /// AES-MAC 256-bit key
    AesMac256 = 256,
    /// Unassigned (27)
    Unassigned8 = 27,
    /// AES-CCM mode 16-byte MAC, 13-byte nonce, 128-bit key
    AesCcm16_128_128 = 30,
    /// AES-CCM mode 16-byte MAC, 13-byte nonce, 256-bit key
    AesCcm16_128_256 = 31,
    /// AES-CCM mode 64-byte MAC, 7-byte nonce, 128-bit key
    AesCcm64_128_128 = 32,
    /// AES-CCM mode 64-byte MAC, 7-byte nonce, 256-bit key
    AesCcm64_128_256 = 33,
    /// For generating IVs (Initialization Vectors)
    IvGeneration = 34,
}
