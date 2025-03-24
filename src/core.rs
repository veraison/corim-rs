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
    ops::{Deref, DerefMut, Index, IndexMut},
};

use derive_more::{Constructor, From, TryFrom};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{generate_tagged, FixedBytes};

/// Text represents a UTF-8 string value
pub type Text<'a> = Cow<'a, str>;
// pub type Text = String;
/// Tstr represents a text string value
pub type Tstr<'a> = Text<'a>;
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
/// Boolean represenation.
pub type Bool = bool;
/// Integer is an alias for Int type
pub type Integer = Int;
/// Floating Point variables.
pub type Float = f32;

#[derive(Debug, Default, From, PartialEq, Eq, PartialOrd, Ord, Clone, Constructor)]
pub struct Bytes {
    bytes: Vec<u8>,
}

impl From<&[u8]> for Bytes {
    fn from(value: &[u8]) -> Self {
        Self {
            bytes: value.to_vec(),
        }
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for Bytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Bytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.bytes.as_slice() == other.as_slice()
    }
}

impl Index<usize> for Bytes {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.bytes[index]
    }
}

impl IndexMut<usize> for Bytes {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.bytes[index]
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.bytes.as_slice())
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Bytes { bytes })
    }
}

/// ExtensionMap represents the possible types that can be used in extensions
#[derive(Debug, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, From, TryFrom, Clone)]
#[serde(untagged)]
pub enum ExtensionMap<'a> {
    /// No value
    Null,
    /// Boolean values
    Bool(Bool),
    /// A signed integer
    Int(Int),
    /// A UTF-8 string value
    Text(Text<'a>),
    /// An unsigned integer
    Uint(Uint),
    /// A bstr
    Bytes(Bytes),
    /// An array of extension values
    Array(Vec<ExtensionMap<'a>>),
    /// A map of extension key-value pairs
    Map(BTreeMap<Label<'a>, ExtensionMap<'a>>),
}

impl<'a> ExtensionMap<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Null => true,
            Self::Text(value) => value.is_empty(),
            Self::Bytes(value) => value.bytes.is_empty(),
            Self::Uint(_) => false,
            Self::Int(_) => false,
            Self::Bool(_) => false,
            Self::Array(value) => value.is_empty(),
            Self::Map(value) => value.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Text(value) => value.len(),
            Self::Bytes(value) => value.bytes.len(),
            Self::Uint(_) => 1,
            Self::Int(_) => 1,
            Self::Bool(_) => 1,
            Self::Array(value) => value.len(),
            Self::Map(value) => value.len(),
        }
    }

    /// Returns `true` if the variant is `Null`, `false` otherwise.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Attempts to extract a `Bool` value.
    pub fn as_bool(&self) -> Option<Bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Attempts to extract an `Int` value.
    pub fn as_int(&self) -> Option<Int> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Attempts to extract a `Uint` value.
    pub fn as_uint(&self) -> Option<Uint> {
        match self {
            Self::Uint(u) => Some(*u),
            _ => None,
        }
    }

    /// Attempts to extract a `Text` value as a string slice.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t.as_ref()),
            _ => None,
        }
    }

    /// Attempts to extract a `Text` value as an owned string.
    pub fn as_string(&self) -> Option<String> {
        match self {
            Self::Text(text) => Some(text.to_string()),
            _ => None,
        }
    }

    /// Attempts to extract a `Bytes` value as a byte slice.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b.as_ref()),
            _ => None,
        }
    }

    /// Attempts to extract an `Array` value as a reference to the vector.
    pub fn as_array(&self) -> Option<&Vec<ExtensionMap<'a>>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Attempts to extract a `Map` value as a reference to the map.
    pub fn as_map(&self) -> Option<&BTreeMap<Label<'a>, ExtensionMap<'a>>> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }
}

/// UUID type representing a 16-byte unique identifier
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct UuidType(pub FixedBytes<16>);

impl TryFrom<&[u8]> for UuidType {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(FixedBytes(value.try_into()?)))
    }
}

impl Deref for UuidType {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UuidType {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for UuidType {
    fn as_ref(&self) -> &[u8] {
        &self.0 .0
    }
}

impl AsMut<[u8]> for UuidType {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0 .0
    }
}

impl Index<usize> for UuidType {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0 .0[index]
    }
}

impl IndexMut<usize> for UuidType {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0 .0[index]
    }
}

/// UEID type representing a 33-byte Unique Entity Identifier
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct UeidType(pub FixedBytes<33>);

impl TryFrom<&[u8]> for UeidType {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(FixedBytes(value.try_into()?)))
    }
}

impl AsRef<[u8]> for UeidType {
    fn as_ref(&self) -> &[u8] {
        &self.0 .0
    }
}

impl AsMut<[u8]> for UeidType {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0 .0
    }
}

impl Deref for UeidType {
    type Target = [u8; 33];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UeidType {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Index<usize> for UeidType {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0 .0[index]
    }
}

impl IndexMut<usize> for UeidType {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0 .0[index]
    }
}

generate_tagged!(
    (1, IntegerTime, Int, "A representation of time in integer format using CBOR tag 1"),
    (32, Uri, Text<'a>, 'a,  "A URI text string with CBOR tag 32"),
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
    (560, TaggedBytes, Bytes, "A generic byte string using CBOR tag 560"),
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

    pub fn empty(&self) -> bool {
        self.0.is_empty()
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

impl<T> Index<usize> for NonEmptyVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for NonEmptyVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
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

impl<'a> TextOrBytes<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(value) => value.is_empty(),
            Self::Bytes(value) => value.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Text(value) => value.len(),
            Self::Bytes(value) => value.len(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value.as_ref()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value.as_ref()),
            _ => None,
        }
    }
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

impl<'a, const N: usize> TextOrBytesSized<'a, N> {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(value) => value.is_empty(),
            Self::Bytes(value) => value.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Text(value) => value.len(),
            Self::Bytes(value) => value.len(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value.as_ref()),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value.as_ref()),
            _ => None,
        }
    }
}

/// Represents a hash entry with algorithm ID and hash value
#[repr(C)]
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct HashEntry {
    /// Algorithm identifier for the hash
    pub hash_alg_id: CoseAlgorithm,
    /// The hash value as bytes
    pub hash_value: Bytes,
}

impl Serialize for HashEntry {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        // The total length is 1 (for hash_alg_id) plus the number of bytes in hash_value

        let mut seq = serializer.serialize_seq(Some(2))?;

        // Serialize hash_alg_id first
        seq.serialize_element(&self.hash_alg_id)?;

        // Serialize the bytes into a bstr
        seq.serialize_element(&self.hash_value)?;

        seq.end()
    }
}

impl<'de> Deserialize<'de> for HashEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{SeqAccess, Visitor};
        use std::fmt;

        struct HashEntryVisitor;

        impl<'de> Visitor<'de> for HashEntryVisitor {
            type Value = HashEntry;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a sequence with at least one element (hash_alg_id followed by bytes)",
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Get the first element (hash_alg_id)
                let hash_alg_id = seq
                    .next_element::<CoseAlgorithm>()?
                    .ok_or_else(|| serde::de::Error::custom("missing hash_alg_id"))?;

                // Collect the remaining elements as bytes
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }

                Ok(HashEntry {
                    hash_alg_id,
                    hash_value: bytes.into(),
                })
            }
        }

        deserializer.deserialize_seq(HashEntryVisitor)
    }
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

impl<'a> Label<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            Label::Text(value) => value.is_empty(),
            Label::Int(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Label::Text(value) => value.len(),
            Label::Int(_) => 1,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Label::Text(value) => Some(value.as_ref()),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<Int> {
        match self {
            Label::Int(value) => Some(*value),
            _ => None,
        }
    }
}

impl<'a> From<&'a str> for Label<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(std::borrow::Cow::Borrowed(value))
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, From, TryFrom)]
/// Algorithm label that can be either a text string or a COSE algorithm identifier
pub enum AlgLabel<'a> {
    Text(Text<'a>),
    Int(CoseAlgorithm),
}

impl<'a> AlgLabel<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            AlgLabel::Text(value) => value.is_empty(),
            AlgLabel::Int(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            AlgLabel::Text(value) => value.len(),
            AlgLabel::Int(_) => 1,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            AlgLabel::Text(value) => Some(value.as_ref()),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<CoseAlgorithm> {
        match self {
            AlgLabel::Int(value) => Some(value.clone()),
            _ => None,
        }
    }
}

impl<'a> Serialize for AlgLabel<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AlgLabel::Text(text) => serializer.serialize_str(text),
            AlgLabel::Int(cose_alg) => cose_alg.serialize(serializer),
        }
    }
}

impl<'de, 'a> Deserialize<'de> for AlgLabel<'a> {
    fn deserialize<D>(deserializer: D) -> Result<AlgLabel<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AlgLabelVisitor<'a> {
            _phantom: std::marker::PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for AlgLabelVisitor<'a> {
            type Value = AlgLabel<'a>; // Match Digest<'a>

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an integer or text for alg")
            }

            fn visit_i8<E>(self, value: i8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(value as i64)
            }

            fn visit_i16<E>(self, value: i16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(value as i64)
            }

            fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(value as i64)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let cose_alg =
                    CoseAlgorithm::deserialize(serde::de::value::I64Deserializer::new(value))?;
                Ok(AlgLabel::Int(cose_alg))
            }

            fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(value as i64)
            }

            fn visit_u16<E>(self, value: u16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(value as i64)
            }

            fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(value as i64)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value > i64::MAX as u64 {
                    Err(serde::de::Error::custom(
                        "COSE algorithm ID out of i64 range",
                    ))
                } else {
                    self.visit_i64(value as i64)
                }
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(AlgLabel::Text(Cow::Owned(value))) // Owned data, no lifetime dependency on 'de
            }
        }

        deserializer.deserialize_any(AlgLabelVisitor {
            _phantom: std::marker::PhantomData,
        })
    }
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

impl<'a> Ulabel<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            Ulabel::Text(value) => value.is_empty(),
            Ulabel::Uint(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Ulabel::Text(value) => value.len(),
            Ulabel::Uint(_) => 1,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Ulabel::Text(value) => Some(value.as_ref()),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<Uint> {
        match self {
            Ulabel::Uint(value) => Some(*value),
            _ => None,
        }
    }
}

/// Represents one or more values that can be either text or integers
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord, From, TryFrom)]
#[serde(untagged)]
#[repr(C)]
pub enum OneOrMore<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMore<T> {
    pub fn as_one(&self) -> Option<T> {
        match self {
            Self::One(val) => Some(val.clone()),
            _ => None,
        }
    }

    pub fn as_many(&self) -> Option<Vec<T>> {
        match self {
            Self::Many(val) => Some(val.clone()),
            _ => None,
        }
    }
}

impl<T> OneOrMore<T> {
    pub fn is_empty(&self) -> bool {
        match self {
            OneOrMore::One(_) => false,
            OneOrMore::Many(items) => items.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            OneOrMore::One(_) => 1usize,
            OneOrMore::Many(items) => items.len(),
        }
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        match self {
            OneOrMore::One(item) => {
                if index == 1 {
                    Some(item)
                } else {
                    None
                }
            }
            OneOrMore::Many(items) => items.get(index),
        }
    }
}

/// Represents an attribute value that can be either text or integer, single or multiple
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, From, TryFrom)]
#[serde(untagged)]
#[repr(C)]
pub enum AttributeValue<'a> {
    Text(OneOrMore<Text<'a>>),
    Int(OneOrMore<Int>),
}

impl<'a> AttributeValue<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            AttributeValue::Text(value) => value.is_empty(),
            AttributeValue::Int(value) => value.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            AttributeValue::Text(value) => value.len(),
            AttributeValue::Int(value) => value.len(),
        }
    }

    pub fn as_one_text(&self) -> Option<Text<'a>> {
        match self {
            AttributeValue::Text(value) => value.as_one(),
            _ => None,
        }
    }

    pub fn as_one_int(&self) -> Option<Int> {
        match self {
            AttributeValue::Int(value) => value.as_one(),
            _ => None,
        }
    }

    pub fn as_many_text(&self) -> Option<Vec<Text<'a>>> {
        match self {
            AttributeValue::Text(value) => value.as_many(),
            _ => None,
        }
    }

    pub fn as_many_int(&self) -> Option<Vec<Int>> {
        match self {
            AttributeValue::Int(value) => value.as_many(),
            _ => None,
        }
    }
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
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Digest<'a> {
    /// Algorithm identifier for the digest
    pub alg: AlgLabel<'a>,
    /// The digest value as bytes
    pub val: Bytes,
}

impl<'a> Serialize for Digest<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        match &self.alg {
            AlgLabel::Text(text) => seq.serialize_element(text)?,
            AlgLabel::Int(cose_alg) => seq.serialize_element(cose_alg)?,
        }
        seq.serialize_element(&self.val)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for Digest<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DigestVisitor<'a> {
            _phantom: std::marker::PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for DigestVisitor<'a> {
            type Value = Digest<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "a CBOR sequence of [alg, val] where alg is an int or text and val is bytes",
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let alg = seq
                    .next_element_seed(AlgLabelSeed {
                        _phantom: std::marker::PhantomData,
                    })?
                    .ok_or_else(|| serde::de::Error::custom("missing alg field"))?;

                let val = seq
                    .next_element::<Bytes>()?
                    .ok_or_else(|| serde::de::Error::custom("missing val field"))?;

                if seq.next_element::<ciborium::value::Value>()?.is_some() {
                    return Err(serde::de::Error::custom("expected exactly 2 elements"));
                }

                Ok(Digest { alg, val })
            }
        }

        struct AlgLabelSeed<'a> {
            _phantom: std::marker::PhantomData<&'a ()>,
        }

        impl<'de, 'a> serde::de::DeserializeSeed<'de> for AlgLabelSeed<'a> {
            type Value = AlgLabel<'a>; // Changed from 'de to 'a to match Digest<'a>

            fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct AlgLabelVisitor<'a> {
                    _phantom: std::marker::PhantomData<&'a ()>,
                }

                impl<'de, 'a> Visitor<'de> for AlgLabelVisitor<'a> {
                    type Value = AlgLabel<'a>; // Match Digest<'a>

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("an integer or text for alg")
                    }

                    fn visit_i8<E>(self, value: i8) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        self.visit_i64(value as i64)
                    }

                    fn visit_i16<E>(self, value: i16) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        self.visit_i64(value as i64)
                    }

                    fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        self.visit_i64(value as i64)
                    }

                    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        let cose_alg = CoseAlgorithm::deserialize(
                            serde::de::value::I64Deserializer::new(value),
                        )?;
                        Ok(AlgLabel::Int(cose_alg))
                    }

                    fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        self.visit_i64(value as i64)
                    }

                    fn visit_u16<E>(self, value: u16) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        self.visit_i64(value as i64)
                    }

                    fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        self.visit_i64(value as i64)
                    }

                    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        if value > i64::MAX as u64 {
                            Err(serde::de::Error::custom(
                                "COSE algorithm ID out of i64 range",
                            ))
                        } else {
                            self.visit_i64(value as i64)
                        }
                    }

                    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok(AlgLabel::Text(Cow::Owned(value))) // Owned data, no lifetime dependency on 'de
                    }
                }

                deserializer.deserialize_any(AlgLabelVisitor {
                    _phantom: std::marker::PhantomData,
                })
            }
        }

        deserializer.deserialize_seq(DigestVisitor {
            _phantom: std::marker::PhantomData,
        })
    }
}
/// Represents either a COSE key set or a single COSE key
#[repr(C)]
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum CoseKeySetOrKey<'a> {
    /// A set of COSE keys
    KeySet(NonEmptyVec<CoseKey<'a>>),
    /// A single COSE key
    Key(CoseKey<'a>),
}

impl<'a> CoseKeySetOrKey<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            CoseKeySetOrKey::KeySet(keys) => keys.is_empty(),
            CoseKeySetOrKey::Key(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            CoseKeySetOrKey::KeySet(keys) => keys.len(),
            CoseKeySetOrKey::Key(_) => 1,
        }
    }

    pub fn as_key_set(&self) -> Option<&NonEmptyVec<CoseKey<'a>>> {
        match self {
            CoseKeySetOrKey::KeySet(keys) => Some(keys),
            _ => None,
        }
    }

    pub fn as_key(&self) -> Option<&CoseKey<'a>> {
        match self {
            CoseKeySetOrKey::Key(key) => Some(key),
            _ => None,
        }
    }
}

impl<'a> Serialize for CoseKeySetOrKey<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            CoseKeySetOrKey::KeySet(key_set) => Ok(key_set.serialize(serializer)?),
            CoseKeySetOrKey::Key(key) => Ok(key.serialize(serializer)?),
        }
    }
}

impl<'de, 'a> Deserialize<'de> for CoseKeySetOrKey<'a> {
    fn deserialize<D>(deserializer: D) -> Result<CoseKeySetOrKey<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoseKeySetOrKeyVisitor<'a> {
            _phantom: std::marker::PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for CoseKeySetOrKeyVisitor<'a> {
            type Value = CoseKeySetOrKey<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a COSE key (map) or key set (array of keys)")
            }

            // Handle array case - this should be a key set
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Read multiple keys into a vector
                let mut keys = Vec::new();
                while let Some(key) = seq.next_element::<CoseKey<'a>>()? {
                    keys.push(key);
                }

                if keys.is_empty() {
                    return Err(serde::de::Error::custom("empty key set"));
                }

                // Convert to NonEmptyVec
                let non_empty_keys = NonEmptyVec::from(keys);
                Ok(CoseKeySetOrKey::KeySet(non_empty_keys))
            }

            // Handle map case - this should be a single key
            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                // Deserialize the map as a CoseKey
                let key = CoseKey::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(CoseKeySetOrKey::Key(key))
            }
        }

        // Use deserialize_any to let serde determine the input type
        deserializer.deserialize_any(CoseKeySetOrKeyVisitor {
            _phantom: std::marker::PhantomData,
        })
    }
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

#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
/// Raw value data structure with associated mask
pub struct MaskedRawValue {
    pub value: Bytes,
    pub mask: Bytes,
}

impl Serialize for MaskedRawValue {
    // Should serialize to the following CDDL:
    //
    // tagged-masked-raw-value = #6.563([
    //   value: bytes
    //   mask : bytes
    // ])
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.value)?;
        seq.serialize_element(&self.mask)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for MaskedRawValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MaskedRawValueVisitor;

        impl<'de> Visitor<'de> for MaskedRawValueVisitor {
            type Value = MaskedRawValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence with exactly two elements (value, mask)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let value = seq
                    .next_element::<Bytes>()?
                    .ok_or_else(|| de::Error::custom("missing value"))?;
                let mask = seq
                    .next_element::<Bytes>()?
                    .ok_or_else(|| de::Error::custom("missing mask"))?;
                Ok(MaskedRawValue { value, mask })
            }
        }

        deserializer.deserialize_seq(MaskedRawValueVisitor)
    }
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

#[derive(Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
/// Represents different types of raw values
pub enum RawValueTypeChoice {
    TaggedBytes(TaggedBytes),
    TaggedMaskedRawValue(TaggedMaskedRawValue),
}

impl RawValueTypeChoice {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::TaggedBytes(tagged_bytes) => Some(tagged_bytes.as_ref().as_ref()),
            _ => None,
        }
    }

    pub fn as_raw_mask_value(&self) -> Option<(&[u8], &[u8])> {
        match self {
            Self::TaggedMaskedRawValue(tmrv) => Some((&tmrv.as_ref().value, &tmrv.as_ref().mask)),
            _ => None,
        }
    }
}

impl Serialize for RawValueTypeChoice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;

        match self {
            Self::TaggedBytes(tagged) => {
                seq.serialize_element(&560u16)?; // Tag 560 for TaggedBytes.
                seq.serialize_element(&tagged.0 .0)?;
            }
            Self::TaggedMaskedRawValue(tagged) => {
                seq.serialize_element(&563u16)?; // Tag 563 for TaggedMaskedRawValue.
                seq.serialize_element(&tagged.0 .0)?;
            }
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for RawValueTypeChoice {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagVisitor;

        impl<'de> Visitor<'de> for TagVisitor {
            type Value = RawValueTypeChoice;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter
                    .write_str("a RawValueTypeChoice variant distinguished by CBOR tag (560, 563)")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let tag: u16 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("missing tag"))?;

                match tag {
                    560 => {
                        let value: TaggedBytes = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(RawValueTypeChoice::TaggedBytes(value))
                    }
                    563 => {
                        let value: TaggedMaskedRawValue = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::custom("missing tagged value"))?;
                        Ok(RawValueTypeChoice::TaggedMaskedRawValue(value))
                    }
                    _ => Err(de::Error::custom(format!("unsupported CBOR tag: {}", tag))),
                }
            }
        }

        deserializer.deserialize_any(TagVisitor)
    }
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, TryFrom)]
#[repr(i64)]
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

impl Serialize for CoseAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Match each variant to its exact discriminant value
        let value = match self {
            Self::Unassigned0 => -65536,
            Self::RS1 => -65535,
            Self::A128CTR => -65534,
            Self::A192CTR => -65533,
            Self::A256CTR => -65532,
            Self::A128CBC => -65531,
            Self::A192CBC => -65530,
            Self::A256CBC => -65529,
            Self::Unassigned1 => -65528,
            Self::WalnutDSA => -260,
            Self::RS512 => -259,
            Self::RS384 => -258,
            Self::RS256 => -257,
            Self::Unassigned2 => -256,
            Self::ES256K => -47,
            Self::HssLms => -46,
            Self::SHAKE256 => -45,
            Self::Sha512 => -44,
            Self::Sha384 => -43,
            Self::RsaesOaepSha512 => -42,
            Self::RsaesOaepSha256 => -41,
            Self::RsaesOaepRfc => 8017,
            Self::PS512 => -39,
            Self::PS384 => -38,
            Self::PS256 => -37,
            Self::ES512 => -36,
            Self::ES384 => -35,
            Self::EcdhSsA256kw => -34,
            Self::EcdhSsA192kw => -33,
            Self::EcdhSsA128kw => -32,
            Self::EcdhEsA256kw => -31,
            Self::EcdhEsA192kw => -30,
            Self::EcdhEsA128kw => -29,
            Self::EcdhSsHkdf512 => -28,
            Self::EcdhSsHkdf256 => -27,
            Self::EcdhEsHkdf512 => -26,
            Self::EcdhEsHkdf256 => -25,
            Self::Unassigned3 => -24,
            Self::SHAKE128 => -18,
            Self::Sha512_256 => -17,
            Self::Sha256 => -16,
            Self::Sha256_64 => -15,
            Self::Sha1 => -14,
            Self::DirectHkdfAes256 => -13,
            Self::DirectHkdfAes128 => -12,
            Self::DirectHkdfSha512 => -11,
            Self::DirectHkdfSha256 => -10,
            Self::Unassigned4 => -9,
            Self::EdDSA => -8,
            Self::ES256 => -7,
            Self::Direct => -6,
            Self::A256KW => -5,
            Self::A192KW => -4,
            Self::A128KW => -3,
            Self::Unassigned5 => -2,
            Self::Reserved => 0,
            Self::A128GCM => 1,
            Self::A192GCM => 2,
            Self::A256GCM => 3,
            Self::Hmac256_64 => 4,
            Self::Hmac256_256 => 5,
            Self::Hmac384_384 => 6,
            Self::Hmac512_512 => 7,
            Self::Unassigned6 => 8,
            Self::AesCcm16_64_128 => 10,
            Self::AesCcm16_64_256 => 11,
            Self::AesCcm64_64_128 => 12,
            Self::AesCcm64_64_256 => 13,
            Self::AesMac128_64 => 14,
            Self::AesMac256_64 => 15,
            Self::Unassigned7 => 16,
            Self::ChaCha20Poly1305 => 24,
            Self::AesMac128 => 128,
            Self::AesMac256 => 256,
            Self::Unassigned8 => 27,
            Self::AesCcm16_128_128 => 30,
            Self::AesCcm16_128_256 => 31,
            Self::AesCcm64_128_128 => 32,
            Self::AesCcm64_128_256 => 33,
            Self::IvGeneration => 34,
        };

        serializer.serialize_i64(value)
    }
}
impl<'de> Deserialize<'de> for CoseAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize the value as an i64
        let value = i64::deserialize(deserializer)?;

        // Match the i64 value to the corresponding enum variant
        match value {
            -65536 => Ok(CoseAlgorithm::Unassigned0),
            -65535 => Ok(CoseAlgorithm::RS1),
            -65534 => Ok(CoseAlgorithm::A128CTR),
            -65533 => Ok(CoseAlgorithm::A192CTR),
            -65532 => Ok(CoseAlgorithm::A256CTR),
            -65531 => Ok(CoseAlgorithm::A128CBC),
            -65530 => Ok(CoseAlgorithm::A192CBC),
            -65529 => Ok(CoseAlgorithm::A256CBC),
            -65528 => Ok(CoseAlgorithm::Unassigned1),
            -260 => Ok(CoseAlgorithm::WalnutDSA),
            -259 => Ok(CoseAlgorithm::RS512),
            -258 => Ok(CoseAlgorithm::RS384),
            -257 => Ok(CoseAlgorithm::RS256),
            -256 => Ok(CoseAlgorithm::Unassigned2),
            -47 => Ok(CoseAlgorithm::ES256K),
            -46 => Ok(CoseAlgorithm::HssLms),
            -45 => Ok(CoseAlgorithm::SHAKE256),
            -44 => Ok(CoseAlgorithm::Sha512),
            -43 => Ok(CoseAlgorithm::Sha384),
            -42 => Ok(CoseAlgorithm::RsaesOaepSha512),
            -41 => Ok(CoseAlgorithm::RsaesOaepSha256),
            8017 => Ok(CoseAlgorithm::RsaesOaepRfc),
            -39 => Ok(CoseAlgorithm::PS512),
            -38 => Ok(CoseAlgorithm::PS384),
            -37 => Ok(CoseAlgorithm::PS256),
            -36 => Ok(CoseAlgorithm::ES512),
            -35 => Ok(CoseAlgorithm::ES384),
            -34 => Ok(CoseAlgorithm::EcdhSsA256kw),
            -33 => Ok(CoseAlgorithm::EcdhSsA192kw),
            -32 => Ok(CoseAlgorithm::EcdhSsA128kw),
            -31 => Ok(CoseAlgorithm::EcdhEsA256kw),
            -30 => Ok(CoseAlgorithm::EcdhEsA192kw),
            -29 => Ok(CoseAlgorithm::EcdhEsA128kw),
            -28 => Ok(CoseAlgorithm::EcdhSsHkdf512),
            -27 => Ok(CoseAlgorithm::EcdhSsHkdf256),
            -26 => Ok(CoseAlgorithm::EcdhEsHkdf512),
            -25 => Ok(CoseAlgorithm::EcdhEsHkdf256),
            -24 => Ok(CoseAlgorithm::Unassigned3),
            -18 => Ok(CoseAlgorithm::SHAKE128),
            -17 => Ok(CoseAlgorithm::Sha512_256),
            -16 => Ok(CoseAlgorithm::Sha256),
            -15 => Ok(CoseAlgorithm::Sha256_64),
            -14 => Ok(CoseAlgorithm::Sha1),
            -13 => Ok(CoseAlgorithm::DirectHkdfAes256),
            -12 => Ok(CoseAlgorithm::DirectHkdfAes128),
            -11 => Ok(CoseAlgorithm::DirectHkdfSha512),
            -10 => Ok(CoseAlgorithm::DirectHkdfSha256),
            -9 => Ok(CoseAlgorithm::Unassigned4),
            -8 => Ok(CoseAlgorithm::EdDSA),
            -7 => Ok(CoseAlgorithm::ES256),
            -6 => Ok(CoseAlgorithm::Direct),
            -5 => Ok(CoseAlgorithm::A256KW),
            -4 => Ok(CoseAlgorithm::A192KW),
            -3 => Ok(CoseAlgorithm::A128KW),
            -2 => Ok(CoseAlgorithm::Unassigned5),
            0 => Ok(CoseAlgorithm::Reserved),
            1 => Ok(CoseAlgorithm::A128GCM),
            2 => Ok(CoseAlgorithm::A192GCM),
            3 => Ok(CoseAlgorithm::A256GCM),
            4 => Ok(CoseAlgorithm::Hmac256_64),
            5 => Ok(CoseAlgorithm::Hmac256_256),
            6 => Ok(CoseAlgorithm::Hmac384_384),
            7 => Ok(CoseAlgorithm::Hmac512_512),
            8 => Ok(CoseAlgorithm::Unassigned6),
            10 => Ok(CoseAlgorithm::AesCcm16_64_128),
            11 => Ok(CoseAlgorithm::AesCcm16_64_256),
            12 => Ok(CoseAlgorithm::AesCcm64_64_128),
            13 => Ok(CoseAlgorithm::AesCcm64_64_256),
            14 => Ok(CoseAlgorithm::AesMac128_64),
            15 => Ok(CoseAlgorithm::AesMac256_64),
            16 => Ok(CoseAlgorithm::Unassigned7),
            24 => Ok(CoseAlgorithm::ChaCha20Poly1305),
            128 => Ok(CoseAlgorithm::AesMac128),
            256 => Ok(CoseAlgorithm::AesMac256),
            27 => Ok(CoseAlgorithm::Unassigned8),
            30 => Ok(CoseAlgorithm::AesCcm16_128_128),
            31 => Ok(CoseAlgorithm::AesCcm16_128_256),
            32 => Ok(CoseAlgorithm::AesCcm64_128_128),
            33 => Ok(CoseAlgorithm::AesCcm64_128_256),
            34 => Ok(CoseAlgorithm::IvGeneration),
            // If the value doesn't match any variant, return an error
            _ => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Signed(value),
                &"a valid COSE algorithm identifier",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod hash_entry {
        use super::{CoseAlgorithm, HashEntry};
        #[test]
        fn test_hash_entry_serialize() {
            /*********************************************************************
             * Explanation of Expected Bytes:
             * 0x82: CBOR array with 2 elements
             * 0x01: COSE algorithm identifier A128GCM
             * 0x45: CBOR byte string with 5 bytes
             * 0x01, 0x02, 0x03, 0x04, 0x05: 5 bytes of hash value
             *********************************************************************/
            let expected = [0x82, 0x01, 0x45, 0x01, 0x02, 0x03, 0x04, 0x05];

            let hash_entry: HashEntry = HashEntry {
                hash_alg_id: CoseAlgorithm::A128GCM,
                hash_value: vec![1, 2, 3, 4, 5].into(),
            };

            let mut actual: Vec<u8> = vec![];
            ciborium::into_writer(&hash_entry, &mut actual).unwrap();

            assert_eq!(actual.as_slice(), expected.as_slice());
        }
    }

    mod bytes {
        #[test]
        fn test_bytes_ciborium_serialize() {
            /*********************************************************************
             * Explanation of Expected Bytes:
             * 0x45: CBOR byte string with 5 bytes
             * 0x01, 0x02, 0x03, 0x04, 0x05: 5 bytes of hash value
             *********************************************************************/
            let expected = [0x45, 0x01, 0x02, 0x03, 0x04, 0x05];

            let bytes: super::Bytes = vec![1, 2, 3, 4, 5].into();

            let mut actual: Vec<u8> = vec![];
            ciborium::into_writer(&bytes, &mut actual).unwrap();

            assert_eq!(actual.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_bytes_ciborium_deserialize() {
            /*********************************************************************
             * Explanation of Input Bytes:
             * 0x45: CBOR byte string with 5 bytes
             * 0x01, 0x02, 0x03, 0x04, 0x05: 5 bytes of hash value
             *********************************************************************/
            let input = [0x45, 0x01, 0x02, 0x03, 0x04, 0x05];

            let expected: super::Bytes = vec![1, 2, 3, 4, 5].into();

            let actual: super::Bytes = ciborium::from_reader(&input[..]).unwrap();

            assert_eq!(actual, expected);
        }
    }

    mod generated_tags {
        use super::*;

        macro_rules! _compare {
            ($expected:expr, $actual:expr) => {
                print!("Expected: ");
                for byte in $expected {
                    print!("0x{:02X?}, ", byte);
                }
                println!();
                print!("Actual: ");
                for byte in $actual {
                    print!("0x{:02X?}, ", byte);
                }
                println!();
            };
        }

        #[test]
        fn test_deserialize_integer_time() {
            let value: Int = 1580000000;
            let expected = IntegerTime::from(value);
            let bytes: [u8; 6] = [0xC1, 0x1A, 0x5E, 0x2C, 0xE3, 0x00]; // C1 1A 0x5E, 0x2C, 0xE3, 0x00 = Tag 1, 1580000000
                                                                       // Deserialize
            let actual: IntegerTime = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(expected, actual);
            // Serialize (note: might use shorter encoding)
            let mut buffer = Vec::new();
            ciborium::into_writer(&expected, &mut buffer).unwrap();
        }
        // 2 bytes total: Tag 1 (C1) + 1-byte integer (Major Type 0)
        #[test]
        fn test_deserialize_integer_time_1_bytes() {
            let value: Int = 23; // Max for 1-byte encoding
            let expected = IntegerTime::from(value);
            let bytes: [u8; 2] = [0xC1, 0x17]; // C1 17 = Tag 1, 23
                                               // Deserialize
            let actual: IntegerTime = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(expected, actual);
            // Serialize
            let mut buffer = Vec::new();
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, bytes);
        }

        // 3 bytes total: Tag 1 (C1) + 2-byte integer (Major Type 0, 0x18)
        #[test]
        fn test_deserialize_integer_time_2_bytes() {
            let value: Int = 255; // Max for 2-byte encoding
            let expected = IntegerTime::from(value);
            let bytes: [u8; 3] = [0xC1, 0x18, 0xFF]; // C1 18 FF = Tag 1, 255
                                                     // Deserialize
            let actual: IntegerTime = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(expected, actual);
            // Serialize
            let mut buffer = Vec::new();
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, bytes);
        }

        #[test]
        fn test_deserialize_integer_time_3_bytes() {
            let expected = IntegerTime::from(1000i32);
            let bytes: [u8; 4] = [0xC1, 0x19, 0x03, 0xE8]; // 1000 = 0x03E8
            let actual: IntegerTime = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(expected, actual);
        }

        // 5 bytes total: Tag 1 (C1) + 4-byte integer (Major Type 0, 0x1A)
        #[test]
        fn test_deserialize_integer_time_4_bytes() {
            let value: Int = 1000; // Fits in 2 bytes, but we force 4-byte encoding
            let expected = IntegerTime::from(value);
            let bytes: [u8; 6] = [0xC1, 0x1A, 0x00, 0x00, 0x03, 0xE8]; // C1 1A 00 03 E8 = Tag 1, 1000
                                                                       // Deserialize
            let actual: IntegerTime = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(expected, actual);
            // Serialize (note: might use shorter encoding)
            let mut buffer = Vec::new();
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, &[0xC1, 0x19, 0x03, 0xE8]);
        }

        // 5 bytes total: Tag 1 (C1) + 4-byte integer (Major Type 0, 0x1A)
        #[test]
        fn test_deserialize_integer_time_4_bytes_larger() {
            let value: Int = 1580000000;
            let expected = IntegerTime::from(value);
            let bytes: [u8; 6] = [0xC1, 0x1A, 0x5E, 0x2C, 0xE3, 0x00]; // C1 1A 00 03 E8 = Tag 1, 1000
                                                                       // Deserialize
            let actual: IntegerTime = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(expected, actual);
            // Serialize (note: might use shorter encoding)
            let mut buffer = Vec::new();
            ciborium::into_writer(&expected, &mut buffer).unwrap();
        }

        #[test]
        fn test_uri_serialize_deserialize() {
            // Test value
            let uri_str = "https://example.com";
            let expected = Uri::from(Cow::Borrowed(uri_str));

            // Expected CBOR bytes: Tag 32 (D820) + Text string (63 + 19 bytes)
            let expected_bytes = [
                0xD8, 0x20, // Tag 32
                0x73, // Major Type 3, length 19 (0x60 + 0x13)
                0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, // "https://"
                0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // "example"
                0x2E, 0x63, 0x6F, 0x6D, // ".com"
            ];

            // Serialize
            let mut buffer = Vec::new();
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            // Deserialize
            let actual: Uri = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");

            // Verify inner value
            assert_eq!(*actual, uri_str, "Inner string mismatch");
        }

        #[test]
        fn test_tagged_uuid_type_serialize_deserialize() {
            let uuid_bytes: [u8; 16] = [
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00,
            ];
            // Test value
            let expected = TaggedUuidType::from(UuidType::from(FixedBytes::from(uuid_bytes)));

            // Expected CBOR bytes: Tag 37 (D825) + Byte string (0x16 bytes)
            let expected_bytes = [
                0xD8, 0x25, // Tag 37
                0x50, // Major Type 2, length 16 bytes.
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, // UUID bytes
                0xA7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
            ];

            // Serialize
            let mut buffer = Vec::new();
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            // Deserialize
            let actual: TaggedUuidType = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");

            // Verify inner value
            assert_eq!(**actual, uuid_bytes, "Inner UUID mismatch");
        }

        #[test]
        fn test_oid_type_serialize_deserialize() {
            // Test OID bytes for 2.5.4.3 (Common Name)
            let oid_bytes = [0x55, 0x04, 0x03]; // OID 2.5.4.3 (Common Name)
            let expected = OidType::from(Bytes::from(oid_bytes.as_slice()));

            // Expected CBOR bytes: Tag 111 (D86F) + Byte string (3 bytes)
            let expected_bytes = [
                0xD8, 0x6F, // Tag 111
                0x43, // Byte string of length 3
                0x55, 0x04, 0x03, // OID bytes
            ];

            // Serialize
            let mut buffer = Vec::new();
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            // Deserialize
            let actual: OidType = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");

            // Verify inner value
            assert_eq!(*actual.as_ref(), oid_bytes, "Inner OID bytes mismatch");
        }

        #[test]
        fn test_tagged_ueid_type_serialize_deserialize() {
            let ueid_bytes: [u8; 33] = [
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00, 0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66,
                0x55, 0x44, 0x00, 0x00, 0x00,
            ];
            // Test value
            let expected = TaggedUeidType::from(UeidType::from(FixedBytes::from(ueid_bytes)));

            // Expected CBOR bytes: Tag 550 (D826) + Byte string 33 bytes
            let expected_bytes = [
                0xD9, 0x02, 0x26, // Tag 550
                0x58, 0x21, // Byte String (33 bytes)
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, // UEID bytes
                0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00, 0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41,
                0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00, 0x00,
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: TaggedUeidType = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_svn_type_serialize_deserialize() {
            let expected = SvnType::from(1u32);

            // Expected CBOR bytes: Tag 550 (D826) + Byte string 33 bytes
            let expected_bytes = [
                0xD9, 0x02, 0x28, // Tag 552
                0x01, // Value 1
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: SvnType = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_min_svn_type_serialize_deserialize() {
            let expected = MinSvnType::from(0u32);

            let expected_bytes = [
                0xD9, 0x02, 0x29, // Tag 553
                0x00, // Value 0
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: MinSvnType = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_pkix_base64_key_type_serialize_deserialize() {
            let key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJQ8";
            let expected = PkixBase64KeyType::from(Cow::Borrowed(key));

            let expected_bytes = [
                0xD9, 0x02, 0x2A, // Tag 554
                0x78, 0x30, // String of 48 characters.
                0x4D, 0x49, 0x49, 0x42, 0x49, 0x6A, 0x41, 0x4E, 0x42, 0x67, 0x6B, 0x71, 0x68, 0x6B,
                0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x4F, 0x43,
                0x41, 0x51, 0x38, 0x41, 0x4D, 0x49, 0x49, 0x42, 0x43, 0x67, 0x4B, 0x43, 0x41, 0x51,
                0x45, 0x41, 0x77, 0x4A, 0x51, 0x38,
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: PkixBase64KeyType =
                ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_pkix_base64_cert_type_serialize_deserialize() {
            let key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJQ8";
            let expected = PkixBase64CertType::from(Cow::Borrowed(key));

            let expected_bytes = [
                0xD9, 0x02, 0x2B, // Tag 555
                0x78, 0x30, // String of 48 characters.
                0x4D, 0x49, 0x49, 0x42, 0x49, 0x6A, 0x41, 0x4E, 0x42, 0x67, 0x6B, 0x71, 0x68, 0x6B,
                0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x4F, 0x43,
                0x41, 0x51, 0x38, 0x41, 0x4D, 0x49, 0x49, 0x42, 0x43, 0x67, 0x4B, 0x43, 0x41, 0x51,
                0x45, 0x41, 0x77, 0x4A, 0x51, 0x38,
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: PkixBase64CertType =
                ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_pkix_base64_cert_path_type_serialize_deserialize() {
            let key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJQ8";
            let expected = PkixBase64CertPathType::from(Cow::Borrowed(key));

            let expected_bytes = [
                0xD9, 0x02, 0x2C, // Tag 556
                0x78, 0x30, // String of 48 characters.
                0x4D, 0x49, 0x49, 0x42, 0x49, 0x6A, 0x41, 0x4E, 0x42, 0x67, 0x6B, 0x71, 0x68, 0x6B,
                0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x4F, 0x43,
                0x41, 0x51, 0x38, 0x41, 0x4D, 0x49, 0x49, 0x42, 0x43, 0x67, 0x4B, 0x43, 0x41, 0x51,
                0x45, 0x41, 0x77, 0x4A, 0x51, 0x38,
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: PkixBase64CertPathType =
                ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_thumbprint_type_serialize_deserialize() {
            let thumbprint_bytes = [0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16];
            let digest = Digest {
                alg: CoseAlgorithm::Sha256.into(),
                val: Bytes::from(thumbprint_bytes.to_vec()),
            };
            let expected = ThumbprintType::from(digest);

            let expected_bytes = [
                0xD9, 0x02, 0x2D, // Tag 557
                0x82, // Array of 2 elements
                0x2F, // Algorithm (-16)
                0x4A, // Bstr of length 10
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16,
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: ThumbprintType = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_cose_key_type_serialize_deserialize() {
            // Create a basic COSE key
            let key = CoseKey {
                kty: Label::Int(1), // EC2 key type
                kid: TaggedBytes::from(Bytes::from(vec![0x01, 0x02, 0x03])),
                alg: AlgLabel::Int(CoseAlgorithm::ES256),
                key_ops: NonEmptyVec::from(Label::Int(1)), // sign operation
                base_iv: TaggedBytes::from(Bytes::from(vec![0x04, 0x05, 0x06])),
                extension: None,
            };
            let expected = CoseKeyType::from(CoseKeySetOrKey::Key(key));

            let expected_bytes = [
                0xD9, 0x02, 0x2E, // Tag 558
                0xBF, // Map *
                0x61, // (key) Text of one character
                0x31, // '1'
                0x01, // (value) unsigned integer 1
                0x61, // (key) Text of one character
                0x32, // '2'
                0xD9, 0x02, 0x30, // Tag 560
                0x43, // (value) Bstr with length of 3
                0x01, 0x02, 0x03, // "\u0001\u0002\u0003"
                0x61, // (key) Text of one character
                0x33, // '3' (algorithm)
                0x26, // (value) -6 (ES256)
                0x61, // (key) Text of one character
                0x34, // '4'
                0x81, // (value) Array of 1 element
                0x01, // Unsigned integer 1
                0x61, // (key) Text of one character
                0x35, // '5'
                0xD9, 0x02, 0x30, // Tag 560
                0x43, // (value) Bstr with length of 3
                0x04, 0x05, 0x06, // "\u0004\u0005\u0006"
                0xFF, // Primitive
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: CoseKeyType = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_cert_thumbprint_type_serialize_deserialize() {
            let thumbprint_bytes = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
            let digest = Digest {
                alg: CoseAlgorithm::Sha384.into(),
                val: Bytes::from(thumbprint_bytes.to_vec()),
            };
            let expected = CertThumprintType::from(digest);

            let expected_bytes = [
                0xD9, 0x02, 0x2F, // Tag 559
                0x82, // Array of 2 elements
                0x38, 0x2A, // Algorithm (-43 for Sha384)
                0x48, // Bstr of length 8
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, // Thumbprint bytes
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: CertThumprintType =
                ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_tagged_bytes_serialize_deserialize() {
            let bytes_data = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
            let expected = TaggedBytes::from(Bytes::from(bytes_data.to_vec()));

            let expected_bytes = [
                0xD9, 0x02, 0x30, // Tag 560
                0x45, // Bstr of length 5
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // Byte data
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: TaggedBytes = ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");

            // Verify inner value
            assert_eq!(*actual.as_ref(), bytes_data, "Inner bytes mismatch");
        }

        #[test]
        fn test_cert_path_thumbprint_type_serialize_deserialize() {
            let thumbprint_bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
            let digest = Digest {
                alg: CoseAlgorithm::Sha512.into(),
                val: Bytes::from(thumbprint_bytes.to_vec()),
            };
            let expected = CertPathThumbprintType::from(digest);

            let expected_bytes = [
                0xD9, 0x02, 0x31, // Tag 561
                0x82, // Array of 2 elements
                0x38, 0x2B, // Algorithm (-44 for Sha512)
                0x49, // Bstr of length 9
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, // Thumbprint bytes
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: CertPathThumbprintType =
                ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_pkix_asn1_der_cert_type_serialize_deserialize() {
            // Create a sample DER certificate (using placeholder bytes)
            let cert_bytes = [0x30, 0x82, 0x01, 0xF1, 0x02, 0x01, 0x01, 0x30, 0x0D];
            let tagged_bytes = TaggedBytes::from(Bytes::from(cert_bytes.to_vec()));
            let expected = PkixAsn1DerCertType::from(tagged_bytes);

            let expected_bytes = [
                0xD9, 0x02, 0x32, // Tag 562
                0xD9, 0x02, 0x30, // Tag 560 (for TaggedBytes)
                0x49, // Bstr of length 9
                0x30, 0x82, 0x01, 0xF1, 0x02, 0x01, 0x01, 0x30, 0x0D, // Certificate bytes
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: PkixAsn1DerCertType =
                ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");
        }

        #[test]
        fn test_tagged_masked_raw_value_serialize_deserialize() {
            // Create a masked raw value with value and mask
            let value_bytes = [0x01, 0x02, 0x03, 0x04];
            let mask_bytes = [0xFF, 0xFF, 0x00, 0x00];

            let masked_value = MaskedRawValue {
                value: Bytes::from(value_bytes.to_vec()),
                mask: Bytes::from(mask_bytes.to_vec()),
            };

            let expected = TaggedMaskedRawValue::from(masked_value);

            let expected_bytes = [
                0xD9, 0x02, 0x33, // Tag 563
                0x82, // Array (2)
                0x44, // Bstr of length 4
                0x01, 0x02, 0x03, 0x04, // "\u0001\u0002\u0003\u0004"
                0x44, // Bstr of length 4
                0xFF, 0xFF, 0x00, 0x00, // "\u00FF\u00FF\u0000\u0000"
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: TaggedMaskedRawValue =
                ciborium::from_reader(expected_bytes.as_slice()).unwrap();
            assert_eq!(expected, actual, "Deserialization mismatch");

            // Verify inner values
            assert_eq!(
                *actual.value.as_ref(),
                value_bytes,
                "Inner value bytes mismatch"
            );
            assert_eq!(
                *actual.mask.as_ref(),
                mask_bytes,
                "Inner mask bytes mismatch"
            );
        }
    }
}
