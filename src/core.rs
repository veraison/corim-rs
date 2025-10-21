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
    fmt::Display,
    marker::PhantomData,
    ops::{Deref, DerefMut, Index, IndexMut},
};

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use derive_more::{AsMut, AsRef, Constructor, Deref, DerefMut, From, TryFrom};
use serde::{
    de::{self, DeserializeOwned, SeqAccess, Unexpected, Visitor},
    ser::{self, Error as _, SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{empty::Empty, error::CoreError, generate_tagged, FixedBytes, Integer};

/// Text represents a UTF-8 string value
pub type Text<'a> = Cow<'a, str>;
// pub type Text = String;
/// Tstr represents a text string value
pub type Tstr<'a> = Text<'a>;
/// AnyUri represents a URI that can be relative or absolute
pub type AnyUri<'a> = Uri<'a>;
/// Time represents an integer value for time measurements
pub type Time = Integer;
/// Uint represents an unsigned 32-bit integer
pub type Uint = Integer;
/// Int represents a signed 32-bit integer
pub type Int = Integer;
/// Boolean representation.
pub type Bool = bool;
/// Floating Point variables.
pub type Float = f32;

#[derive(Debug, Default, From, PartialEq, Eq, PartialOrd, Ord, Clone, Constructor)]
pub struct Bytes {
    bytes: Vec<u8>,
}

impl Bytes {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl From<&[u8]> for Bytes {
    fn from(value: &[u8]) -> Self {
        Self {
            bytes: value.to_vec(),
        }
    }
}

impl TryFrom<&str> for Bytes {
    type Error = base64::DecodeError;

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: URL_SAFE_NO_PAD.decode(v)?,
        })
    }
}

impl TryFrom<String> for Bytes {
    type Error = base64::DecodeError;

    fn try_from(v: String) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: URL_SAFE_NO_PAD.decode(v)?,
        })
    }
}

impl From<&Bytes> for Vec<u8> {
    fn from(value: &Bytes) -> Self {
        value.bytes.clone()
    }
}

impl<const N: usize> From<&FixedBytes<N>> for Bytes {
    fn from(value: &FixedBytes<N>) -> Self {
        Self {
            bytes: value.0.into(),
        }
    }
}

impl Display for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(URL_SAFE_NO_PAD.encode(&self.bytes).as_str())
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
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(self.bytes.as_slice())
        }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Bytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or a byte array")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                v.try_into().map_err(de::Error::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                v.try_into().map_err(de::Error::custom)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(v)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Bytes {
                    bytes: Vec::from(v),
                })
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(v)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Bytes { bytes: v })
            }
        }

        if deserializer.is_human_readable() {
            // note(setrofim): when deserializing complex structures, serde may internally use a
            // number of intermediate deserializers. These do not propagate the
            // is_human_readable() of the original deserializer and always return true. This means
            // that we must be prepared to handle bytes as well as strings, even when dealing with
            // ostensibly human-readable formats.
            deserializer.deserialize_any(BytesVisitor)
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Ok(Bytes { bytes })
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, Clone, Default)]
pub struct ExtensionMap<'a>(pub BTreeMap<Integer, ExtensionValue<'a>>);

#[allow(clippy::needless_lifetimes)]
impl<'a, 'b> ExtensionMap<'a> {
    pub fn to_fully_owned(&self) -> ExtensionMap<'b> {
        let mut res = ExtensionMap::new();

        for (k, v) in &self.0 {
            res.insert(*k, v.to_fully_owned());
        }

        res
    }
}

impl<'a> ExtensionMap<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: Integer, value: ExtensionValue<'a>) {
        self.0.insert(key, value);
    }

    pub fn get(&self, key: Integer) -> Option<&ExtensionValue<'a>> {
        self.0.get(&key)
    }

    pub fn serialize_map<M, O, E>(&self, map: &mut M, _is_human_readable: bool) -> Result<(), E>
    where
        M: ser::SerializeMap<Ok = O, Error = E>,
    {
        for (key, value) in self.0.iter() {
            map.serialize_entry(key, value)?;
        }

        Ok(())
    }
}

impl Empty for ExtensionMap<'_> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// ExtensionMap represents the possible types that can be used in extensions
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, TryFrom, Clone)]
pub enum ExtensionValue<'a> {
    /// No value
    Null,
    /// Boolean values
    Bool(Bool),
    /// A bstr
    Bytes(Bytes),
    /// A signed integer
    Int(Int),
    /// A UTF-8 string value
    Text(Text<'a>),
    /// An unsigned integer
    Uint(Uint),
    /// An array of extension values
    Array(Vec<ExtensionValue<'a>>),
    /// A map of extension key-value pairs
    Map(BTreeMap<Label<'a>, ExtensionValue<'a>>),
    /// A value behind a CBOR tag
    Tag(u64, Box<ExtensionValue<'a>>),
}

#[allow(clippy::needless_lifetimes)]
impl<'a, 'b> ExtensionValue<'a> {
    /// create a deep copy of the value, converting all Cow::Borrowed into Cow::Owned
    pub fn to_fully_owned(&self) -> ExtensionValue<'b> {
        match self {
            ExtensionValue::Null => ExtensionValue::Null,
            ExtensionValue::Bool(b) => ExtensionValue::Bool(*b),
            ExtensionValue::Bytes(b) => ExtensionValue::Bytes(b.clone()),
            ExtensionValue::Int(i) => ExtensionValue::Int(*i),
            ExtensionValue::Text(t) => ExtensionValue::Text(t.to_string().into()),
            ExtensionValue::Uint(i) => ExtensionValue::Uint(*i),
            ExtensionValue::Array(a) => {
                ExtensionValue::Array(a.iter().map(|v| v.to_fully_owned()).collect())
            }
            ExtensionValue::Map(m) => {
                let mut map: BTreeMap<Label<'b>, ExtensionValue<'b>> = BTreeMap::new();
                for (k, v) in m {
                    map.insert(k.to_fully_owned(), v.to_fully_owned());
                }
                ExtensionValue::Map(map)
            }
            ExtensionValue::Tag(n, v) => ExtensionValue::Tag(*n, Box::new(v.to_fully_owned())),
        }
    }
}

impl Empty for ExtensionValue<'_> {
    fn is_empty(&self) -> bool {
        match self {
            Self::Null => true,
            Self::Text(value) => value.is_empty(),
            Self::Bytes(value) => value.bytes.is_empty(),
            Self::Uint(_) => false,
            Self::Int(_) => false,
            Self::Bool(_) => false,
            Self::Array(value) => value.is_empty(),
            Self::Map(value) => value.is_empty(),
            Self::Tag(_, value) => value.is_empty(),
        }
    }
}

impl<'a> ExtensionValue<'a> {
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
            Self::Tag(_, value) => value.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Text(value) => value.len(),
            Self::Bytes(value) => value.bytes.len(),
            Self::Uint(_) => 4,
            Self::Int(_) => 4,
            Self::Bool(_) => 1,
            Self::Array(value) => value.len(),
            Self::Map(value) => value.len(),
            Self::Tag(_, value) => value.len(),
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
            Self::Tag(_, boxed) => match boxed.deref() {
                Self::Bool(b) => Some(*b),
                _ => None,
            },
            _ => None,
        }
    }

    /// Attempts to extract an `Int` value.
    pub fn as_int(&self) -> Option<Int> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Tag(_, boxed) => match boxed.deref() {
                Self::Int(i) => Some(*i),
                _ => None,
            },
            _ => None,
        }
    }

    /// Attempts to extract a `Uint` value.
    pub fn as_uint(&self) -> Option<Uint> {
        match self {
            Self::Uint(u) => Some(*u),
            Self::Tag(_, boxed) => match boxed.deref() {
                Self::Uint(u) => Some(*u),
                _ => None,
            },
            _ => None,
        }
    }

    /// Attempts to extract a `Text` value as a string slice.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t.as_ref()),
            Self::Tag(_, boxed) => match boxed.deref() {
                Self::Text(t) => Some(t.as_ref()),
                _ => None,
            },
            _ => None,
        }
    }

    /// Attempts to extract a `Text` value as an owned string.
    pub fn as_string(&self) -> Option<String> {
        match self {
            Self::Text(text) => Some(text.to_string()),
            Self::Tag(_, boxed) => match boxed.deref() {
                Self::Text(text) => Some(text.to_string()),
                _ => None,
            },
            _ => None,
        }
    }

    /// Attempts to extract a `Bytes` value as a byte slice.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b.as_ref()),
            Self::Tag(_, boxed) => match boxed.deref() {
                Self::Bytes(b) => Some(b.as_ref()),
                _ => None,
            },
            _ => None,
        }
    }

    /// Attempts to extract an `Array` value as a reference to the vector.
    pub fn as_array(&self) -> Option<&Vec<ExtensionValue<'a>>> {
        match self {
            Self::Array(a) => Some(a),
            Self::Tag(_, boxed) => match boxed.deref() {
                Self::Array(a) => Some(a),
                _ => None,
            },
            _ => None,
        }
    }

    /// Attempts to extract a `Map` value as a reference to the map.
    pub fn as_map(&self) -> Option<&BTreeMap<Label<'a>, ExtensionValue<'a>>> {
        match self {
            Self::Map(m) => Some(m),
            Self::Tag(_, boxed) => match boxed.deref() {
                Self::Map(m) => Some(m),
                _ => None,
            },
            _ => None,
        }
    }
}

impl From<bool> for ExtensionValue<'_> {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<u64> for ExtensionValue<'_> {
    fn from(value: u64) -> Self {
        Self::Uint(value.into())
    }
}

impl From<i64> for ExtensionValue<'_> {
    fn from(value: i64) -> Self {
        Self::Int(value.into())
    }
}

impl From<i128> for ExtensionValue<'_> {
    fn from(value: i128) -> Self {
        Self::Int(value.into())
    }
}

impl<'a> From<&'a str> for ExtensionValue<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(value.into())
    }
}

impl From<String> for ExtensionValue<'_> {
    fn from(value: String) -> Self {
        Self::Text(value.into())
    }
}

impl<'a> From<&'a [u8]> for ExtensionValue<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Bytes(value.into())
    }
}

impl From<Vec<u8>> for ExtensionValue<'_> {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value.into())
    }
}

impl<'a> From<Vec<ExtensionValue<'a>>> for ExtensionValue<'a> {
    fn from(value: Vec<ExtensionValue<'a>>) -> Self {
        Self::Array(value)
    }
}

impl<'a> From<BTreeMap<Label<'a>, ExtensionValue<'a>>> for ExtensionValue<'a> {
    fn from(value: BTreeMap<Label<'a>, ExtensionValue<'a>>) -> Self {
        Self::Map(value)
    }
}

impl TryFrom<serde_json::Value> for ExtensionValue<'_> {
    type Error = CoreError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(b) => Ok(Self::Bool(b)),
            serde_json::Value::Number(n) => {
                if n.is_u64() {
                    Ok(Self::Uint(n.as_u64().unwrap().into()))
                } else if n.is_i64() {
                    Ok(Self::Int(n.as_i64().unwrap().into()))
                } else {
                    Err(CoreError::InvalidValue(
                        "floating point and BigInt extension values not supported".to_string(),
                    ))
                }
            }
            serde_json::Value::String(s) => {
                if let Some(stripped) = s.strip_prefix("[base64]:") {
                    match URL_SAFE_NO_PAD.decode(stripped) {
                        Ok(bytes) => Ok(Self::Bytes(bytes.into())),
                        Err(err) => Err(CoreError::Custom(err.to_string())),
                    }
                } else {
                    Ok(Self::Text(s.into()))
                }
            }
            serde_json::Value::Array(a) => Ok(Self::Array(
                a.into_iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<ExtensionValue>, CoreError>>()?,
            )),
            serde_json::Value::Object(m) => Ok(Self::Map(
                m.into_iter()
                    .map(|(k, v)| Ok((Label::parse(k.as_str()), Self::try_from(v)?)))
                    .collect::<Result<BTreeMap<Label, ExtensionValue>, CoreError>>()?,
            )),
        }
    }
}

impl From<&ExtensionValue<'_>> for serde_json::Value {
    fn from(value: &ExtensionValue<'_>) -> Self {
        match value {
            ExtensionValue::Null => Self::Null,
            ExtensionValue::Bool(b) => Self::Bool(*b),
            // the unwrap()'s below will never panic because arbitrary_precision feature is enabled
            ExtensionValue::Int(i) => Self::Number(serde_json::Number::from_i128(i.0).unwrap()),
            ExtensionValue::Uint(u) => Self::Number(serde_json::Number::from_i128(u.0).unwrap()),
            ExtensionValue::Bytes(b) => {
                let mut text = "[base64]:".to_string();
                text.push_str(URL_SAFE_NO_PAD.encode(b).as_str());
                Self::String(text)
            }
            ExtensionValue::Text(t) => Self::String(t.clone().into()),
            ExtensionValue::Array(a) => {
                Self::Array(a.iter().map(serde_json::Value::from).collect())
            }
            ExtensionValue::Map(m) => Self::Object(
                m.iter()
                    .map(|(k, v)| (k.to_string(), serde_json::Value::from(v)))
                    .collect(),
            ),
            ExtensionValue::Tag(u, boxed) => Self::Object({
                let mut map = serde_json::Map::new();
                map.insert(
                    "tag".to_string(),
                    serde_json::Value::Number(serde_json::Number::from_i128(*u as i128).unwrap()),
                );
                map.insert("value".to_string(), serde_json::Value::from(boxed.deref()));
                map
            }),
        }
    }
}

impl TryFrom<ciborium::Value> for ExtensionValue<'_> {
    type Error = CoreError;

    fn try_from(value: ciborium::Value) -> Result<Self, Self::Error> {
        match value {
            ciborium::Value::Null => Ok(Self::Null),
            ciborium::Value::Bool(b) => Ok(Self::Bool(b)),
            ciborium::Value::Integer(i) => {
                let raw: i128 = i128::from(i);
                if raw >= 0 {
                    Ok(Self::Uint(raw.into()))
                } else {
                    Ok(Self::Int(raw.into()))
                }
            }
            ciborium::Value::Float(_) => Err(CoreError::InvalidValue(
                "floating point extension values not supported".to_string(),
            )),
            ciborium::Value::Text(t) => {
                let val = Self::Text(t.into());
                Ok(val)
            }
            ciborium::Value::Bytes(b) => Ok(Self::Bytes(b.into())),
            ciborium::Value::Tag(u, boxed) => Ok(Self::Tag(
                u,
                Box::new(Self::try_from(boxed.deref().to_owned())?),
            )),
            ciborium::Value::Array(a) => Ok(Self::Array(
                a.into_iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<ExtensionValue>, CoreError>>()?,
            )),
            ciborium::Value::Map(m) => Ok(Self::Map(
                m.into_iter()
                    .map(|(k, v)| Ok((Label::try_from(k)?, Self::try_from(v)?)))
                    .collect::<Result<BTreeMap<Label, ExtensionValue>, CoreError>>()?,
            )),
            value => Err(CoreError::InvalidValue(format!(
                "unexpected value {value:?}"
            ))),
        }
    }
}

impl From<&ExtensionValue<'_>> for ciborium::Value {
    fn from(value: &ExtensionValue<'_>) -> Self {
        match value {
            ExtensionValue::Null => Self::Null,
            ExtensionValue::Bool(b) => Self::Bool(*b),
            ExtensionValue::Int(i) => {
                Self::Integer(ciborium::value::Integer::try_from(i.0).unwrap())
            }
            ExtensionValue::Uint(i) => {
                Self::Integer(ciborium::value::Integer::try_from(i.0).unwrap())
            }
            ExtensionValue::Bytes(b) => Self::Bytes(b.into()),
            ExtensionValue::Text(t) => Self::Text(t.clone().into()),
            ExtensionValue::Array(a) => Self::Array(a.iter().map(ciborium::Value::from).collect()),
            ExtensionValue::Map(m) => Self::Map(
                m.iter()
                    .map(|(k, v)| {
                        (
                            match k {
                                Label::Text(t) => ciborium::Value::Text(t.to_string()),
                                Label::Int(i) => {
                                    Self::Integer(ciborium::value::Integer::try_from(i.0).unwrap())
                                }
                            },
                            ciborium::Value::from(v),
                        )
                    })
                    .collect(),
            ),
            ExtensionValue::Tag(u, boxed) => {
                Self::Tag(*u, Box::new(ciborium::Value::from(boxed.deref())))
            }
        }
    }
}

impl Serialize for ExtensionValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serde_json::Value::from(self).serialize(serializer)
        } else {
            ciborium::Value::from(self).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ExtensionValue<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = serde_json::Value::deserialize(deserializer)?;
            match value {
                serde_json::Value::Object(m) => {
                    if m.contains_key("tag") && m.contains_key("value") && m.len() == 2 {
                        let tag: u64 = match m.get("tag").unwrap() {
                            serde_json::Value::Number(n) => match n.as_u64() {
                                Some(v) => Ok(v),
                                None => Err(de::Error::custom(format!("invalid tag {n:?}"))),
                            },
                            v => Err(de::Error::custom(format!("invalid tag {v:?}"))),
                        }?;

                        let val: Self = m
                            .get("value")
                            .unwrap()
                            .to_owned()
                            .try_into()
                            .map_err(de::Error::custom)?;
                        Ok(Self::Tag(tag, Box::new(val)))
                    } else {
                        serde_json::Value::Object(m)
                            .try_into()
                            .map_err(de::Error::custom)
                    }
                }
                v => v.try_into().map_err(de::Error::custom),
            }
        } else {
            ciborium::Value::deserialize(deserializer)?
                .try_into()
                .map_err(de::Error::custom)
        }
    }
}

/// UUID type representing a 16-byte unique identifier
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct UuidType(pub FixedBytes<16>);

impl From<[u8; 16]> for UuidType {
    fn from(value: [u8; 16]) -> Self {
        Self(FixedBytes::<16>(value))
    }
}

impl TryFrom<&[u8]> for UuidType {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(FixedBytes(value.try_into()?)))
    }
}

impl TryFrom<&str> for UuidType {
    type Error = uuid::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(UuidType::from(FixedBytes::from(
            *uuid::Uuid::parse_str(value)?.as_bytes(),
        )))
    }
}

impl TryFrom<String> for UuidType {
    type Error = uuid::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(UuidType::from(FixedBytes::from(
            *uuid::Uuid::parse_str(&value)?.as_bytes(),
        )))
    }
}

impl Display for UuidType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(uuid::Uuid::from_bytes(self.0 .0).to_string().as_ref())
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

impl Serialize for UuidType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0 .0)
        }
    }
}

impl<'de> Deserialize<'de> for UuidType {
    fn deserialize<D>(deserializer: D) -> Result<UuidType, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .try_into()
                .map_err(de::Error::custom)
        } else {
            Ok(UuidType::from(FixedBytes::<16>::deserialize(deserializer)?))
        }
    }
}

/// UEID type representing a Unique Entity Identifier between 7 and 33 bytes long
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct UeidType(Bytes);

impl TryFrom<&[u8]> for UeidType {
    type Error = CoreError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() >= 7 && value.len() <= 33 {
            Ok(Self(Bytes::from(value)))
        } else {
            Err(CoreError::InvalidValue(
                "UEID must be between 7 and 33 bytes long".to_string(),
            ))
        }
    }
}

impl TryFrom<Vec<u8>> for UeidType {
    type Error = CoreError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<&str> for UeidType {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|e| CoreError::InvalidValue(e.to_string()))?
            .as_slice()
            .try_into()
    }
}

impl TryFrom<String> for UeidType {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(<std::string::String as AsRef<str>>::as_ref(&value))
    }
}

impl From<&UeidType> for Vec<u8> {
    fn from(value: &UeidType) -> Self {
        value.0.bytes.clone()
    }
}

impl AsRef<[u8]> for UeidType {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for UeidType {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for UeidType {
    type Target = [u8];

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
        &self.0[index]
    }
}

impl IndexMut<usize> for UeidType {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Display for UeidType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(URL_SAFE_NO_PAD.encode(self).as_ref())
    }
}

impl Serialize for UeidType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for UeidType {
    fn deserialize<D>(deserializer: D) -> Result<UeidType, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .try_into()
                .map_err(de::Error::custom)
        } else {
            UeidType::try_from(Bytes::deserialize(deserializer)?.as_ref())
                .map_err(de::Error::custom)
        }
    }
}

// ObjectIdentifier is an identifier mechanism defined by [ITU
// X.660](https://www.itu.int/rec/T-REC-X.660-201107-I/en) for naming objects in a
// globally-unambiguous way. It is a sequence of integer nodes (textually represented as
// dot-delimited integers) representing a path through the OID tree. Each node in the tree is
// controlled by an assigning authority.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, AsRef, AsMut, Deref, DerefMut)]
pub struct ObjectIdentifier(Bytes);

impl TryFrom<&str> for ObjectIdentifier {
    type Error = oid::ObjectIdentifierError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes: Vec<u8> = oid::ObjectIdentifier::try_from(value)?.into();
        Ok(Self(bytes.into()))
    }
}

impl TryFrom<&[u8]> for ObjectIdentifier {
    type Error = oid::ObjectIdentifierError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: Vec<u8> = oid::ObjectIdentifier::try_from(value)?.into();
        Ok(Self(bytes.into()))
    }
}

impl TryFrom<Vec<u8>> for ObjectIdentifier {
    type Error = oid::ObjectIdentifierError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes: Vec<u8> = oid::ObjectIdentifier::try_from(value)?.into();
        Ok(Self(bytes.into()))
    }
}

impl AsRef<[u8]> for ObjectIdentifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for ObjectIdentifier {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Display for ObjectIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let obj = oid::ObjectIdentifier::try_from(self.0.as_ref());
        match obj {
            Ok(oid) => f.write_str(Into::<String>::into(oid).as_str()),
            Err(_) => f.write_str("<INVALID OID>"),
        }
    }
}

impl Serialize for ObjectIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let obj = oid::ObjectIdentifier::try_from(self.0.as_ref())
                .map_err(|e| S::Error::custom(format!("invalid OID: {:?}", e)))?;
            serializer.serialize_str(&Into::<String>::into(obj))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ObjectIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<ObjectIdentifier, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = oid::ObjectIdentifier::deserialize(deserializer)?.into();
        Ok(Self(bytes.into()))
    }
}

generate_tagged!(
    (1, IntegerTime, Int, "time", "A representation of time in integer format using CBOR tag 1"),
    (32, Uri, Text<'a>, 'a,  "uri", "A URI text string with CBOR tag 32"),
    (37, TaggedUuidType, UuidType, "uuid", "UUID type wrapped with CBOR tag 37"),
    (111, OidType, ObjectIdentifier, "oid", "An Object Identifier (OID) represented as bytes using CBOR tag 111"),
    (550, TaggedUeidType, UeidType, "ueid", "UEID type wrapped with CBOR tag 550"),
    (552, SvnType, Uint, "svn", "A Security Version Number (SVN) using CBOR tag 552"),
    (553, MinSvnType, Uint, "min-svn", "A minimum Security Version Number (SVN) using CBOR tag 553"),
    (554, PkixBase64KeyType, Tstr<'a>, 'a, "pkix-base64-key", "A PKIX key in base64 format using CBOR tag 554"),
    (555, PkixBase64CertType, Tstr<'a>, 'a, "pkix-base64-cert", "A PKIX certificate in base64 format using CBOR tag 555"),
    (556, PkixBase64CertPathType, Tstr<'a>, 'a, "pkix-base64-cert-path", "A PKIX certificate path in base64 format using CBOR tag 556"),
    (557, ThumbprintType, Digest, "thumbprint", "A cryptographic thumbprint using CBOR tag 557"),
    (558, CoseKeyType, CoseKeySetOrKey, "cose-key", "CBOR tag 558 wrapper for COSE Key Structures"),
    (559, CertThumbprintType, Digest, "cert-thumbprint", "A certificate thumbprint using CBOR tag 559"),
    (560, TaggedBytes, Bytes, "bytes", "A generic byte string using CBOR tag 560"),
    (561, CertPathThumbprintType, Digest, "cert-path-thumbprint", "A certificate path thumbprint using CBOR tag 561"),
    (562, PkixAsn1DerCertType, Bytes, "pkix-asn1-der-cert", "A PKIX certificate in ASN.1 DER format using CBOR tag 562"),
    (563, TaggedMaskedRawValue, MaskedRawValue, "masked-raw-value", "Represents a masked raw value with its mask"),
);

impl IntegerTime {
    pub fn as_i128(&self) -> i128 {
        self.0 .0 .0
    }
}

impl Default for IntegerTime {
    fn default() -> Self {
        0.into()
    }
}

impl From<i64> for IntegerTime {
    fn from(value: i64) -> Self {
        Int::from(value).into()
    }
}

impl<'a> From<&'a str> for Uri<'a> {
    fn from(value: &'a str) -> Self {
        Text::from(value).into()
    }
}

impl From<String> for Uri<'_> {
    fn from(value: String) -> Self {
        Text::from(value).into()
    }
}

impl From<[u8; 16]> for TaggedUuidType {
    fn from(value: [u8; 16]) -> Self {
        UuidType::from(value).into()
    }
}

impl TryFrom<&[u8]> for TaggedUuidType {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(UuidType::try_from(value)?.into())
    }
}

impl TryFrom<&str> for TaggedUuidType {
    type Error = uuid::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(UuidType::try_from(value)?.into())
    }
}

impl TryFrom<String> for TaggedUuidType {
    type Error = uuid::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(UuidType::try_from(value)?.into())
    }
}

impl TryFrom<&str> for OidType {
    type Error = oid::ObjectIdentifierError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(ObjectIdentifier::try_from(value)?.into())
    }
}

impl TryFrom<&[u8]> for OidType {
    type Error = oid::ObjectIdentifierError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(ObjectIdentifier::try_from(value)?.into())
    }
}

impl TryFrom<Vec<u8>> for OidType {
    type Error = oid::ObjectIdentifierError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(ObjectIdentifier::try_from(value)?.into())
    }
}

impl TryFrom<&[u8]> for TaggedUeidType {
    type Error = CoreError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(UeidType::try_from(value)?.into())
    }
}

impl TryFrom<&str> for TaggedUeidType {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(UeidType::try_from(value)?.into())
    }
}

impl TryFrom<String> for TaggedUeidType {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(UeidType::try_from(value)?.into())
    }
}

impl From<u64> for SvnType {
    fn from(value: u64) -> Self {
        Uint::from(value).into()
    }
}

impl From<u64> for MinSvnType {
    fn from(value: u64) -> Self {
        Uint::from(value).into()
    }
}

impl<'a> From<&'a str> for PkixBase64KeyType<'a> {
    fn from(value: &'a str) -> Self {
        Tstr::from(value).into()
    }
}

impl<'a> From<&'a str> for PkixBase64CertType<'a> {
    fn from(value: &'a str) -> Self {
        Tstr::from(value).into()
    }
}

impl<'a> From<&'a str> for PkixBase64CertPathType<'a> {
    fn from(value: &'a str) -> Self {
        Tstr::from(value).into()
    }
}

impl TryFrom<&str> for ThumbprintType {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Digest::try_from(value)?.into())
    }
}

impl TryFrom<&str> for CertThumbprintType {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Digest::try_from(value)?.into())
    }
}

impl TaggedBytes {
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0 .0.as_slice()
    }
}

impl From<&[u8]> for TaggedBytes {
    fn from(value: &[u8]) -> Self {
        Bytes::from(value).into()
    }
}

impl TryFrom<&str> for TaggedBytes {
    type Error = base64::DecodeError;

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        Ok(Bytes::try_from(v)?.into())
    }
}

impl TryFrom<String> for TaggedBytes {
    type Error = base64::DecodeError;

    fn try_from(v: String) -> Result<Self, Self::Error> {
        Ok(Bytes::try_from(v)?.into())
    }
}

impl From<&TaggedBytes> for Vec<u8> {
    fn from(value: &TaggedBytes) -> Self {
        value.0 .0.as_ref().into()
    }
}

impl TryFrom<&str> for CertPathThumbprintType {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Digest::try_from(value)?.into())
    }
}

impl From<&[u8]> for PkixAsn1DerCertType {
    fn from(value: &[u8]) -> Self {
        Bytes::from(value).into()
    }
}

impl TryFrom<&str> for PkixAsn1DerCertType {
    type Error = base64::DecodeError;

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        Ok(Bytes::try_from(v)?.into())
    }
}

impl TryFrom<String> for PkixAsn1DerCertType {
    type Error = base64::DecodeError;

    fn try_from(v: String) -> Result<Self, Self::Error> {
        Ok(Bytes::try_from(v)?.into())
    }
}

impl From<&PkixAsn1DerCertType> for Vec<u8> {
    fn from(value: &PkixAsn1DerCertType) -> Self {
        value.0 .0.as_ref().into()
    }
}

impl From<CoseKey> for CoseKeyType {
    fn from(value: CoseKey) -> Self {
        CoseKeySetOrKey::Key(value).into()
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

impl TextOrBytes<'_> {
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
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum TextOrBytesSized<'a, const N: usize> {
    /// UTF-8 string value
    Text(Text<'a>),
    /// Fixed-size byte array
    Bytes(FixedBytes<N>),
}

impl<const N: usize> TextOrBytesSized<'_, N> {
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

impl<'a, const N: usize> From<&'a str> for TextOrBytesSized<'a, N> {
    fn from(value: &'a str) -> Self {
        TextOrBytesSized::Text(value.into())
    }
}

impl<const N: usize> From<String> for TextOrBytesSized<'_, N> {
    fn from(value: String) -> Self {
        TextOrBytesSized::Text(value.into())
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for TextOrBytesSized<'_, N> {
    type Error = CoreError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(TextOrBytesSized::Bytes(FixedBytes(
            value.try_into().map_err(|bytes: Vec<u8>| {
                CoreError::custom(format!(
                    "invalid TextOrBytesSized<{}> len: {}",
                    N,
                    bytes.len()
                ))
            })?,
        )))
    }
}

impl<const N: usize> Serialize for TextOrBytesSized<'_, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            TextOrBytesSized::Text(text) => text.serialize(serializer),
            TextOrBytesSized::Bytes(fixed_bytes) => Bytes::from(fixed_bytes).serialize(serializer),
        }
    }
}

impl<'de, const N: usize> Deserialize<'de> for TextOrBytesSized<'_, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            let text = String::deserialize(deserializer)?;

            match FixedBytes::<N>::try_from(text.clone()) {
                Ok(bytes) => Ok(TextOrBytesSized::Bytes(bytes)),
                Err(_) => Ok(TextOrBytesSized::Text(text.into())),
            }
        } else {
            let value = ciborium::Value::deserialize(deserializer)?;

            match value {
                ciborium::Value::Text(text) => Ok(TextOrBytesSized::Text(text.into())),
                ciborium::Value::Bytes(bytes) => Ok(TextOrBytesSized::Bytes(FixedBytes(
                    bytes.try_into().map_err(|bytes: Vec<u8>| {
                        de::Error::custom(format!("invalid TextOrBytesSized len: {}", bytes.len()))
                    })?,
                ))),
                other => Err(de::Error::custom(format!(
                    "invalid TextOrBytesSized type: {:?}",
                    other
                ))),
            }
        }
    }
}

pub type HashEntry = Digest;

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

#[allow(clippy::needless_lifetimes)]
impl<'a, 'b> Label<'a> {
    pub fn to_fully_owned(&self) -> Label<'b> {
        match self {
            Label::Text(t) => Label::Text(t.to_string().into()),
            Label::Int(i) => Label::Int(*i),
        }
    }
}

impl Label<'_> {
    /// Parse the provided string into a Label. If the string can be parsed
    /// into an integer, then a Label::Int is returned, otherwise a Label::Text.
    pub fn parse(value: &str) -> Self {
        match value.parse::<Integer>() {
            Ok(i) => Self::Int(i),
            Err(_) => Self::Text(value.to_owned().into()),
        }
    }

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

impl From<i64> for Label<'_> {
    fn from(value: i64) -> Self {
        Label::Int(value.into())
    }
}

impl From<i128> for Label<'_> {
    fn from(value: i128) -> Self {
        Label::Int(value.into())
    }
}

impl<'a> From<&'a str> for Label<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(std::borrow::Cow::Borrowed(value))
    }
}

impl From<String> for Label<'_> {
    fn from(value: String) -> Self {
        Self::Text(std::borrow::Cow::Owned::<str>(value))
    }
}

impl TryFrom<ciborium::Value> for Label<'_> {
    type Error = CoreError;

    fn try_from(value: ciborium::Value) -> Result<Self, Self::Error> {
        match value {
            ciborium::Value::Text(s) => Ok(Label::Text(s.into())),
            ciborium::Value::Integer(i) => Ok(Label::Int(i128::from(i).into())),
            value => Err(CoreError::InvalidValue(format!(
                "must be Integer or Text, got {value:?}"
            ))),
        }
    }
}

impl Display for Label<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let temp: String;

        match self {
            Label::Text(t) => f.write_str(t),
            Label::Int(u) => f.write_str({
                temp = u.to_string();
                temp.as_str()
            }),
        }
    }
}

/// Represents an unsigned label that can be either text or unsigned integer
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, From, TryFrom)]
pub enum Ulabel<'a> {
    /// Text label
    Text(Text<'a>),
    /// Unsigned integer label
    Uint(Uint),
}

#[allow(clippy::needless_lifetimes)]
impl<'a, 'b> Ulabel<'a> {
    pub fn to_fully_owned(&self) -> Ulabel<'b> {
        match self {
            Ulabel::Text(t) => Ulabel::Text(t.to_string().into()),
            Ulabel::Uint(i) => Ulabel::Uint(*i),
        }
    }
}

impl Ulabel<'_> {
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

impl From<u64> for Ulabel<'_> {
    fn from(value: u64) -> Self {
        Uint::from(value).into()
    }
}

impl<'a> From<&'a str> for Ulabel<'a> {
    fn from(value: &'a str) -> Self {
        Tstr::from(value).into()
    }
}

impl From<String> for Ulabel<'_> {
    fn from(value: String) -> Self {
        Tstr::from(value).into()
    }
}

impl Display for Ulabel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ulabel::Text(t) => {
                write!(f, "\"{t}\"")
            }
            Ulabel::Uint(u) => {
                write!(f, "{u}")
            }
        }
    }
}

impl Serialize for Ulabel<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();

        if is_human_readable {
            // to_string() will ensure that Text variants a quoted when they are serialized. This
            // is necessary because JSON mandates string keys and we need to distinguish between
            // labels Text("1") and Uint(1). Since 1 will be serialized as "1" when used as key, we
            // must serialize "1" as "\"1\"" to preserve the distinction.
            self.to_string().serialize(serializer)
        } else {
            match self {
                Ulabel::Text(s) => s.serialize(serializer),
                Ulabel::Uint(u) => u.serialize(serializer),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Ulabel<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UlabelVisitor<'a> {
            is_human_readable: bool,
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for UlabelVisitor<'a> {
            type Value = Ulabel<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or uint contianing the label")
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Ulabel::Uint(v.into()))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if self.is_human_readable {
                    if v.is_empty() {
                        return Err(de::Error::custom("empty label"));
                    }

                    // In JSON, both Text and Uint label keys are serialized as strings (as all
                    // JSON keys must be strings). Text keys are distinguished by that they start
                    // (and end) with a ".
                    if v.chars().nth(0).unwrap() == '"' {
                        Ok(Ulabel::Text(v[1..v.len() - 1].to_string().into()))
                    } else {
                        Ok(Ulabel::Uint(
                            v.parse::<u64>().map_err(de::Error::custom)?.into(),
                        ))
                    }
                } else {
                    Ok(Ulabel::Text(v.to_string().into()))
                }
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(v)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_any(UlabelVisitor {
            is_human_readable: is_hr,
            marker: PhantomData,
        })
    }
}

/// Represents one or more values that can be either text or integers
#[derive(Debug, Clone, PartialEq, Serialize, Eq, PartialOrd, Ord, TryFrom)]
#[serde(untagged)]
#[repr(C)]
pub enum OneOrMore<T> {
    One(T),
    More(Vec<T>),
}

impl<T: Clone> std::ops::Add for OneOrMore<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::One(lhs), Self::One(rhs)) => Self::More(vec![lhs, rhs]),
            (Self::More(lhs_vec), Self::One(rhs)) => {
                let mut new = lhs_vec.clone();
                new.push(rhs);
                Self::More(new)
            }
            (Self::One(lhs), Self::More(rhs_vec)) => {
                let mut new = vec![lhs];
                new.extend(rhs_vec.clone());
                Self::More(new)
            }
            (Self::More(lhs_vec), Self::More(rhs_vec)) => {
                let mut new = lhs_vec.clone();
                new.extend(rhs_vec.clone());
                Self::More(new)
            }
        }
    }
}

impl<T> From<T> for OneOrMore<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T: Clone> From<Vec<T>> for OneOrMore<T> {
    fn from(value: Vec<T>) -> Self {
        if value.len() == 1 {
            Self::One(value[0].clone())
        } else {
            Self::More(value)
        }
    }
}

impl<T: Clone> From<&[T]> for OneOrMore<T> {
    fn from(value: &[T]) -> Self {
        if value.len() == 1 {
            Self::One(value[0].clone())
        } else {
            Self::More(value.to_vec())
        }
    }
}

impl<T: Clone> OneOrMore<T> {
    pub fn is_one(&self) -> bool {
        match self {
            Self::One(_) => true,
            Self::More(_) => false,
        }
    }

    pub fn as_one(&self) -> Option<T> {
        match self {
            Self::One(val) => Some(val.clone()),
            _ => None,
        }
    }

    pub fn as_many(&self) -> Option<&[T]> {
        match self {
            Self::More(val) => Some(val),
            _ => None,
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        match self {
            Self::One(val) => vec![val.clone()],
            Self::More(val) => val.clone(),
        }
    }
}

impl<T> OneOrMore<T> {
    pub fn is_empty(&self) -> bool {
        match self {
            OneOrMore::One(_) => false,
            OneOrMore::More(items) => items.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            OneOrMore::One(_) => 1usize,
            OneOrMore::More(items) => items.len(),
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
            OneOrMore::More(items) => items.get(index),
        }
    }
}

impl<T: Clone> IntoIterator for OneOrMore<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::One(one) => vec![one].into_iter(),
            Self::More(more) => more.into_iter(),
        }
    }
}

impl<T: Display> Display for OneOrMore<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::One(one) => f.write_str(one.to_string().as_str()),
            Self::More(more) => {
                f.write_str("[")?;

                let last = more.len() - 1;
                for (i, val) in more.iter().enumerate() {
                    f.write_str(val.to_string().as_str())?;
                    if i < last {
                        f.write_str(", ")?;
                    }
                }

                f.write_str("[")
            }
        }
    }
}

// note(setrofim): we cannot rely on the derived implementation as it cannot handle CBOR tags
// inside enum variants. Since we cannot rely on EnumAccess, I cannot think of a better way of
// handling this other than deserializing as Value, checking if it is a sequence (and therefore the
// More variant), re-serializing, and then deserializing as an appropriate type.
impl<'de, T: Clone + DeserializeOwned> Deserialize<'de> for OneOrMore<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            let (reserialized, is_seq) = match serde_json::Value::deserialize(deserializer)? {
                value @ serde_json::Value::Array(_) => {
                    (serde_json::to_string(&value).unwrap(), true)
                }
                value => (serde_json::to_string(&value).unwrap(), false),
            };

            if is_seq {
                Ok(OneOrMore::More(
                    serde_json::from_str::<Vec<T>>(&reserialized).map_err(de::Error::custom)?,
                ))
            } else {
                Ok(OneOrMore::One(
                    serde_json::from_str::<T>(&reserialized).map_err(de::Error::custom)?,
                ))
            }
        } else {
            let mut reserialized: Vec<u8> = vec![];

            let is_seq = match ciborium::Value::deserialize(deserializer)? {
                value @ ciborium::Value::Array(_) => {
                    ciborium::into_writer(&value, &mut reserialized).unwrap();
                    true
                }
                value => {
                    ciborium::into_writer(&value, &mut reserialized).unwrap();
                    false
                }
            };

            if is_seq {
                Ok(OneOrMore::More(
                    ciborium::from_reader::<Vec<T>, _>(reserialized.as_slice())
                        .map_err(de::Error::custom)?,
                ))
            } else {
                Ok(OneOrMore::One(
                    ciborium::from_reader::<T, _>(reserialized.as_slice())
                        .map_err(de::Error::custom)?,
                ))
            }
        }
    }
}

/// Represents global attributes used by various SWID structures
#[derive(Debug, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, Clone, Default)]
pub struct AttributeMap<'a>(pub BTreeMap<Label<'a>, AttributeValue<'a>>);

impl<'a> AttributeMap<'a> {
    pub fn insert(&mut self, key: Label<'a>, value: AttributeValue<'a>) {
        self.0.insert(key, value);
    }

    pub fn serialize_map<M, O, E>(&self, map: &mut M, _is_human_readable: bool) -> Result<(), E>
    where
        M: ser::SerializeMap<Ok = O, Error = E>,
    {
        for (key, value) in self.0.iter() {
            map.serialize_entry(key, value)?;
        }

        Ok(())
    }
}

impl AttributeMap<'_> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Represents the value of a global attribute. Either one or more integers, or one or more text
/// strings.
#[derive(Debug, Clone, PartialEq, Serialize, Eq, PartialOrd, Ord, From, TryFrom)]
#[serde(untagged)]
#[repr(C)]
pub enum AttributeValue<'a> {
    Text(OneOrMore<Text<'a>>),
    Int(OneOrMore<Integer>),
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

    pub fn is_one(&self) -> bool {
        match self {
            AttributeValue::Text(value) => value.is_one(),
            AttributeValue::Int(value) => value.is_one(),
        }
    }

    pub fn is_int(&self) -> bool {
        matches!(self, AttributeValue::Int(_))
    }

    pub fn is_text(&self) -> bool {
        matches!(self, AttributeValue::Text(_))
    }

    pub fn as_int(&self) -> Option<&OneOrMore<Integer>> {
        match self {
            Self::Int(val) => Some(val),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&OneOrMore<Text>> {
        match self {
            Self::Text(val) => Some(val),
            _ => None,
        }
    }

    pub fn into_int(self) -> Option<OneOrMore<Integer>> {
        match self {
            Self::Int(val) => Some(val),
            _ => None,
        }
    }

    pub fn into_text(self) -> Option<OneOrMore<Text<'a>>> {
        match self {
            Self::Text(val) => Some(val),
            _ => None,
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

    pub fn as_many_text(&self) -> Option<&[Text<'a>]> {
        match self {
            AttributeValue::Text(value) => value.as_many(),
            _ => None,
        }
    }

    pub fn as_many_int(&self) -> Option<&[Int]> {
        match self {
            AttributeValue::Int(value) => value.as_many(),
            _ => None,
        }
    }
}

impl From<i64> for AttributeValue<'_> {
    fn from(value: i64) -> Self {
        Self::Int(OneOrMore::One(value.into()))
    }
}

impl From<i128> for AttributeValue<'_> {
    fn from(value: i128) -> Self {
        Self::Int(OneOrMore::One(value.into()))
    }
}

impl From<String> for AttributeValue<'_> {
    fn from(value: String) -> Self {
        Self::Text(OneOrMore::One(value.into()))
    }
}

impl<'a> From<&'a str> for AttributeValue<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(OneOrMore::One(value.into()))
    }
}

impl From<&[i64]> for AttributeValue<'_> {
    fn from(value: &[i64]) -> Self {
        Self::Int(
            value
                .iter()
                .map(|v| Integer::from(*v))
                .collect::<Vec<Integer>>()
                .into(),
        )
    }
}

impl From<&[String]> for AttributeValue<'_> {
    fn from(value: &[String]) -> Self {
        Self::Text(
            value
                .iter()
                .map(|v| Text::from(v.to_owned()))
                .collect::<Vec<Text>>()
                .into(),
        )
    }
}

impl<'a> From<&[&'a str]> for AttributeValue<'a> {
    fn from(value: &[&'a str]) -> Self {
        Self::Text(
            value
                .iter()
                .map(|v| Text::from(*v))
                .collect::<Vec<Text>>()
                .into(),
        )
    }
}

impl Display for AttributeValue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(val) => f.write_str(val.to_string().as_str()),
            Self::Text(val) => f.write_str(val.to_string().as_str()),
        }
    }
}

impl<'de> Deserialize<'de> for AttributeValue<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let is_human_readable = deserializer.is_human_readable();

        if is_human_readable {
            match serde_json::Value::deserialize(deserializer)? {
                serde_json::Value::String(text) => Ok(Self::Text(OneOrMore::One(text.into()))),
                serde_json::Value::Number(n) => {
                    if n.is_u64() {
                        Ok(Self::Int(OneOrMore::One(n.as_u64().unwrap().into())))
                    } else if n.is_i64() {
                        Ok(Self::Int(OneOrMore::One(n.as_i64().unwrap().into())))
                    } else {
                        Err(de::Error::custom(format!(
                            "invalid global attribute value: {:?}",
                            n,
                        )))
                    }
                }
                serde_json::Value::Array(arr) => {
                    if arr.is_empty() {
                        return Err(de::Error::custom("empty global attribute value array"));
                    }

                    let is_int = match arr[0] {
                        serde_json::Value::Number(_) => Ok(true),
                        serde_json::Value::String(_) => Ok(false),
                        _ => Err(de::Error::custom(format!(
                            "invalid global attribute value: {:?}",
                            &arr[0]
                        ))),
                    }?;

                    if is_int {
                        let mut ret: Vec<Integer> = vec![];

                        for elt_value in arr.into_iter() {
                            match elt_value {
                                serde_json::Value::Number(n) => {
                                    if n.is_u64() {
                                        ret.push(n.as_u64().unwrap().into());
                                    } else if n.is_i64() {
                                        ret.push(n.as_i64().unwrap().into());
                                    } else {
                                        return Err(de::Error::custom(format!(
                                            "invalid global attribute value array element: {:?}",
                                            n,
                                        )));
                                    }
                                }
                                _ => {
                                    return Err(de::Error::custom(
                                        "mixed types inside global attribute value array",
                                    ))
                                }
                            }
                        }

                        Ok(Self::Int(OneOrMore::More(ret)))
                    } else {
                        // ! is_int
                        let mut ret: Vec<Text> = vec![];

                        for elt_value in arr.into_iter() {
                            match elt_value {
                                serde_json::Value::String(text) => {
                                    ret.push(text.into());
                                }
                                _ => {
                                    return Err(de::Error::custom(
                                        "mixed types inside global attribute value array",
                                    ))
                                }
                            }
                        }

                        Ok(Self::Text(OneOrMore::More(ret)))
                    }
                }
                value => Err(de::Error::custom(format!(
                    "invalid global attribute value: {:?}",
                    value
                ))),
            }
        } else {
            // ! is_human_readable
            match ciborium::Value::deserialize(deserializer)? {
                ciborium::Value::Text(text) => Ok(Self::Text(OneOrMore::One(text.into()))),
                ciborium::Value::Integer(n) => Ok(Self::Int(OneOrMore::One(i128::from(n).into()))),
                ciborium::Value::Array(arr) => {
                    if arr.is_empty() {
                        return Err(de::Error::custom("empty global attribute value array"));
                    }

                    let is_int = match arr[0] {
                        ciborium::Value::Integer(_) => Ok(true),
                        ciborium::Value::Text(_) => Ok(false),
                        _ => Err(de::Error::custom(format!(
                            "invalid global attribute value: {:?}",
                            &arr[0]
                        ))),
                    }?;

                    if is_int {
                        let mut ret: Vec<Integer> = vec![];

                        for elt_value in arr.into_iter() {
                            match elt_value {
                                ciborium::Value::Integer(n) => {
                                    ret.push(i128::from(n).into());
                                }
                                _ => {
                                    return Err(de::Error::custom(
                                        "mixed types inside global attribute value array",
                                    ))
                                }
                            }
                        }

                        Ok(Self::Int(OneOrMore::More(ret)))
                    } else {
                        // ! is_int
                        let mut ret: Vec<Text> = vec![];

                        for elt_value in arr.into_iter() {
                            match elt_value {
                                ciborium::Value::Text(text) => {
                                    ret.push(text.into());
                                }
                                _ => {
                                    return Err(de::Error::custom(
                                        "mixed types inside global attribute value array",
                                    ))
                                }
                            }
                        }

                        Ok(Self::Text(OneOrMore::More(ret)))
                    }
                }
                value => Err(de::Error::custom(format!(
                    "invalid global attribute value: {:?}",
                    value
                ))),
            }
        }
    }
}

/// Represents global attributes with optional language tag and arbitrary attributes
#[derive(Debug, Clone, Serialize, Deserialize, Default, From, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct GlobalAttributes<'a> {
    /// Optional language tag (ex. en_US)
    pub lang: Option<Text<'a>>,
    /// Arbitrary attributes
    pub attributes: Option<AttributeMap<'a>>,
}

impl<'a> GlobalAttributes<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        if self.lang.is_some() {
            return false;
        }

        match &self.attributes {
            Some(attributes) => attributes.is_empty(),
            None => true,
        }
    }

    pub fn insert(&mut self, key: Label<'a>, value: AttributeValue<'a>) -> Result<(), CoreError> {
        if key == Label::from("lang") || key == Label::from(15i64) {
            match value.as_one_text() {
                val @ Some(_) => self.lang = val,
                None => return Err(CoreError::InvalidValue(format!("lang: {:?}", value))),
            }
        }

        match self.attributes.as_mut() {
            Some(attributes) => {
                attributes.insert(key, value);
            }
            None => {
                let mut attributes = AttributeMap::new();
                attributes.insert(key, value);
                self.attributes = Some(attributes);
            }
        }

        Ok(())
    }

    pub fn serialize_map<M, O, E>(&self, map: &mut M, is_human_readable: bool) -> Result<(), E>
    where
        M: ser::SerializeMap<Ok = O, Error = E>,
    {
        if let Some(lang) = &self.lang {
            if is_human_readable {
                map.serialize_entry("lang", lang)?;
            } else {
                map.serialize_entry(&15, lang)?;
            }
        }

        if let Some(attributes) = &self.attributes {
            attributes.serialize_map(map, is_human_readable)
        } else {
            Ok(())
        }
    }
}

impl Empty for GlobalAttributes<'_> {
    fn is_empty(&self) -> bool {
        self.lang.is_none()
            && (self.attributes.is_none() || self.attributes.as_ref().unwrap().is_empty())
    }
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
pub struct Digest {
    /// Algorithm identifier for the digest
    pub alg: HashAlgorithm,
    /// The digest value as bytes
    pub val: Bytes,
}

impl TryFrom<&str> for Digest {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut split = value.split(";");

        let alg = HashAlgorithm::try_from(match split.next() {
            Some(v) => Ok(v),
            None => Err(CoreError::InvalidValue("empty value".to_string())),
        }?)?;

        let val = Bytes::try_from(match split.next() {
            Some(v) => Ok(v),
            None => Err(CoreError::InvalidValue("no data after \";\"".to_string())),
        }?)
        .map_err(|e| CoreError::InvalidValue(e.to_string()))?;

        match split.next() {
            Some(_) => Err(CoreError::InvalidValue(
                "too many \";\" found (expect exactly one)".to_string(),
            )),
            None => Ok(Digest { alg, val }),
        }
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{};{}", self.alg, URL_SAFE_NO_PAD.encode(&self.val),)
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let mut seq = serializer.serialize_seq(Some(2))?;
            match self.alg.to_u8() {
                Some(u) => seq.serialize_element(&u)?,
                None => seq.serialize_element(&self.alg.to_string())?,
            }
            seq.serialize_element(&self.val)?;
            seq.end()
        }
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DigestVisitor;

        impl<'de> Visitor<'de> for DigestVisitor {
            type Value = Digest;

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
                    .next_element::<HashAlgorithm>()?
                    .ok_or_else(|| serde::de::Error::custom("missing alg field"))?;

                let val = seq
                    .next_element::<Bytes>()?
                    .ok_or_else(|| serde::de::Error::custom("missing val field"))?;

                if seq.next_element::<ciborium::value::Value>()?.is_some() {
                    return Err(serde::de::Error::custom("expected exactly 2 elements"));
                }

                Ok(Digest { alg, val })
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Digest::try_from(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(DigestVisitor)
        } else {
            deserializer.deserialize_seq(DigestVisitor)
        }
    }
}
/// Represents either a COSE key set or a single COSE key
#[repr(C)]
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum CoseKeySetOrKey {
    /// A set of COSE keys
    KeySet(Vec<CoseKey>),
    /// A single COSE key
    Key(CoseKey),
}

impl CoseKeySetOrKey {
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

    pub fn as_key_set(&self) -> Option<&[CoseKey]> {
        match self {
            CoseKeySetOrKey::KeySet(keys) => Some(keys),
            _ => None,
        }
    }

    pub fn as_key(&self) -> Option<&CoseKey> {
        match self {
            CoseKeySetOrKey::Key(key) => Some(key),
            _ => None,
        }
    }
}

impl Serialize for CoseKeySetOrKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            CoseKeySetOrKey::KeySet(key_set) => key_set.serialize(serializer),
            CoseKeySetOrKey::Key(key) => key.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for CoseKeySetOrKey {
    fn deserialize<D>(deserializer: D) -> Result<CoseKeySetOrKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoseKeySetOrKeyVisitor {
            is_human_readable: bool,
        }

        impl<'de> Visitor<'de> for CoseKeySetOrKeyVisitor {
            type Value = CoseKeySetOrKey;

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
                while let Some(key) = seq.next_element::<CoseKey>()? {
                    keys.push(key);
                }

                if keys.is_empty() {
                    return Err(serde::de::Error::custom("empty key set"));
                }

                // Convert to Vec
                let non_empty_keys = keys;
                Ok(CoseKeySetOrKey::KeySet(non_empty_keys))
            }

            // Handle map case - this should be a single key
            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                // Deserialize the map as a CoseKey
                let key =
                    CoseKey::deserialize(MapAccessDeserializer::new(map, self.is_human_readable))?;

                Ok(CoseKeySetOrKey::Key(key))
            }
        }

        let is_hr = deserializer.is_human_readable();
        // Use deserialize_any to let serde determine the input type
        deserializer.deserialize_any(CoseKeySetOrKeyVisitor {
            is_human_readable: is_hr,
        })
    }
}

/// Builds a CoseKey, ensuring the constraints described in section 13 of RFC8152 are met.
/// Key types not covered by RFC8152 are currently not supported.
///
/// # Returns
///
/// * `Ok(CoseKey)` - if kty has been set to a supported key type (OKP, EC2, and Symmetric), and
///   constraints associated with the key type have been met.
/// * `Err(CoreError::InvalidValue) - if kty is invalid or some of the constraints associated with
///   the specified key type have not been met.
///
/// # Example
///
/// ```
/// # use corim_rs::core::{CoseKeyBuilder, CoseKty, Bytes, CoseEllipticCurve, CoseKeyOperation};
///
/// let cose_key = CoseKeyBuilder::new()
///     .kty(CoseKty::Ec2)
///     .crv(CoseEllipticCurve::P256)
///     .key_ops(vec![CoseKeyOperation::Sign])
///     .x(Bytes::from(vec![
///         0x7f, 0xcd, 0xce, 0x27, 0x70, 0xf6, 0xc4, 0x5d,
///         0x41, 0x83, 0xcb, 0xee, 0x6f, 0xdb, 0x4b, 0x7b,
///         0x58, 0x07, 0x33, 0x35, 0x7b, 0xe9, 0xef, 0x13,
///         0xba, 0xcf, 0x6e, 0x3c, 0x7b, 0xd1, 0x54, 0x45,
///     ]))
///     .y(Bytes::from(vec![
///         0xc7, 0xf1, 0x44, 0xcd, 0x1b, 0xbd, 0x9b, 0x7e,
///         0x87, 0x2c, 0xdf, 0xed, 0xb9, 0xee, 0xb9, 0xf4,
///         0xb3, 0x69, 0x5d, 0x6e, 0xa9, 0x0b, 0x24, 0xad,
///         0x8a, 0x46, 0x23, 0x28, 0x85, 0x88, 0xe5, 0xad,
///     ]))
///     .d(Bytes::from(vec![
///         0x8e, 0x9b, 0x10, 0x9e, 0x71, 0x90, 0x98, 0xbf,
///         0x98, 0x04, 0x87, 0xdf, 0x1f, 0x5d, 0x77, 0xe9,
///         0xcb, 0x29, 0x60, 0x6e, 0xbe, 0xd2, 0x26, 0x3b,
///         0x5f, 0x57, 0xc2, 0x13, 0xdf, 0x84, 0xf4, 0xb2,
///     ]))
///     .build().unwrap();
/// ```
pub struct CoseKeyBuilder {
    cose_key: CoseKey,
}

impl CoseKeyBuilder {
    pub fn new() -> Self {
        CoseKeyBuilder {
            cose_key: CoseKey {
                kty: CoseKty::Invalid,
                kid: None,
                alg: None,
                key_ops: None,
                base_iv: None,
                crv: None,
                x: None,
                y: None,
                d: None,
                k: None,
            },
        }
    }

    pub fn get_kty(&self) -> CoseKty {
        self.cose_key.kty
    }

    pub fn kty(mut self, kty: CoseKty) -> Self {
        self.cose_key.kty = kty;
        self
    }

    pub fn kid(mut self, kid: Bytes) -> Self {
        self.cose_key.kid = Some(kid);
        self
    }

    pub fn alg(mut self, alg: CoseAlgorithm) -> Self {
        self.cose_key.alg = Some(alg);
        self
    }

    pub fn key_ops(mut self, ops: Vec<CoseKeyOperation>) -> Self {
        self.cose_key.key_ops = Some(ops);
        self
    }

    pub fn base_iv(mut self, base_iv: Bytes) -> Self {
        self.cose_key.base_iv = Some(base_iv);
        self
    }

    pub fn crv(mut self, crv: CoseEllipticCurve) -> Self {
        self.cose_key.crv = Some(crv);
        self
    }

    pub fn x(mut self, x: Bytes) -> Self {
        self.cose_key.x = Some(x);
        self
    }

    pub fn y(mut self, y: Bytes) -> Self {
        self.cose_key.y = Some(y);
        self
    }

    pub fn d(mut self, d: Bytes) -> Self {
        self.cose_key.d = Some(d);
        self
    }

    pub fn k(mut self, k: Bytes) -> Self {
        self.cose_key.k = Some(k);
        self
    }

    pub fn build(self) -> Result<CoseKey, CoreError> {
        match self.cose_key.kty {
            CoseKty::Invalid => {
                return Err(CoreError::InvalidValue("invalid key type".to_string()));
            }

            CoseKty::Okp => {
                // check crv is set and is compatible with kty
                match self.cose_key.crv {
                    Some(CoseEllipticCurve::Ed448)
                    | Some(CoseEllipticCurve::Ed25519)
                    | Some(CoseEllipticCurve::X25519)
                    | Some(CoseEllipticCurve::X448) => {}
                    Some(crv) => {
                        return Err(CoreError::InvalidValue(format!(
                            "Invalid crv \"{}\" for OKP keys",
                            crv
                        )));
                    }
                    None => {
                        return Err(CoreError::InvalidValue(
                            "crv must be set when kty is OKP".to_string(),
                        ));
                    }
                };

                // if key_ops set, check fields required for the specified ops are set
                if let Some(key_ops) = &self.cose_key.key_ops {
                    if (key_ops.contains(&CoseKeyOperation::Sign)
                        || key_ops.contains(&CoseKeyOperation::Encrypt))
                        && self.cose_key.d.is_none()
                    {
                        return Err(CoreError::InvalidValue(
                            "d field must set be set for OKP keys when key_ops contains \"sign\" or \"encrypt\"".to_string(),
                        ));
                    }

                    if (key_ops.contains(&CoseKeyOperation::Verify)
                        || key_ops.contains(&CoseKeyOperation::Decrypt))
                        && self.cose_key.x.is_none()
                    {
                        return Err(CoreError::InvalidValue(
                                "x field must set be set for OKP keys when key_ops contains \"verify\" or \"decrypt\"".to_string(),
                            ));
                    }
                }

                // check fields invalid for kty are not set
                if self.cose_key.y.is_some() {
                    return Err(CoreError::InvalidValue(
                        "y field must not be set for OKP keys".to_string(),
                    ));
                }

                if self.cose_key.k.is_some() {
                    return Err(CoreError::InvalidValue(
                        "k field must not be set for OKP keys".to_string(),
                    ));
                }
            }

            CoseKty::Ec2 => {
                // check crv is set and is compatible with kty
                match self.cose_key.crv {
                    Some(CoseEllipticCurve::P256)
                    | Some(CoseEllipticCurve::P384)
                    | Some(CoseEllipticCurve::P521) => {}
                    Some(crv) => {
                        return Err(CoreError::InvalidValue(format!(
                            "Invalid crv \"{}\" for EC2 keys",
                            crv
                        )));
                    }
                    None => {
                        return Err(CoreError::InvalidValue(
                            "crv must be set when kty is EC2".to_string(),
                        ));
                    }
                };

                // if key_ops set, check fields required for the specified ops are set
                if let Some(key_ops) = &self.cose_key.key_ops {
                    if (key_ops.contains(&CoseKeyOperation::Sign)
                        || key_ops.contains(&CoseKeyOperation::Encrypt))
                        && self.cose_key.d.is_none()
                    {
                        return Err(CoreError::InvalidValue(
                                "d field must set be set for OKP keys when key_ops contains \"sign\" or \"encrypt\"".to_string(),
                            ));
                    }

                    if key_ops.contains(&CoseKeyOperation::Verify)
                        || key_ops.contains(&CoseKeyOperation::Decrypt)
                    {
                        if self.cose_key.x.is_none() {
                            return Err(CoreError::InvalidValue(
                                "x field must set be set for OKP keys when key_ops contains \"verify\" or \"decrypt\"".to_string(),
                            ));
                        }

                        if self.cose_key.y.is_none() {
                            return Err(CoreError::InvalidValue(
                                "y field must set be set for OKP keys when key_ops contains \"verify\" or \"decrypt\"".to_string(),
                            ));
                        }
                    }
                }

                // check fields invalid for kty are not set
                if self.cose_key.k.is_some() {
                    return Err(CoreError::InvalidValue(
                        "k field must not be set for EC2 keys".to_string(),
                    ));
                }
            }

            CoseKty::Symmetric => {
                // check required fields are set
                if self.cose_key.k.is_none() {
                    return Err(CoreError::InvalidValue(
                        "k field must be set for Symmetric keys".to_string(),
                    ));
                }

                // check fields invalid for kty are not set
                if self.cose_key.crv.is_some() {
                    return Err(CoreError::InvalidValue(
                        "crv field must not be set for Symmetric keys".to_string(),
                    ));
                }

                if self.cose_key.x.is_some() {
                    return Err(CoreError::InvalidValue(
                        "x field must not be set for Symmetric keys".to_string(),
                    ));
                }

                if self.cose_key.y.is_some() {
                    return Err(CoreError::InvalidValue(
                        "y field must not be set for Symmetric keys".to_string(),
                    ));
                }

                if self.cose_key.d.is_some() {
                    return Err(CoreError::InvalidValue(
                        "d field must not be set for Symmetric keys".to_string(),
                    ));
                }
            }

            kty => {
                return Err(CoreError::InvalidValue(format!(
                    "unsupported key type \"{}\"",
                    kty
                )));
            }
        }

        Ok(self.cose_key)
    }
}

impl Default for CoseKeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a COSE key structure as defined in RFC 8152
#[derive(Debug, Default, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct CoseKey {
    /// Key type identifier (kty)
    pub kty: CoseKty,
    /// Key identifier (kid)
    pub kid: Option<Bytes>,
    /// Algorithm identifier (alg)
    pub alg: Option<CoseAlgorithm>,
    /// Allowed operations for this key
    pub key_ops: Option<Vec<CoseKeyOperation>>,
    /// Base initialization vector
    pub base_iv: Option<Bytes>,
    /// COSE curve for OKP/EC2 keys
    pub crv: Option<CoseEllipticCurve>,
    /// Public Key X parameter for OKP/EC2 Keys
    pub x: Option<Bytes>,
    /// Public Key Y parameter for EC2 Keys
    pub y: Option<Bytes>,
    /// Private Key D parameter for OKP/EC2 Keys
    pub d: Option<Bytes>,
    /// Key value for Symmetric Keys
    pub k: Option<Bytes>,
}

impl Serialize for CoseKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.kty == CoseKty::Invalid {
            return Err(S::Error::custom("invalid kty"));
        }

        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("kty", &self.kty)?;

            if let Some(kid) = &self.kid {
                map.serialize_entry("kid", kid)?;
            }
            if let Some(alg) = &self.alg {
                map.serialize_entry("alg", alg)?;
            }
            if let Some(key_ops) = &self.key_ops {
                map.serialize_entry("key_ops", key_ops)?;
            }
            if let Some(base_iv) = &self.base_iv {
                map.serialize_entry("base_iv", base_iv)?;
            }
            if let Some(crv) = &self.crv {
                map.serialize_entry("crv", crv)?;
            }
            if let Some(x) = &self.x {
                map.serialize_entry("x", x)?;
            }
            if let Some(y) = &self.y {
                map.serialize_entry("y", y)?;
            }
            if let Some(d) = &self.d {
                map.serialize_entry("d", d)?;
            }
            if let Some(k) = &self.k {
                map.serialize_entry("k", k)?;
            }
        } else {
            // crv and k both use label -1 when serialized. As they are used by different key
            // types, it is not a problem, but we need to explicitly check that they are not
            // both set here to avoid duplicate keys in the resulting map, which would confuse
            // deserialization.
            if self.crv.is_some() && self.k.is_some() {
                return Err(serde::ser::Error::custom(
                    "crv and k fields can't both be set",
                ));
            }

            map.serialize_entry(&1, &self.kty)?;

            if let Some(kid) = &self.kid {
                map.serialize_entry(&2, kid)?;
            }
            if let Some(alg) = &self.alg {
                map.serialize_entry(&3, alg)?;
            }
            if let Some(key_ops) = &self.key_ops {
                map.serialize_entry(&4, key_ops)?;
            }
            if let Some(base_iv) = &self.base_iv {
                map.serialize_entry(&5, base_iv)?;
            }
            if let Some(crv) = &self.crv {
                map.serialize_entry(&-1, crv)?;
            }
            if let Some(x) = &self.x {
                map.serialize_entry(&-2, x)?;
            }
            if let Some(y) = &self.y {
                map.serialize_entry(&-3, y)?;
            }
            if let Some(d) = &self.d {
                map.serialize_entry(&-4, d)?;
            }
            if let Some(k) = &self.k {
                map.serialize_entry(&-1, k)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for CoseKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoseKeyVisitor {
            is_human_readable: bool,
        }

        impl<'de> Visitor<'de> for CoseKeyVisitor {
            type Value = CoseKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing the COSE key")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut kb = CoseKeyBuilder::new();
                // used to cache the label -1 value until we have the key type and can resolve it
                // to either crv or k field.
                let mut cob: Option<CurveOrBytes> = None;

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("kty") => {
                                kb = kb.kty(map.next_value::<CoseKty>()?);
                            }
                            Some("kid") => {
                                kb = kb.kid(map.next_value::<Bytes>()?);
                            }
                            Some("alg") => {
                                kb = kb.alg(map.next_value::<CoseAlgorithm>()?);
                            }
                            Some("key_ops") => {
                                kb = kb.key_ops(map.next_value::<Vec<CoseKeyOperation>>()?);
                            }
                            Some("base_iv") => {
                                kb = kb.base_iv(map.next_value::<Bytes>()?);
                            }
                            Some("crv") => {
                                kb = kb.crv(map.next_value::<CoseEllipticCurve>()?);
                            }
                            Some("x") => {
                                kb = kb.x(map.next_value::<Bytes>()?);
                            }
                            Some("y") => {
                                kb = kb.y(map.next_value::<Bytes>()?);
                            }
                            Some("d") => {
                                kb = kb.d(map.next_value::<Bytes>()?);
                            }
                            Some("k") => {
                                kb = kb.k(map.next_value::<Bytes>()?);
                            }
                            Some(s) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected CoseKey field \"{}\"",
                                    s
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(1) => {
                                kb = kb.kty(map.next_value::<CoseKty>()?);
                            }
                            Some(2) => {
                                kb = kb.kid(map.next_value::<Bytes>()?);
                            }
                            Some(3) => {
                                kb = kb.alg(map.next_value::<CoseAlgorithm>()?);
                            }
                            Some(4) => {
                                kb = kb.key_ops(map.next_value::<Vec<CoseKeyOperation>>()?);
                            }
                            Some(5) => {
                                kb = kb.base_iv(map.next_value::<Bytes>()?);
                            }
                            Some(-1) => {
                                cob = Some(map.next_value::<CurveOrBytes>()?);
                            }
                            Some(-2) => {
                                kb = kb.x(map.next_value::<Bytes>()?);
                            }
                            Some(-3) => {
                                kb = kb.y(map.next_value::<Bytes>()?);
                            }
                            Some(-4) => {
                                kb = kb.d(map.next_value::<Bytes>()?);
                            }
                            Some(i) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected CoseKey field {}",
                                    i
                                )))
                            }
                            None => break,
                        }
                    }
                }

                match cob {
                    Some(CurveOrBytes::Curve(crv)) => match kb.get_kty() {
                        CoseKty::Okp | CoseKty::Ec2 => {
                            kb = kb.crv(crv);
                        }
                        kty => {
                            return Err(de::Error::custom(format!(
                                "found curve at label -1 for kty \"{}\"",
                                kty
                            )))
                        }
                    },
                    Some(CurveOrBytes::Bytes(bytes)) => match kb.get_kty() {
                        CoseKty::Symmetric => kb = kb.d(bytes),
                        kty => {
                            return Err(de::Error::custom(format!(
                                "found bstr at label -1 for kty \"{}\"",
                                kty
                            )))
                        }
                    },
                    None => (),
                }

                kb.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(CoseKeyVisitor {
            is_human_readable: is_hr,
        })
    }
}

// When deserializing CoseKey, label -1 may refer to either crv or k field, depending on the key
// type. Since we cannot guarantee that we'll see the key type (label 1) before label -1, we need
// to deserialize as this, and then populate the correct field once the key type is known.
enum CurveOrBytes {
    Curve(CoseEllipticCurve),
    Bytes(Bytes),
}

impl<'de> Deserialize<'de> for CurveOrBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CurveOrBytesVisitor;

        impl Visitor<'_> for CurveOrBytesVisitor {
            type Value = CurveOrBytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "either a byte string key or integer curve ID, depending on kty field",
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CurveOrBytes::Bytes(Bytes::from(v)))
            }

            fn visit_borrowed_bytes<E>(self, v: &'_ [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(v)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CurveOrBytes::Curve(
                    CoseEllipticCurve::try_from(v).map_err(de::Error::custom)?,
                ))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v <= i64::MAX as u64 {
                    self.visit_i64(v as i64)
                } else {
                    Err(de::Error::invalid_value(Unexpected::Unsigned(v), &self))
                }
            }
        }

        deserializer.deserialize_any(CurveOrBytesVisitor)
    }
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
pub struct RawValueType<'a> {
    pub raw_value: RawValueTypeChoice<'a>,
    pub raw_value_mask: Option<RawValueMaskType>,
}

#[allow(clippy::needless_lifetimes)]
impl<'a, 'b> RawValueType<'a> {
    pub fn to_fully_owned(&self) -> RawValueType<'b> {
        RawValueType {
            raw_value: self.raw_value.to_fully_owned(),
            raw_value_mask: self.raw_value_mask.clone(),
        }
    }
}

impl RawValueType<'_> {
    pub fn matches(&self, other: &RawValueType) -> bool {
        // other cannot specify a mask
        if other.raw_value_mask.is_some() {
            return false;
        }
        if let RawValueTypeChoice::TaggedMaskedRawValue(_) = other.raw_value {
            return false;
        }

        match &self.raw_value {
            RawValueTypeChoice::TaggedBytes(self_bytes) => {
                if let RawValueTypeChoice::TaggedBytes(other_bytes) = &other.raw_value {
                    if let Some(mask) = &self.raw_value_mask {
                        if self_bytes.len() != mask.len() || other_bytes.len() != mask.len() {
                            return false;
                        }

                        let self_masked: Vec<u8> = self_bytes
                            .as_slice()
                            .iter()
                            .zip(mask.as_slice().iter())
                            .map(|(v, m)| v & m)
                            .collect();
                        let other_masked: Vec<u8> = other_bytes
                            .as_slice()
                            .iter()
                            .zip(mask.as_slice().iter())
                            .map(|(v, m)| v & m)
                            .collect();

                        self_masked == other_masked
                    } else {
                        self_bytes == other_bytes
                    }
                } else {
                    false
                }
            }
            RawValueTypeChoice::TaggedMaskedRawValue(self_tagged_masked) => {
                if let RawValueTypeChoice::TaggedBytes(other_bytes) = &other.raw_value {
                    if self_tagged_masked.value.len() != self_tagged_masked.mask.len()
                        || other_bytes.len() != self_tagged_masked.mask.len()
                    {
                        return false;
                    }

                    let self_masked: Vec<u8> = self_tagged_masked
                        .value
                        .as_slice()
                        .iter()
                        .zip(self_tagged_masked.mask.as_slice().iter())
                        .map(|(v, m)| v & m)
                        .collect();
                    let other_masked: Vec<u8> = other_bytes
                        .as_slice()
                        .iter()
                        .zip(self_tagged_masked.mask.as_slice().iter())
                        .map(|(v, m)| v & m)
                        .collect();

                    self_masked == other_masked
                } else {
                    false
                }
            }
            RawValueTypeChoice::Extension(self_ext) => {
                if let RawValueTypeChoice::Extension(other_ext) = &other.raw_value {
                    self_ext == other_ext
                } else {
                    false
                }
            }
        }
    }
}

/// Type alias for raw value masks
pub type RawValueMaskType = Bytes;

#[derive(Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
/// Represents different types of raw values
pub enum RawValueTypeChoice<'a> {
    TaggedBytes(TaggedBytes),
    TaggedMaskedRawValue(TaggedMaskedRawValue),
    Extension(ExtensionValue<'a>),
}

#[allow(clippy::needless_lifetimes)]
impl<'a, 'b> RawValueTypeChoice<'a> {
    pub fn to_fully_owned(&self) -> RawValueTypeChoice<'b> {
        match self {
            RawValueTypeChoice::TaggedBytes(bytes) => {
                RawValueTypeChoice::TaggedBytes(bytes.clone())
            }
            RawValueTypeChoice::TaggedMaskedRawValue(val) => {
                RawValueTypeChoice::TaggedMaskedRawValue(val.clone())
            }
            RawValueTypeChoice::Extension(ext) => {
                RawValueTypeChoice::Extension(ext.to_fully_owned())
            }
        }
    }
}

impl RawValueTypeChoice<'_> {
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

impl Serialize for RawValueTypeChoice<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::TaggedBytes(tagged_bytes) => tagged_bytes.serialize(serializer),
            Self::TaggedMaskedRawValue(tagged_masked_raw_value) => {
                tagged_masked_raw_value.serialize(serializer)
            }
            Self::Extension(ext) => ext.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RawValueTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            match serde_json::Value::deserialize(deserializer)? {
                serde_json::Value::Object(map) => {
                    if map.contains_key("type") && map.contains_key("value") && map.len() == 2 {
                        let value = serde_json::to_string(&map["value"]).unwrap();

                        match &map["type"] {
                            serde_json::Value::String(typ) => match typ.as_str() {
                                "bytes" => {
                                    let bytes: Bytes = serde_json::from_str(value.as_str())
                                        .map_err(de::Error::custom)?;
                                    Ok(RawValueTypeChoice::TaggedBytes(TaggedBytes::from(bytes)))
                                }
                                "masked-raw-value" => {
                                    let mrv: MaskedRawValue = serde_json::from_str(value.as_str())
                                        .map_err(de::Error::custom)?;
                                    Ok(RawValueTypeChoice::TaggedMaskedRawValue(
                                        TaggedMaskedRawValue::from(mrv),
                                    ))
                                }
                                s => Err(de::Error::custom(format!(
                                    "unexpected RawValueTypeChoice type \"{s}\""
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
                                Some(u) => Ok(RawValueTypeChoice::Extension(ExtensionValue::Tag(
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
                        Ok(RawValueTypeChoice::Extension(
                            ExtensionValue::try_from(serde_json::Value::Object(map))
                                .map_err(de::Error::custom)?,
                        ))
                    }
                }
                other => Ok(RawValueTypeChoice::Extension(
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
                        560 => {
                            let bytes: Bytes =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(RawValueTypeChoice::TaggedBytes(TaggedBytes::from(bytes)))
                        }
                        563 => {
                            let mrv: MaskedRawValue =
                                ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                            Ok(RawValueTypeChoice::TaggedMaskedRawValue(
                                TaggedMaskedRawValue::from(mrv),
                            ))
                        }
                        n => Ok(RawValueTypeChoice::Extension(ExtensionValue::Tag(
                            n,
                            Box::new(
                                ExtensionValue::try_from(inner.deref().to_owned())
                                    .map_err(de::Error::custom)?,
                            ),
                        ))),
                    }
                }
                other => Ok(RawValueTypeChoice::Extension(
                    other.try_into().map_err(de::Error::custom)?,
                )),
            }
        }
    }
}

/// Version scheme enumeration as defined in the specification
#[repr(i64)]
#[derive(Debug, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum VersionScheme<'a> {
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
    /// Unregistered schemes for Private Use. Must be either a string or an in in the range
    /// [-256, -1].
    PrivateUse(Label<'a>),
}

#[allow(clippy::needless_lifetimes)]
impl<'a, 'b> VersionScheme<'a> {
    pub fn to_fully_owned(&self) -> VersionScheme<'b> {
        match self {
            VersionScheme::Multipartnumeric => VersionScheme::Multipartnumeric,
            VersionScheme::MultipartnumericSuffix => VersionScheme::MultipartnumericSuffix,
            VersionScheme::Alphanumeric => VersionScheme::Alphanumeric,
            VersionScheme::Decimal => VersionScheme::Decimal,
            VersionScheme::Semver => VersionScheme::Semver,
            VersionScheme::PrivateUse(text) => VersionScheme::PrivateUse(text.to_string().into()),
        }
    }
}

impl TryFrom<i64> for VersionScheme<'_> {
    type Error = CoreError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Multipartnumeric),
            2 => Ok(Self::MultipartnumericSuffix),
            3 => Ok(Self::Alphanumeric),
            4 => Ok(Self::Decimal),
            16384 => Ok(Self::Semver),
            int @ -256..=-1 => Ok(Self::PrivateUse(Label::Int(int.into()))),
            int => Err(CoreError::InvalidValue(format!(
                "invalid version scheme {int}"
            ))),
        }
    }
}

impl TryFrom<&VersionScheme<'_>> for i64 {
    type Error = CoreError;

    fn try_from(value: &VersionScheme<'_>) -> Result<Self, Self::Error> {
        match value {
            VersionScheme::Multipartnumeric => Ok(1),
            VersionScheme::MultipartnumericSuffix => Ok(2),
            VersionScheme::Alphanumeric => Ok(3),
            VersionScheme::Decimal => Ok(4),
            VersionScheme::Semver => Ok(16384),
            VersionScheme::PrivateUse(label) => match label {
                Label::Int(int) => (*int).try_into().map_err(|e: crate::error::NumbersError| {
                    CoreError::InvalidValue(e.to_string())
                }),
                Label::Text(text) => Err(CoreError::InvalidValue(format!(
                    "Private Use version scheme \"{text}\" does not have an integer prepresention"
                ))),
            },
        }
    }
}

impl<'a> TryFrom<&'a str> for VersionScheme<'a> {
    type Error = CoreError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "multipartnumeric" => Ok(Self::Multipartnumeric),
            "multipartnumeric+suffix" => Ok(Self::MultipartnumericSuffix),
            "alphanumeric" => Ok(Self::Alphanumeric),
            "decimal" => Ok(Self::Decimal),
            "semver" => Ok(Self::Semver),
            label => match label.parse::<i128>() {
                int @ Ok(-256..=-1) => Ok(Self::PrivateUse(Label::Int(Integer(int.unwrap())))),
                Ok(int) => Err(CoreError::InvalidValue(format!(
                    "invalid version scheme {int}"
                ))),
                Err(_) => Ok(Self::PrivateUse(Label::Text(label.into()))),
            },
        }
    }
}

impl TryFrom<String> for VersionScheme<'_> {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "multipartnumeric" => Ok(Self::Multipartnumeric),
            "multipartnumeric+suffix" => Ok(Self::MultipartnumericSuffix),
            "alphanumeric" => Ok(Self::Alphanumeric),
            "decimal" => Ok(Self::Decimal),
            "semver" => Ok(Self::Semver),
            label => match label.parse::<i128>() {
                int @ Ok(-256..=-1) => Ok(Self::PrivateUse(Label::Int(Integer(int.unwrap())))),
                Ok(int) => Err(CoreError::InvalidValue(format!(
                    "invalid version scheme {int}"
                ))),
                Err(_) => Ok(Self::PrivateUse(Label::Text(label.to_owned().into()))),
            },
        }
    }
}

impl Display for VersionScheme<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tmp: String;

        let name = match self {
            Self::Multipartnumeric => "multipartnumeric",
            Self::MultipartnumericSuffix => "multipartnumeric+suffix",
            Self::Alphanumeric => "alphanumeric",
            Self::Decimal => "decimal",
            Self::Semver => "semver",
            Self::PrivateUse(label) => match label {
                Label::Int(int) => {
                    tmp = int.to_string();
                    &tmp
                }
                Label::Text(text) => text.as_ref(),
            },
        };

        f.write_str(name)
    }
}

impl Serialize for VersionScheme<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();

        if is_human_readable {
            self.to_string().serialize(serializer)
        } else {
            match i64::try_from(self) {
                Ok(int) => int.serialize(serializer),
                Err(_) => self.to_string().serialize(serializer),
            }
        }
    }
}

impl<'de> Deserialize<'de> for VersionScheme<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VersionSchemeVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'a> Visitor<'_> for VersionSchemeVisitor<'a> {
            type Value = VersionScheme<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("int or string VersionScheme identifier")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                VersionScheme::try_from(v).map_err(de::Error::custom)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v > i64::MAX as u64 {
                    return Err(de::Error::invalid_value(de::Unexpected::Unsigned(v), &self));
                }

                self.visit_i64(v as i64)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                VersionScheme::try_from(v.to_owned()).map_err(de::Error::custom)
            }

            fn visit_borrowed_str<E>(self, v: &'_ str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                VersionScheme::try_from(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(VersionSchemeVisitor {
            marker: PhantomData,
        })
    }
}

/// Hashing algorithms listed in the [IANA Named Information Hash Algorithm
/// Registry][1]. These can be represented either via their numeric ID or Hash
/// Name String. (Note: some algorithms, those in BLAKE and KangarooTwelve
/// families, do not have an ID an can only be represented via their string
/// names.)
///
/// [1]: https://www.iana.org/assignments/named-information/named-information.xhtml
///
/// Examples:
/// ```rust
/// use corim_rs::core::HashAlgorithm;
///
/// let alg = HashAlgorithm::Sha256;
/// let sha384 = HashAlgorithm::try_from("sha-384").unwrap();
/// let sha512 = HashAlgorithm::try_from(8u8).unwrap();
/// ```
#[repr(i8)]
#[derive(Debug, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum HashAlgorithm {
    Sha256 = 1,
    Sha256_128 = 2,
    Sha256_120 = 3,
    Sha256_96 = 4,
    Sha256_64 = 5,
    Sha256_32 = 6,
    Sha384 = 7,
    Sha512 = 8,
    Sha3_224 = 9,
    Sha3_256 = 10,
    Sha3_384 = 11,
    Sha3_512 = 12,

    Blake2s256 = -1,
    Blake2b256 = -2,
    Blake2b512 = -3,
    K12_256 = -4,
    K12_512 = -5,
}

impl HashAlgorithm {
    fn to_u8(&self) -> Option<u8> {
        match self {
            HashAlgorithm::Sha256 => Some(1),
            HashAlgorithm::Sha256_128 => Some(2),
            HashAlgorithm::Sha256_120 => Some(3),
            HashAlgorithm::Sha256_96 => Some(4),
            HashAlgorithm::Sha256_64 => Some(5),
            HashAlgorithm::Sha256_32 => Some(6),
            HashAlgorithm::Sha384 => Some(7),
            HashAlgorithm::Sha512 => Some(8),
            HashAlgorithm::Sha3_224 => Some(9),
            HashAlgorithm::Sha3_256 => Some(10),
            HashAlgorithm::Sha3_384 => Some(11),
            HashAlgorithm::Sha3_512 => Some(12),
            _ => None,
        }
    }
}

impl TryFrom<u8> for HashAlgorithm {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HashAlgorithm::Sha256),
            2 => Ok(HashAlgorithm::Sha256_128),
            3 => Ok(HashAlgorithm::Sha256_120),
            4 => Ok(HashAlgorithm::Sha256_96),
            5 => Ok(HashAlgorithm::Sha256_64),
            6 => Ok(HashAlgorithm::Sha256_32),
            7 => Ok(HashAlgorithm::Sha384),
            8 => Ok(HashAlgorithm::Sha512),
            9 => Ok(HashAlgorithm::Sha3_224),
            10 => Ok(HashAlgorithm::Sha3_256),
            11 => Ok(HashAlgorithm::Sha3_384),
            12 => Ok(HashAlgorithm::Sha3_512),
            v => Err(CoreError::InvalidValue(format!(
                "algorithmmust be between 0 and 63, found {v}"
            ))),
        }
    }
}

impl TryFrom<i64> for HashAlgorithm {
    type Error = CoreError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        <Self as TryFrom<u8>>::try_from(u8::try_from(value).map_err(|_| {
            CoreError::InvalidValue(format!("algorithm must be between 0 and 63, found {value}"))
        })?)
    }
}

impl TryFrom<u64> for HashAlgorithm {
    type Error = CoreError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        <Self as TryFrom<u8>>::try_from(u8::try_from(value).map_err(|_| {
            CoreError::InvalidValue(format!("algorithm must be between 0 and 63, found {value}"))
        })?)
    }
}

impl TryFrom<&str> for HashAlgorithm {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "sha-256" => Ok(HashAlgorithm::Sha256),
            "sha-256-128" => Ok(HashAlgorithm::Sha256_128),
            "sha-256-120" => Ok(HashAlgorithm::Sha256_120),
            "sha-256-96" => Ok(HashAlgorithm::Sha256_96),
            "sha-256-64" => Ok(HashAlgorithm::Sha256_64),
            "sha-256-32" => Ok(HashAlgorithm::Sha256_32),
            "sha-384" => Ok(HashAlgorithm::Sha384),
            "sha-512" => Ok(HashAlgorithm::Sha512),
            "sha3-224" => Ok(HashAlgorithm::Sha3_224),
            "sha3-256" => Ok(HashAlgorithm::Sha3_256),
            "sha3-384" => Ok(HashAlgorithm::Sha3_384),
            "sha3-512" => Ok(HashAlgorithm::Sha3_512),
            "blake2s-256" => Ok(HashAlgorithm::Blake2s256),
            "blake2b-256" => Ok(HashAlgorithm::Blake2b256),
            "blake2b-512" => Ok(HashAlgorithm::Blake2b512),
            "k12-256" => Ok(HashAlgorithm::K12_256),
            "k12-512" => Ok(HashAlgorithm::K12_512),
            s => Err(CoreError::InvalidValue(format!(
                "unkown algorithm name \"{s}\""
            ))),
        }
    }
}

impl TryFrom<String> for HashAlgorithm {
    type Error = CoreError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        <Self as TryFrom<&str>>::try_from(&value)
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match *self {
            HashAlgorithm::Sha256 => "sha-256",
            HashAlgorithm::Sha256_128 => "sha-256-128",
            HashAlgorithm::Sha256_120 => "sha-256-120",
            HashAlgorithm::Sha256_96 => "sha-256-96",
            HashAlgorithm::Sha256_64 => "sha-256-64",
            HashAlgorithm::Sha256_32 => "sha-256-32",
            HashAlgorithm::Sha384 => "sha-384",
            HashAlgorithm::Sha512 => "sha-512",
            HashAlgorithm::Sha3_224 => "sha3-224",
            HashAlgorithm::Sha3_256 => "sha3-256",
            HashAlgorithm::Sha3_384 => "sha3-384",
            HashAlgorithm::Sha3_512 => "sha3-512",
            HashAlgorithm::Blake2s256 => "blake2s-256",
            HashAlgorithm::Blake2b256 => "blake2b-256",
            HashAlgorithm::Blake2b512 => "blake2b-512",
            HashAlgorithm::K12_256 => "k12-256",
            HashAlgorithm::K12_512 => "k12-512",
        };

        f.write_str(s)
    }
}

impl Serialize for HashAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            match self.to_u8() {
                Some(u) => serializer.serialize_u8(u),
                None => serializer.serialize_str(&self.to_string()),
            }
        }
    }
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashAlgorithmVisitor;

        impl Visitor<'_> for HashAlgorithmVisitor {
            type Value = HashAlgorithm;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "an integer ID or a string name form the IANA hash algorithm registry",
                )
            }

            fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(value as i64)
            }

            fn visit_i8<E>(self, value: i8) -> Result<Self::Value, E>
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

            fn visit_i16<E>(self, value: i16) -> Result<Self::Value, E>
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

            fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(value as i64)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                HashAlgorithm::try_from(v).map_err(E::custom)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                HashAlgorithm::try_from(v).map_err(E::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                HashAlgorithm::try_from(v).map_err(E::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                HashAlgorithm::try_from(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(HashAlgorithmVisitor)
    }
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, TryFrom)]
#[repr(i64)]
pub enum CoseAlgorithm {
    // Reserved for Private Use
    PrivateUse(i64),
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
    /// WalnutDSA signature algorithm
    WalnutDSA = -260,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512 = -259,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384 = -258,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256 = -257,
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
    /// ChaCha20/Poly1305 w/ 256-bit key
    ChaCha20Poly1305 = 24,
    /// AES-MAC 128-bit key
    AesMac128 = 128,
    /// AES-MAC 256-bit key
    AesMac256 = 256,
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

const COSE_REGISTRY_PRIVATE_BOUNDARY: i64 = -65536;

impl From<CoseAlgorithm> for i64 {
    fn from(value: CoseAlgorithm) -> Self {
        match value {
            CoseAlgorithm::PrivateUse(v) => v,
            CoseAlgorithm::RS1 => -65535,
            CoseAlgorithm::A128CTR => -65534,
            CoseAlgorithm::A192CTR => -65533,
            CoseAlgorithm::A256CTR => -65532,
            CoseAlgorithm::A128CBC => -65531,
            CoseAlgorithm::A192CBC => -65530,
            CoseAlgorithm::A256CBC => -65529,
            CoseAlgorithm::WalnutDSA => -260,
            CoseAlgorithm::RS512 => -259,
            CoseAlgorithm::RS384 => -258,
            CoseAlgorithm::RS256 => -257,
            CoseAlgorithm::ES256K => -47,
            CoseAlgorithm::HssLms => -46,
            CoseAlgorithm::SHAKE256 => -45,
            CoseAlgorithm::Sha512 => -44,
            CoseAlgorithm::Sha384 => -43,
            CoseAlgorithm::RsaesOaepSha512 => -42,
            CoseAlgorithm::RsaesOaepSha256 => -41,
            CoseAlgorithm::RsaesOaepRfc => 8017,
            CoseAlgorithm::PS512 => -39,
            CoseAlgorithm::PS384 => -38,
            CoseAlgorithm::PS256 => -37,
            CoseAlgorithm::ES512 => -36,
            CoseAlgorithm::ES384 => -35,
            CoseAlgorithm::EcdhSsA256kw => -34,
            CoseAlgorithm::EcdhSsA192kw => -33,
            CoseAlgorithm::EcdhSsA128kw => -32,
            CoseAlgorithm::EcdhEsA256kw => -31,
            CoseAlgorithm::EcdhEsA192kw => -30,
            CoseAlgorithm::EcdhEsA128kw => -29,
            CoseAlgorithm::EcdhSsHkdf512 => -28,
            CoseAlgorithm::EcdhSsHkdf256 => -27,
            CoseAlgorithm::EcdhEsHkdf512 => -26,
            CoseAlgorithm::EcdhEsHkdf256 => -25,
            CoseAlgorithm::SHAKE128 => -18,
            CoseAlgorithm::Sha512_256 => -17,
            CoseAlgorithm::Sha256 => -16,
            CoseAlgorithm::Sha256_64 => -15,
            CoseAlgorithm::Sha1 => -14,
            CoseAlgorithm::DirectHkdfAes256 => -13,
            CoseAlgorithm::DirectHkdfAes128 => -12,
            CoseAlgorithm::DirectHkdfSha512 => -11,
            CoseAlgorithm::DirectHkdfSha256 => -10,
            CoseAlgorithm::EdDSA => -8,
            CoseAlgorithm::ES256 => -7,
            CoseAlgorithm::Direct => -6,
            CoseAlgorithm::A256KW => -5,
            CoseAlgorithm::A192KW => -4,
            CoseAlgorithm::A128KW => -3,
            CoseAlgorithm::A128GCM => 1,
            CoseAlgorithm::A192GCM => 2,
            CoseAlgorithm::A256GCM => 3,
            CoseAlgorithm::Hmac256_64 => 4,
            CoseAlgorithm::Hmac256_256 => 5,
            CoseAlgorithm::Hmac384_384 => 6,
            CoseAlgorithm::Hmac512_512 => 7,
            CoseAlgorithm::AesCcm16_64_128 => 10,
            CoseAlgorithm::AesCcm16_64_256 => 11,
            CoseAlgorithm::AesCcm64_64_128 => 12,
            CoseAlgorithm::AesCcm64_64_256 => 13,
            CoseAlgorithm::AesMac128_64 => 14,
            CoseAlgorithm::AesMac256_64 => 15,
            CoseAlgorithm::ChaCha20Poly1305 => 24,
            CoseAlgorithm::AesMac128 => 128,
            CoseAlgorithm::AesMac256 => 256,
            CoseAlgorithm::AesCcm16_128_128 => 30,
            CoseAlgorithm::AesCcm16_128_256 => 31,
            CoseAlgorithm::AesCcm64_128_128 => 32,
            CoseAlgorithm::AesCcm64_128_256 => 33,
            CoseAlgorithm::IvGeneration => 34,
        }
    }
}

impl TryFrom<i64> for CoseAlgorithm {
    type Error = CoreError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            -65535 => Ok(CoseAlgorithm::RS1),
            -65534 => Ok(CoseAlgorithm::A128CTR),
            -65533 => Ok(CoseAlgorithm::A192CTR),
            -65532 => Ok(CoseAlgorithm::A256CTR),
            -65531 => Ok(CoseAlgorithm::A128CBC),
            -65530 => Ok(CoseAlgorithm::A192CBC),
            -65529 => Ok(CoseAlgorithm::A256CBC),
            -260 => Ok(CoseAlgorithm::WalnutDSA),
            -259 => Ok(CoseAlgorithm::RS512),
            -258 => Ok(CoseAlgorithm::RS384),
            -257 => Ok(CoseAlgorithm::RS256),
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
            -18 => Ok(CoseAlgorithm::SHAKE128),
            -17 => Ok(CoseAlgorithm::Sha512_256),
            -16 => Ok(CoseAlgorithm::Sha256),
            -15 => Ok(CoseAlgorithm::Sha256_64),
            -14 => Ok(CoseAlgorithm::Sha1),
            -13 => Ok(CoseAlgorithm::DirectHkdfAes256),
            -12 => Ok(CoseAlgorithm::DirectHkdfAes128),
            -11 => Ok(CoseAlgorithm::DirectHkdfSha512),
            -10 => Ok(CoseAlgorithm::DirectHkdfSha256),
            -8 => Ok(CoseAlgorithm::EdDSA),
            -7 => Ok(CoseAlgorithm::ES256),
            -6 => Ok(CoseAlgorithm::Direct),
            -5 => Ok(CoseAlgorithm::A256KW),
            -4 => Ok(CoseAlgorithm::A192KW),
            -3 => Ok(CoseAlgorithm::A128KW),
            1 => Ok(CoseAlgorithm::A128GCM),
            2 => Ok(CoseAlgorithm::A192GCM),
            3 => Ok(CoseAlgorithm::A256GCM),
            4 => Ok(CoseAlgorithm::Hmac256_64),
            5 => Ok(CoseAlgorithm::Hmac256_256),
            6 => Ok(CoseAlgorithm::Hmac384_384),
            7 => Ok(CoseAlgorithm::Hmac512_512),
            10 => Ok(CoseAlgorithm::AesCcm16_64_128),
            11 => Ok(CoseAlgorithm::AesCcm16_64_256),
            12 => Ok(CoseAlgorithm::AesCcm64_64_128),
            13 => Ok(CoseAlgorithm::AesCcm64_64_256),
            14 => Ok(CoseAlgorithm::AesMac128_64),
            15 => Ok(CoseAlgorithm::AesMac256_64),
            24 => Ok(CoseAlgorithm::ChaCha20Poly1305),
            128 => Ok(CoseAlgorithm::AesMac128),
            256 => Ok(CoseAlgorithm::AesMac256),
            30 => Ok(CoseAlgorithm::AesCcm16_128_128),
            31 => Ok(CoseAlgorithm::AesCcm16_128_256),
            32 => Ok(CoseAlgorithm::AesCcm64_128_128),
            33 => Ok(CoseAlgorithm::AesCcm64_128_256),
            34 => Ok(CoseAlgorithm::IvGeneration),
            v => {
                if v < COSE_REGISTRY_PRIVATE_BOUNDARY {
                    Ok(CoseAlgorithm::PrivateUse(v))
                } else {
                    // If the value doesn't match any variant, return an error
                    Err(CoreError::InvalidValue(format!(
                        "expected a valid COSE algorithm identifier, found {}",
                        value
                    )))
                }
            }
        }
    }
}

impl TryFrom<&str> for CoseAlgorithm {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "RS1" => Ok(CoseAlgorithm::RS1),
            "A128CTR" => Ok(CoseAlgorithm::A128CTR),
            "A192CTR" => Ok(CoseAlgorithm::A192CTR),
            "A256CTR" => Ok(CoseAlgorithm::A256CTR),
            "A128CBC" => Ok(CoseAlgorithm::A128CBC),
            "A192CBC" => Ok(CoseAlgorithm::A192CBC),
            "A256CBC" => Ok(CoseAlgorithm::A256CBC),
            "WalnutDSA" => Ok(CoseAlgorithm::WalnutDSA),
            "RS512" => Ok(CoseAlgorithm::RS512),
            "RS384" => Ok(CoseAlgorithm::RS384),
            "RS256" => Ok(CoseAlgorithm::RS256),
            "ES256K" => Ok(CoseAlgorithm::ES256K),
            "HSS-LMS" => Ok(CoseAlgorithm::HssLms),
            "SHAKE256" => Ok(CoseAlgorithm::SHAKE256),
            "SHA-512" => Ok(CoseAlgorithm::Sha512),
            "SHA-384" => Ok(CoseAlgorithm::Sha384),
            "RSAES-OAEP w/ SHA-512" => Ok(CoseAlgorithm::RsaesOaepSha512),
            "RSAES-OAEP w/ SHA-256" => Ok(CoseAlgorithm::RsaesOaepSha256),
            "RSAES-OAEP w/ RFC 8017 default parameters" => Ok(CoseAlgorithm::RsaesOaepRfc),
            "PS512" => Ok(CoseAlgorithm::PS512),
            "PS384" => Ok(CoseAlgorithm::PS384),
            "PS256" => Ok(CoseAlgorithm::PS256),
            "ES512" => Ok(CoseAlgorithm::ES512),
            "ES384" => Ok(CoseAlgorithm::ES384),
            "ECDH-SS + A256KW" => Ok(CoseAlgorithm::EcdhSsA256kw),
            "ECDH-SS + A192KW" => Ok(CoseAlgorithm::EcdhSsA192kw),
            "ECDH-SS + A128KW" => Ok(CoseAlgorithm::EcdhSsA128kw),
            "ECDH-ES + A256KW" => Ok(CoseAlgorithm::EcdhEsA256kw),
            "ECDH-ES + A192KW" => Ok(CoseAlgorithm::EcdhEsA192kw),
            "ECDH-ES + A128KW" => Ok(CoseAlgorithm::EcdhEsA128kw),
            "ECDH-SS + HKDF-512" => Ok(CoseAlgorithm::EcdhSsHkdf512),
            "ECDH-SS + HKDF-256" => Ok(CoseAlgorithm::EcdhSsHkdf256),
            "ECDH-ES + HKDF-512" => Ok(CoseAlgorithm::EcdhEsHkdf512),
            "ECDH-ES + HKDF-256" => Ok(CoseAlgorithm::EcdhEsHkdf256),
            "SHAKE128" => Ok(CoseAlgorithm::SHAKE128),
            "SHA-512/256" => Ok(CoseAlgorithm::Sha512_256),
            "SHA-256" => Ok(CoseAlgorithm::Sha256),
            "SHA-256/64" => Ok(CoseAlgorithm::Sha256_64),
            "SHA-1" => Ok(CoseAlgorithm::Sha1),
            "direct+HKDF-AES-256" => Ok(CoseAlgorithm::DirectHkdfAes256),
            "direct+HKDF-AES-128" => Ok(CoseAlgorithm::DirectHkdfAes128),
            "direct+HKDF-SHA-512" => Ok(CoseAlgorithm::DirectHkdfSha512),
            "direct+HKDF-SHA-256" => Ok(CoseAlgorithm::DirectHkdfSha256),
            "EdDSA" => Ok(CoseAlgorithm::EdDSA),
            "ES256" => Ok(CoseAlgorithm::ES256),
            "direct" => Ok(CoseAlgorithm::Direct),
            "A256KW" => Ok(CoseAlgorithm::A256KW),
            "A192KW" => Ok(CoseAlgorithm::A192KW),
            "A128KW" => Ok(CoseAlgorithm::A128KW),
            "A128GCM" => Ok(CoseAlgorithm::A128GCM),
            "A192GCM" => Ok(CoseAlgorithm::A192GCM),
            "A256GCM" => Ok(CoseAlgorithm::A256GCM),
            "HMAC-256/64" => Ok(CoseAlgorithm::Hmac256_64),
            "HMAC-256/256" => Ok(CoseAlgorithm::Hmac256_256),
            "HMAC-384/384" => Ok(CoseAlgorithm::Hmac384_384),
            "HMAC-512/512" => Ok(CoseAlgorithm::Hmac512_512),
            "AES-CCM-16-64-128" => Ok(CoseAlgorithm::AesCcm16_64_128),
            "AES-CCM-16-64-256" => Ok(CoseAlgorithm::AesCcm16_64_256),
            "AES-CCM-64-64-128" => Ok(CoseAlgorithm::AesCcm64_64_128),
            "AES-CCM-64-64-256" => Ok(CoseAlgorithm::AesCcm64_64_256),
            "AES-MAC 128/64" => Ok(CoseAlgorithm::AesMac128_64),
            "AES-MAC 256/64" => Ok(CoseAlgorithm::AesMac256_64),
            "ChaCha20/Poly1305" => Ok(CoseAlgorithm::ChaCha20Poly1305),
            "AES-MAC 128/128" => Ok(CoseAlgorithm::AesMac128),
            "AES-MAC 256/256" => Ok(CoseAlgorithm::AesMac256),
            "AES-CCM-16-128-128" => Ok(CoseAlgorithm::AesCcm16_128_128),
            "AES-CCM-16-128-256" => Ok(CoseAlgorithm::AesCcm16_128_256),
            "AES-CCM-64-128-128" => Ok(CoseAlgorithm::AesCcm64_128_128),
            "AES-CCM-64-128-256" => Ok(CoseAlgorithm::AesCcm64_128_256),
            "IV-GENERATION" => Ok(CoseAlgorithm::IvGeneration),
            s => {
                if s.starts_with("PrivateUse(") {
                    let v: i64 = s[11..s.len() - 1].parse().map_err(|_| {
                        CoreError::InvalidValue(format!(
                            "expected a valid COSE algorithm name, found \"{}\"",
                            value
                        ))
                    })?;

                    if v < COSE_REGISTRY_PRIVATE_BOUNDARY {
                        Ok(CoseAlgorithm::PrivateUse(v))
                    } else {
                        Err(CoreError::InvalidValue(format!(
                            "invalid COSE algorithm Private Use value {} (must be < {})",
                            v, COSE_REGISTRY_PRIVATE_BOUNDARY,
                        )))
                    }
                } else {
                    Err(CoreError::InvalidValue(format!(
                        "expected a valid COSE algorithm name, found \"{}\"",
                        value
                    )))
                }
            }
        }
    }
}

impl Display for CoseAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String;

        let name = match self {
            CoseAlgorithm::PrivateUse(v) => {
                s = format!("PrivateUse({})", v);
                s.as_str()
            }
            CoseAlgorithm::RS1 => "RS1",
            CoseAlgorithm::A128CTR => "A128CTR",
            CoseAlgorithm::A192CTR => "A192CTR",
            CoseAlgorithm::A256CTR => "A256CTR",
            CoseAlgorithm::A128CBC => "A128CBC",
            CoseAlgorithm::A192CBC => "A192CBC",
            CoseAlgorithm::A256CBC => "A256CBC",
            CoseAlgorithm::WalnutDSA => "WalnutDSA",
            CoseAlgorithm::RS512 => "RS512",
            CoseAlgorithm::RS384 => "RS384",
            CoseAlgorithm::RS256 => "RS256",
            CoseAlgorithm::ES256K => "ES256K",
            CoseAlgorithm::HssLms => "HSS-LMS",
            CoseAlgorithm::SHAKE256 => "SHAKE256",
            CoseAlgorithm::Sha512 => "SHA-512",
            CoseAlgorithm::Sha384 => "SHA-384",
            CoseAlgorithm::RsaesOaepSha512 => "RSAES-OAEP w/ SHA-512",
            CoseAlgorithm::RsaesOaepSha256 => "RSAES-OAEP w/ SHA-256",
            CoseAlgorithm::RsaesOaepRfc => "RSAES-OAEP w/ RFC 8017 default parameters",
            CoseAlgorithm::PS512 => "PS512",
            CoseAlgorithm::PS384 => "PS384",
            CoseAlgorithm::PS256 => "PS256",
            CoseAlgorithm::ES512 => "ES512",
            CoseAlgorithm::ES384 => "ES384",
            CoseAlgorithm::EcdhSsA256kw => "ECDH-SS + A256KW",
            CoseAlgorithm::EcdhSsA192kw => "ECDH-SS + A192KW",
            CoseAlgorithm::EcdhSsA128kw => "ECDH-SS + A128KW",
            CoseAlgorithm::EcdhEsA256kw => "ECDH-ES + A256KW",
            CoseAlgorithm::EcdhEsA192kw => "ECDH-ES + A192KW",
            CoseAlgorithm::EcdhEsA128kw => "ECDH-ES + A128KW",
            CoseAlgorithm::EcdhSsHkdf512 => "ECDH-SS + HKDF-512",
            CoseAlgorithm::EcdhSsHkdf256 => "ECDH-SS + HKDF-256",
            CoseAlgorithm::EcdhEsHkdf512 => "ECDH-ES + HKDF-512",
            CoseAlgorithm::EcdhEsHkdf256 => "ECDH-ES + HKDF-256",
            CoseAlgorithm::SHAKE128 => "SHAKE128",
            CoseAlgorithm::Sha512_256 => "SHA-512/256",
            CoseAlgorithm::Sha256 => "SHA-256",
            CoseAlgorithm::Sha256_64 => "SHA-256/64",
            CoseAlgorithm::Sha1 => "SHA-1",
            CoseAlgorithm::DirectHkdfAes256 => "direct+HKDF-AES-256",
            CoseAlgorithm::DirectHkdfAes128 => "direct+HKDF-AES-128",
            CoseAlgorithm::DirectHkdfSha512 => "direct+HKDF-SHA-512",
            CoseAlgorithm::DirectHkdfSha256 => "direct+HKDF-SHA-256",
            CoseAlgorithm::EdDSA => "EdDSA",
            CoseAlgorithm::ES256 => "ES256",
            CoseAlgorithm::Direct => "direct",
            CoseAlgorithm::A256KW => "A256KW",
            CoseAlgorithm::A192KW => "A192KW",
            CoseAlgorithm::A128KW => "A128KW",
            CoseAlgorithm::A128GCM => "A128GCM",
            CoseAlgorithm::A192GCM => "A192GCM",
            CoseAlgorithm::A256GCM => "A256GCM",
            CoseAlgorithm::Hmac256_64 => "HMAC-256/64",
            CoseAlgorithm::Hmac256_256 => "HMAC-256/256",
            CoseAlgorithm::Hmac384_384 => "HMAC-384/384",
            CoseAlgorithm::Hmac512_512 => "HMAC-512/512",
            CoseAlgorithm::AesCcm16_64_128 => "AES-CCM-16-64-128",
            CoseAlgorithm::AesCcm16_64_256 => "AES-CCM-16-64-256",
            CoseAlgorithm::AesCcm64_64_128 => "AES-CCM-64-64-128",
            CoseAlgorithm::AesCcm64_64_256 => "AES-CCM-64-64-256",
            CoseAlgorithm::AesMac128_64 => "AES-MAC 128/64",
            CoseAlgorithm::AesMac256_64 => "AES-MAC 256/64",
            CoseAlgorithm::ChaCha20Poly1305 => "ChaCha20/Poly1305",
            CoseAlgorithm::AesMac128 => "AES-MAC 128/128",
            CoseAlgorithm::AesMac256 => "AES-MAC 256/256",
            CoseAlgorithm::AesCcm16_128_128 => "AES-CCM-16-128-128",
            CoseAlgorithm::AesCcm16_128_256 => "AES-CCM-16-128-256",
            CoseAlgorithm::AesCcm64_128_128 => "AES-CCM-64-128-128",
            CoseAlgorithm::AesCcm64_128_256 => "AES-CCM-64-128-256",
            CoseAlgorithm::IvGeneration => "IV-GENERATION",
        };

        f.write_str(name)
    }
}

impl Serialize for CoseAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            serializer.serialize_i64(self.to_owned().into())
        }
    }
}

impl<'de> Deserialize<'de> for CoseAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            CoseAlgorithm::try_from(String::deserialize(deserializer)?.as_str())
                .map_err(serde::de::Error::custom)
        } else {
            CoseAlgorithm::try_from(i64::deserialize(deserializer)?)
                .map_err(serde::de::Error::custom)
        }
    }
}

/// COSE key types as defined in RFC 8152 and the IANA COSE Registry
///
/// These identify the key families and, thus, the set of key-type-specific parameters to be found
/// inside the COSE key structure.
///
/// # Example
///
/// ```rust
/// use corim_rs::core::CoseKty;
///
/// let okp = CoseKty::Okp;  // Octet Key Pair
/// let ec2 = CoseKty::Ec2;  // Elliptic Curve w/ x/y coordinates
/// ```
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, TryFrom)]
#[repr(i8)]
pub enum CoseKty {
    // key type is invalid/has not been set
    #[default]
    Invalid,
    /// Octet Key Pair
    Okp = 1,
    /// Elliptic Curve Keys w/ x- and y-coordinate pair
    Ec2 = 2,
    /// RSA Key
    Rsa = 3,
    /// Symmetric Keys
    Symmetric = 4,
    /// Public key for HSS/LMS hash-based digital signature
    HssLms = 5,
    /// WallnutDSA public key
    WallnutDsa = 6,
}

impl From<CoseKty> for i8 {
    fn from(value: CoseKty) -> Self {
        value as i8
    }
}

impl TryFrom<i8> for CoseKty {
    type Error = CoreError;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CoseKty::Okp),
            2 => Ok(CoseKty::Ec2),
            3 => Ok(CoseKty::Rsa),
            4 => Ok(CoseKty::Symmetric),
            5 => Ok(CoseKty::HssLms),
            6 => Ok(CoseKty::WallnutDsa),
            i => Err(CoreError::InvalidValue(format!(
                "{} is not a valid COSE key type (must be between 1 and 6)",
                i
            ))),
        }
    }
}

impl TryFrom<&str> for CoseKty {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "OKP" => Ok(CoseKty::Okp),
            "EC2" => Ok(CoseKty::Ec2),
            "Rsa" => Ok(CoseKty::Rsa),
            "Symmetric" => Ok(CoseKty::Symmetric),
            "HSS-LMS" => Ok(CoseKty::HssLms),
            "WallnutDSA" => Ok(CoseKty::WallnutDsa),
            s => Err(CoreError::InvalidValue(format!(
                "\"{}\" is not a valid COSE key type",
                s
            ))),
        }
    }
}

impl Display for CoseKty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kty = match self {
            CoseKty::Invalid => "<INVALID>",
            CoseKty::Okp => "OKP",
            CoseKty::Ec2 => "EC2",
            CoseKty::Rsa => "Rsa",
            CoseKty::Symmetric => "Symmetric",
            CoseKty::HssLms => "HSS-LMS",
            CoseKty::WallnutDsa => "WallnutDSA",
        };

        f.write_str(kty)
    }
}

impl Serialize for CoseKty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *self == CoseKty::Invalid {
            return Err(S::Error::custom("invalid key type"));
        }

        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            serializer.serialize_i8(self.to_owned().into())
        }
    }
}

impl<'de> Deserialize<'de> for CoseKty {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let kty = String::deserialize(deserializer)?;
            Ok(CoseKty::try_from(kty.as_str()).map_err(de::Error::custom)?)
        } else {
            Ok(CoseKty::try_from(i8::deserialize(deserializer)?).map_err(de::Error::custom)?)
        }
    }
}

/// COSE key operations as defined in RFC 8152 and the IANA COSE Registry
///
/// These restrict the set of operations a COSE Key could be used for to the ones specified.
///
/// # Example
///
/// ```rust
/// use corim_rs::core::CoseKeyOperation;
///
/// let sign = CoseKeyOperation::Sign;  // key used for signing
/// let verify = CoseKeyOperation::Verify;  // key used for verification of signatures
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, TryFrom)]
#[repr(i8)]
pub enum CoseKeyOperation {
    /// The key is used to create signatures. Requires private key fields.
    Sign = 1,
    /// The key is used for verification of signatures.
    Verify = 2,
    /// The key is used for key transport encryption.
    Encrypt = 3,
    /// The key is used for key transport decryption. Requires private key fields.
    Decrypt = 4,
    /// The key is used for key wrap encryption.
    WrapKeys = 5,
    /// The key is used for key wrap decryption. Requires private key fields.
    UnwrapKeys = 6,
    /// The key is used for deriving keys.  Requires private key fields.
    KeyDerive = 7,
    /// The key is used for deriving bits not to be used as a key. Requires private key fields.
    KeyDeriveBits = 8,
    /// The key is used for creating MACs.
    MacCreate = 9,
    /// They key used for validating MACs.
    MacVerify = 10,
}

impl From<CoseKeyOperation> for i8 {
    fn from(value: CoseKeyOperation) -> Self {
        value as i8
    }
}

impl TryFrom<i8> for CoseKeyOperation {
    type Error = CoreError;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CoseKeyOperation::Sign),
            2 => Ok(CoseKeyOperation::Verify),
            3 => Ok(CoseKeyOperation::Encrypt),
            4 => Ok(CoseKeyOperation::Decrypt),
            5 => Ok(CoseKeyOperation::WrapKeys),
            6 => Ok(CoseKeyOperation::UnwrapKeys),
            7 => Ok(CoseKeyOperation::KeyDerive),
            8 => Ok(CoseKeyOperation::KeyDeriveBits),
            9 => Ok(CoseKeyOperation::MacCreate),
            10 => Ok(CoseKeyOperation::MacVerify),
            i => Err(CoreError::InvalidValue(format!(
                "{} is not a valid COSE key ops (must be between 1 and 10)",
                i
            ))),
        }
    }
}

impl TryFrom<&str> for CoseKeyOperation {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "sign" => Ok(CoseKeyOperation::Sign),
            "verify" => Ok(CoseKeyOperation::Verify),
            "encrypt" => Ok(CoseKeyOperation::Encrypt),
            "decrypt" => Ok(CoseKeyOperation::Decrypt),
            "wrapKey" => Ok(CoseKeyOperation::WrapKeys),
            "unwrapKey" => Ok(CoseKeyOperation::UnwrapKeys),
            "deriveKey" => Ok(CoseKeyOperation::KeyDerive),
            "deriveBits" => Ok(CoseKeyOperation::KeyDeriveBits),
            // unlike the other values, MAC ops are not taken from RFC7517, which does not define
            // these operations. They are taken from the "Name" column of table 4 inside RFC8152;
            // these do not constitute valid string values for CBOR serializations.
            "MAC create" => Ok(CoseKeyOperation::MacCreate),
            "MAC verify" => Ok(CoseKeyOperation::MacVerify),
            i => Err(CoreError::InvalidValue(format!(
                "{} is not a valid COSE key ops (must be between 1 and 10)",
                i
            ))),
        }
    }
}

impl Display for CoseKeyOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = match self {
            CoseKeyOperation::Sign => "sign",
            CoseKeyOperation::Verify => "verify",
            CoseKeyOperation::Encrypt => "encrypt",
            CoseKeyOperation::Decrypt => "decrypt",
            CoseKeyOperation::WrapKeys => "wrapKey",
            CoseKeyOperation::UnwrapKeys => "unwrapKey",
            CoseKeyOperation::KeyDerive => "deriveKey",
            CoseKeyOperation::KeyDeriveBits => "deriveBits",
            CoseKeyOperation::MacCreate => "MAC create",
            CoseKeyOperation::MacVerify => "MAC verify",
        };

        f.write_str(op)
    }
}

impl Serialize for CoseKeyOperation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            serializer.serialize_i8(self.to_owned().into())
        }
    }
}

impl<'de> Deserialize<'de> for CoseKeyOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoseKeyOpsVisitor {
            pub is_human_readable: bool,
        }

        impl Visitor<'_> for CoseKeyOpsVisitor {
            type Value = CoseKeyOperation;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string or integer COSE key operations identifier")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let op: CoseKeyOperation = v.try_into().map_err(de::Error::custom)?;

                // RFC8152 states that string values for key operations match those defined by
                // RFC7517, which does not define the MAC create and verify operations. Even though
                // we define string representation for these for the sake of the non-normative JSON
                // serialization, they are not valid for the normative CBOR serialization, where
                // they must appear as ints.
                if !self.is_human_readable
                    && (op == CoseKeyOperation::MacVerify || op == CoseKeyOperation::MacCreate)
                {
                    Err(de::Error::custom(
                        "string representation is not valid for MAC create and verify ops",
                    ))
                } else {
                    Ok(op)
                }
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(v.as_str())
            }

            fn visit_borrowed_str<E>(self, v: &'_ str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(v)
            }

            fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                CoseKeyOperation::try_from(v).map_err(de::Error::custom)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v <= i8::MAX as i64 && v >= i8::MIN as i64 {
                    self.visit_i8(v as i8)
                } else {
                    Err(de::Error::invalid_value(Unexpected::Signed(v), &self))
                }
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v <= i8::MAX as u64 && v > 0 {
                    self.visit_i8(v as i8)
                } else {
                    Err(de::Error::invalid_value(Unexpected::Unsigned(v), &self))
                }
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_any(CoseKeyOpsVisitor {
            is_human_readable: is_hr,
        })
    }
}

/// COSE elliptic curves as defined in RFC 8152 and the IANA COSE Registry
///
///
/// # Example
///
/// ```rust
/// use corim_rs::core::CoseEllipticCurve;
///
/// let curve1 = CoseEllipticCurve::P256; // NIST P-256 curve, EC2 keys
/// let curve2 = CoseEllipticCurve::Ed25519; // Ed25519 EdDSA curve, OKP keys
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, TryFrom)]
#[repr(i64)]
pub enum CoseEllipticCurve {
    /// Private Use
    PrivateUse(i64),
    /// NIST P-256 also known as secp256r1
    P256 = 1,
    /// NIST P-384 also known as secp384r1
    P384 = 2,
    /// NIST P-521 also known as secp521r1
    P521 = 3,
    /// X25519 for use w/ ECDH only
    X25519 = 4,
    /// X448 for use w/ ECDH only
    X448 = 5,
    /// Ed25519 for use w/ EdDSA only
    Ed25519 = 6,
    /// Ed448 for use w/ EdDSA only
    Ed448 = 7,
    /// SECG secp256k1 curve
    Secp256k1 = 8,
    /// BrainPoolP256r1
    BrainpoolP256r1 = 256,
    /// BrainPoolP320r1
    BrainpoolP320r1 = 257,
    /// BrainPoolP384r1
    BrainpoolP384r1 = 258,
    /// BrainPoolP512r1
    BrainpoolP512r1 = 259,
}

impl From<CoseEllipticCurve> for i64 {
    fn from(value: CoseEllipticCurve) -> Self {
        match value {
            CoseEllipticCurve::PrivateUse(v) => v,
            CoseEllipticCurve::P256 => 1,
            CoseEllipticCurve::P384 => 2,
            CoseEllipticCurve::P521 => 3,
            CoseEllipticCurve::X25519 => 4,
            CoseEllipticCurve::X448 => 5,
            CoseEllipticCurve::Ed25519 => 6,
            CoseEllipticCurve::Ed448 => 7,
            CoseEllipticCurve::Secp256k1 => 8,
            CoseEllipticCurve::BrainpoolP256r1 => 256,
            CoseEllipticCurve::BrainpoolP320r1 => 257,
            CoseEllipticCurve::BrainpoolP384r1 => 258,
            CoseEllipticCurve::BrainpoolP512r1 => 259,
        }
    }
}

impl TryFrom<i64> for CoseEllipticCurve {
    type Error = CoreError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CoseEllipticCurve::P256),
            2 => Ok(CoseEllipticCurve::P384),
            3 => Ok(CoseEllipticCurve::P521),
            4 => Ok(CoseEllipticCurve::X25519),
            5 => Ok(CoseEllipticCurve::X448),
            6 => Ok(CoseEllipticCurve::Ed25519),
            7 => Ok(CoseEllipticCurve::Ed448),
            8 => Ok(CoseEllipticCurve::Secp256k1),
            256 => Ok(CoseEllipticCurve::BrainpoolP256r1),
            257 => Ok(CoseEllipticCurve::BrainpoolP320r1),
            258 => Ok(CoseEllipticCurve::BrainpoolP384r1),
            259 => Ok(CoseEllipticCurve::BrainpoolP512r1),
            v => {
                if v < COSE_REGISTRY_PRIVATE_BOUNDARY {
                    Ok(CoseEllipticCurve::PrivateUse(v))
                } else {
                    Err(CoreError::InvalidValue(format!(
                        "expected a valid COSE elliptic curve identifier, found {}",
                        value
                    )))
                }
            }
        }
    }
}

impl TryFrom<&str> for CoseEllipticCurve {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "P-256" => Ok(CoseEllipticCurve::P256),
            "P-384" => Ok(CoseEllipticCurve::P384),
            "P-521" => Ok(CoseEllipticCurve::P521),
            "X25519" => Ok(CoseEllipticCurve::X25519),
            "X448" => Ok(CoseEllipticCurve::X448),
            "Ed25519" => Ok(CoseEllipticCurve::Ed25519),
            "Ed448" => Ok(CoseEllipticCurve::Ed448),
            "secp256k1" => Ok(CoseEllipticCurve::Secp256k1),
            "brainpoolP256r1" => Ok(CoseEllipticCurve::BrainpoolP256r1),
            "brainpoolP320r1" => Ok(CoseEllipticCurve::BrainpoolP320r1),
            "brainpoolP384r1" => Ok(CoseEllipticCurve::BrainpoolP384r1),
            "brainpoolP512r1" => Ok(CoseEllipticCurve::BrainpoolP512r1),
            s => {
                if s.starts_with("PrivateUse(") {
                    let v: i64 = s[11..s.len() - 1].parse().map_err(|_| {
                        CoreError::InvalidValue(format!(
                            "expected a valid COSE elliptic curve name, found \"{}\"",
                            value
                        ))
                    })?;

                    if v < COSE_REGISTRY_PRIVATE_BOUNDARY {
                        Ok(CoseEllipticCurve::PrivateUse(v))
                    } else {
                        Err(CoreError::InvalidValue(format!(
                            "invalid COSE elliptic curve Private Use value {} (must be < {})",
                            v, COSE_REGISTRY_PRIVATE_BOUNDARY,
                        )))
                    }
                } else {
                    Err(CoreError::InvalidValue(format!(
                        "expected a valid COSE elliptic curve name, found \"{}\"",
                        value
                    )))
                }
            }
        }
    }
}

impl Display for CoseEllipticCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String;

        let name = match self {
            CoseEllipticCurve::PrivateUse(v) => {
                s = format!("PrivateUse({})", v);
                s.as_str()
            }
            CoseEllipticCurve::P256 => "P-256",
            CoseEllipticCurve::P384 => "P-384",
            CoseEllipticCurve::P521 => "P-521",
            CoseEllipticCurve::X25519 => "X25519",
            CoseEllipticCurve::X448 => "X448",
            CoseEllipticCurve::Ed25519 => "Ed25519",
            CoseEllipticCurve::Ed448 => "Ed448",
            CoseEllipticCurve::Secp256k1 => "secp256k1",
            CoseEllipticCurve::BrainpoolP256r1 => "brainpoolP256r1",
            CoseEllipticCurve::BrainpoolP320r1 => "brainpoolP320r1",
            CoseEllipticCurve::BrainpoolP384r1 => "brainpoolP384r1",
            CoseEllipticCurve::BrainpoolP512r1 => "brainpoolP512r1",
        };

        f.write_str(name)
    }
}

impl Serialize for CoseEllipticCurve {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            serializer.serialize_i64(self.to_owned().into())
        }
    }
}

impl<'de> Deserialize<'de> for CoseEllipticCurve {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            CoseEllipticCurve::try_from(String::deserialize(deserializer)?.as_str())
                .map_err(de::Error::custom)
        } else {
            CoseEllipticCurve::try_from(i64::deserialize(deserializer)?).map_err(de::Error::custom)
        }
    }
}

// This is a wrapper of serde::de::value::MapAccessDeserializer that propagates is_human_readable value
// that is given to it.
#[derive(Clone, Debug)]
pub(crate) struct MapAccessDeserializer<A> {
    md: de::value::MapAccessDeserializer<A>,
    is_hr: bool,
}

impl<A> MapAccessDeserializer<A> {
    pub(crate) fn new(map: A, is_hr: bool) -> Self {
        MapAccessDeserializer {
            md: de::value::MapAccessDeserializer::new(map),
            is_hr,
        }
    }
}

impl<'de, A> de::Deserializer<'de> for MapAccessDeserializer<A>
where
    A: de::MapAccess<'de>,
{
    type Error = A::Error;

    fn is_human_readable(&self) -> bool {
        self.is_hr
    }

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: de::Visitor<'de>,
    {
        self.md.deserialize_any(visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct identifier ignored_any enum
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(vec)]
mod tests {
    use super::*;
    use crate::test::SerdeTestCase;

    mod hash_entry {
        use super::{HashAlgorithm, HashEntry};
        #[test]
        fn test_hash_entry_serialize() {
            /*********************************************************************
             * Explanation of Expected Bytes:
             * 0x82: CBOR array with 2 elements
             * 0x01: Hash algorithm identifier Sha256
             * 0x45: CBOR byte string with 5 bytes
             * 0x01, 0x02, 0x03, 0x04, 0x05: 5 bytes of hash value
             *********************************************************************/
            let expected = [0x82, 0x01, 0x45, 0x01, 0x02, 0x03, 0x04, 0x05];

            let hash_entry: HashEntry = HashEntry {
                alg: HashAlgorithm::Sha256,
                val: vec![1, 2, 3, 4, 5].into(),
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

        #[test]
        fn test_bytes_json_serialize() {
            let bytes: super::Bytes = vec![1, 2, 3, 4, 5].into();

            let text = serde_json::to_string(&bytes).unwrap();

            assert_eq!(text, "\"AQIDBAU\"");
        }

        #[test]
        fn test_bytes_json_deserialize() {
            let text = "\"AQIDBAU\"";

            let expected: super::Bytes = vec![1, 2, 3, 4, 5].into();

            let actual: super::Bytes = serde_json::from_str(text).unwrap();

            assert_eq!(actual, expected);
        }
    }

    mod uuid {
        use super::super::*;

        // note: CBOR is tested as part of TaggedUuidType below.

        #[test]
        fn test_uuid_type_json_serialize() {
            let uuid_bytes: [u8; 16] = [
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00,
            ];

            let expected = "\"550e8400-e29b-41d4-a716-446655440000\"";

            let uuid = UuidType::from(FixedBytes::from(uuid_bytes));

            let actual = serde_json::to_string(&uuid).unwrap();

            assert_eq!(actual, expected);
        }

        #[test]
        fn test_uuid_type_json_deserialize() {
            let uuid_bytes: [u8; 16] = [
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00,
            ];

            let expected = UuidType::from(FixedBytes::from(uuid_bytes));

            let json = "\"550e8400-e29b-41d4-a716-446655440000\"";

            let actual: UuidType = serde_json::from_str(json).unwrap();

            assert_eq!(actual, expected);
        }
    }

    mod ueid {
        use super::super::*;

        #[test]
        fn test_ueid_type_from_bytes() {
            let ueid_bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

            let res = UeidType::try_from(ueid_bytes).err().unwrap();

            assert_eq!(
                res,
                CoreError::InvalidValue("UEID must be between 7 and 33 bytes long".to_string())
            );

            let ueid_bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

            let res = UeidType::try_from(ueid_bytes).err();

            assert_eq!(res, None);

            let ueid_bytes: &[u8] = &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                0x1D, 0x1E, 0x1F, 0x20, 0x21,
            ];

            let res = UeidType::try_from(ueid_bytes).err();

            assert_eq!(res, None);

            let ueid_bytes: &[u8] = &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22,
            ];

            let res = UeidType::try_from(ueid_bytes).err().unwrap();

            assert_eq!(
                res,
                CoreError::InvalidValue("UEID must be between 7 and 33 bytes long".to_string())
            );
        }

        #[test]
        fn test_ueid_type_from_str() {
            let ueid_str = "AAECAwQF";

            let res = UeidType::try_from(ueid_str).err().unwrap();

            assert_eq!(
                res,
                CoreError::InvalidValue("UEID must be between 7 and 33 bytes long".to_string())
            );

            let ueid_str = "AAECAwQFBg";

            let res = UeidType::try_from(ueid_str).err();

            assert_eq!(res, None);

            let ueid_str = "AAECAwQFBgcJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAh";

            let res = UeidType::try_from(ueid_str).err();

            assert_eq!(res, None);

            let ueid_str = "AAECAwQFBgcJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIg";

            let res = UeidType::try_from(ueid_str).err().unwrap();

            assert_eq!(
                res,
                CoreError::InvalidValue("UEID must be between 7 and 33 bytes long".to_string())
            );
        }

        #[test]
        fn test_ueid_type_json_serialize() {
            let ueid_bytes: &[u8] = &[
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00, 0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66,
                0x55, 0x44, 0x00, 0x00, 0x00,
            ];

            let ueid = UeidType::try_from(ueid_bytes).unwrap();

            let expected = "\"VQ6EAOKbQdSnFkRmVUQAAFUOhADim0HUpxZEZlVEAAAA\"";

            let actual = serde_json::to_string(&ueid).unwrap();

            assert_eq!(&actual, expected);
        }

        #[test]
        fn test_ueid_type_json_deserialize() {
            let ueid_bytes: &[u8] = &[
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00, 0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66,
                0x55, 0x44, 0x00, 0x00, 0x00,
            ];

            let expected = UeidType::try_from(ueid_bytes).unwrap();

            let text = "\"VQ6EAOKbQdSnFkRmVUQAAFUOhADim0HUpxZEZlVEAAAA\"";

            let actual: UeidType = serde_json::from_str(text).unwrap();

            assert_eq!(actual, expected);
        }
    }

    mod generated_tags {
        use super::*;
        #[test]
        fn test_deserialize_integer_time() {
            let value: Int = 1580000000.into();
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
            let value: Int = 23.into(); // Max for 1-byte encoding
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
            let value: Int = 255.into(); // Max for 2-byte encoding
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
            let expected: IntegerTime = Integer::from(1000i32).into();
            let bytes: [u8; 4] = [0xC1, 0x19, 0x03, 0xE8]; // 1000 = 0x03E8
            let actual: IntegerTime = ciborium::from_reader(bytes.as_slice()).unwrap();
            assert_eq!(expected, actual);
        }

        // 5 bytes total: Tag 1 (C1) + 4-byte integer (Major Type 0, 0x1A)
        #[test]
        fn test_deserialize_integer_time_4_bytes() {
            let value: Int = 1000.into(); // Fits in 2 bytes, but we force 4-byte encoding
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
            let value: Int = 1580000000.into();
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
            let expected = TaggedUuidType::from(UuidType::from(uuid_bytes));

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
            let expected = OidType::from(ObjectIdentifier::try_from(oid_bytes.as_slice()).unwrap());

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
            assert_eq!(
                actual.as_ref().as_ref(),
                oid_bytes,
                "Inner OID bytes mismatch"
            );
        }

        #[test]
        fn test_objectidentifier_serde_json() {
            let oid_bytes = [0x55, 0x04, 0x03]; // OID 2.5.4.3 (Common Name)
            let oid_json = "\"2.5.4.3\"";
            let expected = ObjectIdentifier::try_from(oid_bytes.as_slice()).unwrap();

            let actual: ObjectIdentifier = serde_json::from_str(oid_json).unwrap();
            assert_eq!(actual, expected);

            let text = serde_json::to_string(&actual).unwrap();
            assert_eq!(text, oid_json);
        }

        #[test]
        fn test_tagged_ueid_type_serialize_deserialize() {
            let ueid_bytes: &[u8] = &[
                0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44,
                0x00, 0x00, 0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66,
                0x55, 0x44, 0x00, 0x00, 0x00,
            ];
            // Test value
            let expected = TaggedUeidType::from(UeidType::from(Bytes::from(ueid_bytes)));

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
            let expected = SvnType::from(Integer::from(1u32));

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
            let expected = MinSvnType::from(Integer::from(0u32));

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
                alg: HashAlgorithm::Sha256,

                val: Bytes::from(thumbprint_bytes.to_vec()),
            };
            let expected = ThumbprintType::from(digest);

            let expected_bytes = [
                0xD9, 0x02, 0x2D, // Tag 557
                0x82, // Array of 2 elements
                0x01, // Algorithm (1)
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
            let key = CoseKeyBuilder::new()
                .kty(CoseKty::Ec2)
                .kid(Bytes::from(vec![0x01, 0x02, 0x03]))
                .alg(CoseAlgorithm::ES256)
                .key_ops(vec![CoseKeyOperation::Sign])
                .base_iv(Bytes::from(vec![0x04, 0x05, 0x06]))
                .crv(CoseEllipticCurve::P256)
                .x(Bytes::from(vec![0x07, 0x08, 0x09]))
                .y(Bytes::from(vec![0x0a, 0x0b, 0x0c]))
                .d(Bytes::from(vec![0x0d, 0x0e, 0x0f]))
                .build()
                .unwrap();

            let expected = CoseKeyType::from(CoseKeySetOrKey::Key(key));

            let expected_bytes = vec![
                0xd9, 0x02, 0x2e, // tag(558)
                  0xbf,  // map(indef)
                    0x01, // key: 1 [kty]
                    0x02, // value: 2 [CoseKty::Ec2]
                    0x02, // key: 2 [kid]
                    0x43, // value: bstr(3)
                      0x01, 0x02, 0x03,
                    0x03, // key: 3 [alg]
                    0x26, // value: -7 [CoseAlgorithm::ES256]
                    0x04, // key: 4 [key_ops]
                    0x81, // value: array(1)
                      0x01, // 1 [CoseKeyOperation::Sign]
                    0x05, // key: 5 [base_iv]
                    0x43, // value: bstr(3)
                      0x04, 0x05, 0x06,
                    0x20, // key: -1 [crv]
                    0x01, // value: 1 [CoseEllipticCurve::P256]
                    0x21, // key: -2 [x]
                    0x43, // value: bstr(3)
                      0x07, 0x08, 0x09,
                    0x22, // key: -3 [y]
                    0x43, // value: bstr(3)
                      0x0a, 0x0b, 0x0c,
                    0x23, // key: -4 [d]
                    0x43, // value: bstr(3)
                      0x0d, 0x0e, 0x0f,
                  0xff // break
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
                alg: HashAlgorithm::Sha384,
                val: Bytes::from(thumbprint_bytes.to_vec()),
            };
            let expected = CertThumbprintType::from(digest);

            let expected_bytes = [
                0xD9, 0x02, 0x2F, // Tag 559
                0x82, // Array of 2 elements
                0x07, // Algorithm (7 for Sha384)
                0x48, // Bstr of length 8
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, // Thumbprint bytes
            ];

            let mut buffer = vec![];
            ciborium::into_writer(&expected, &mut buffer).unwrap();
            assert_eq!(buffer, expected_bytes, "Serialization mismatch");

            let actual: CertThumbprintType =
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
                alg: HashAlgorithm::Sha512,
                val: Bytes::from(thumbprint_bytes.to_vec()),
            };
            let expected = CertPathThumbprintType::from(digest);

            let expected_bytes = [
                0xD9, 0x02, 0x31, // Tag 561
                0x82, // Array of 2 elements
                0x08, // Algorithm (8 for Sha512)
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
            let bytes = Bytes::from(cert_bytes.to_vec());
            let expected = PkixAsn1DerCertType::from(bytes);

            let expected_bytes = [
                0xD9, 0x02, 0x32, // Tag 562
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

    mod cose {
        use super::*;

        #[test]
        fn test_cose_algorithm_serde() {
            let expected = vec![
                0x30, // -17
            ];

            let mut buffer = Vec::new();
            ciborium::into_writer(&CoseAlgorithm::Sha512_256, &mut buffer).unwrap();

            assert_eq!(buffer, expected);

            let alg: CoseAlgorithm = ciborium::from_reader(expected.as_slice()).unwrap();

            assert_eq!(alg, CoseAlgorithm::Sha512_256);

            let expected = "\"SHA-512/256\"";

            let json = serde_json::to_string(&CoseAlgorithm::Sha512_256).unwrap();

            assert_eq!(json.as_str(), expected);

            let alg: CoseAlgorithm = serde_json::from_str(expected).unwrap();

            assert_eq!(alg, CoseAlgorithm::Sha512_256);
        }

        #[test]
        fn test_cose_algorithm_private_use_serde() {
            let alg = CoseAlgorithm::PrivateUse(-65537);

            let expected = vec![
                0x3a, 0x00, 0x01, 0x00, 0x00, // -65537
            ];

            let mut buffer = Vec::new();
            ciborium::into_writer(&alg, &mut buffer).unwrap();

            assert_eq!(buffer, expected);

            let alg_de: CoseAlgorithm = ciborium::from_reader(expected.as_slice()).unwrap();

            assert_eq!(alg_de, alg);

            let expected = "\"PrivateUse(-65537)\"";

            let json = serde_json::to_string(&alg).unwrap();

            assert_eq!(json.as_str(), expected);

            let alg_de: CoseAlgorithm = serde_json::from_str(expected).unwrap();

            assert_eq!(alg_de, alg);

            let err: serde_json::Error = serde_json::from_str::<CoseAlgorithm>("\"foo\"")
                .err()
                .unwrap();

            assert_eq!(
                err.to_string().as_str(),
                "invalid value: expected a valid COSE algorithm name, found \"foo\"",
            );

            let err: serde_json::Error =
                serde_json::from_str::<CoseAlgorithm>("\"PrivateUse(42)\"")
                    .err()
                    .unwrap();

            assert_eq!(
                err.to_string().as_str(),
                "invalid value: invalid COSE algorithm Private Use value 42 (must be < -65536)",
            );
        }

        #[test]
        fn test_cose_kty_serde() {
            let expected = vec![
                0x01, // 1
            ];

            let mut buffer = Vec::new();
            ciborium::into_writer(&CoseKty::Okp, &mut buffer).unwrap();

            assert_eq!(buffer, expected);

            let kty: CoseKty = ciborium::from_reader(expected.as_slice()).unwrap();

            assert_eq!(kty, CoseKty::Okp);

            let expected = "\"OKP\"";

            let json = serde_json::to_string(&CoseKty::Okp).unwrap();

            assert_eq!(json.as_str(), expected);

            let kty: CoseKty = serde_json::from_str(expected).unwrap();

            assert_eq!(kty, CoseKty::Okp);
        }

        #[test]
        fn test_cose_key_operation_serde() {
            let expected = vec![
                0x01, // 1
            ];

            let mut buffer = Vec::new();
            ciborium::into_writer(&CoseKeyOperation::Sign, &mut buffer).unwrap();

            assert_eq!(buffer, expected);

            let op: CoseKeyOperation = ciborium::from_reader(expected.as_slice()).unwrap();

            assert_eq!(op, CoseKeyOperation::Sign);

            let expected = "\"sign\"";

            let json = serde_json::to_string(&CoseKeyOperation::Sign).unwrap();

            assert_eq!(json.as_str(), expected);

            let op: CoseKeyOperation = serde_json::from_str(expected).unwrap();

            assert_eq!(op, CoseKeyOperation::Sign);
        }

        #[test]
        fn test_cose_elliptic_curve_private_use_serde() {
            let curve = CoseEllipticCurve::PrivateUse(-65537);

            let expected = vec![
                0x3a, 0x00, 0x01, 0x00, 0x00, // -65537
            ];

            let mut buffer = Vec::new();
            ciborium::into_writer(&curve, &mut buffer).unwrap();

            assert_eq!(buffer, expected);

            let curve_de: CoseEllipticCurve = ciborium::from_reader(expected.as_slice()).unwrap();

            assert_eq!(curve_de, curve);

            let expected = "\"PrivateUse(-65537)\"";

            let json = serde_json::to_string(&curve).unwrap();

            assert_eq!(json.as_str(), expected);

            let cruve_de: CoseEllipticCurve = serde_json::from_str(expected).unwrap();

            assert_eq!(cruve_de, curve);

            let err: serde_json::Error = serde_json::from_str::<CoseEllipticCurve>("\"foo\"")
                .err()
                .unwrap();

            assert_eq!(
                err.to_string().as_str(),
                "invalid value: expected a valid COSE elliptic curve name, found \"foo\"",
            );

            let err: serde_json::Error =
                serde_json::from_str::<CoseEllipticCurve>("\"PrivateUse(42)\"")
                    .err()
                    .unwrap();

            assert_eq!(
                err.to_string().as_str(),
                "invalid value: invalid COSE elliptic curve Private Use value 42 (must be < -65536)",
            );
        }
    }

    #[test]
    fn test_version_scheme_serde() {
        let vs = VersionScheme::Multipartnumeric;

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&vs, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0x01, // 1 [multipartnumeric]
        ];

        assert_eq!(actual, expected);

        let vs_de: VersionScheme = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(vs_de, vs);

        let actual = serde_json::to_string(&vs).unwrap();

        let expected = "\"multipartnumeric\"";

        assert_eq!(actual, expected);

        let vs_de: VersionScheme = serde_json::from_str(expected).unwrap();

        assert_eq!(vs_de, vs);

        let vs = VersionScheme::PrivateUse(Label::Text("foo".into()));

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&vs, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0x63, // tstr(3),
              0x66, 0x6f, 0x6f, // "foo"
        ];

        assert_eq!(actual, expected);

        let vs_de: VersionScheme = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(vs_de, vs);

        let actual = serde_json::to_string(&vs).unwrap();

        let expected = "\"foo\"";

        assert_eq!(actual, expected);

        let vs_de: VersionScheme = serde_json::from_str(expected).unwrap();

        assert_eq!(vs_de, vs);

        let vs = VersionScheme::PrivateUse(Label::Int(Integer(-1)));

        let mut actual: Vec<u8> = vec![];
        ciborium::into_writer(&vs, &mut actual).unwrap();

        let expected: Vec<u8> = vec![
            0x20, // -1
        ];

        assert_eq!(actual, expected);

        let vs_de: VersionScheme = ciborium::from_reader(expected.as_slice()).unwrap();

        assert_eq!(vs_de, vs);

        let actual = serde_json::to_string(&vs).unwrap();

        let expected = "\"-1\"";

        assert_eq!(actual, expected);

        let vs_de: VersionScheme = serde_json::from_str(expected).unwrap();

        assert_eq!(vs_de, vs);

        let vs_de: VersionScheme = serde_json::from_str("16384").unwrap();

        assert_eq!(vs_de, VersionScheme::Semver);

        let err = serde_json::from_str::<VersionScheme>("42")
            .err()
            .unwrap()
            .to_string();

        assert_eq!(
            err,
            "invalid value: invalid version scheme 42 at line 1 column 2"
        );
    }

    #[test]
    fn test_extension_value_serde() {
        let test_cases = vec![
            SerdeTestCase {
                value: ExtensionValue::Null,
                expected_json: "null",
                expected_cbor: vec![ 0xf6 ],
            },
            SerdeTestCase {
                value: ExtensionValue::Uint(Integer(1)),
                expected_json: "1",
                expected_cbor: vec![ 0x01 ],
            },
            SerdeTestCase {
                value: ExtensionValue::Int(Integer(-1)),
                expected_json: "-1",
                expected_cbor: vec![ 0x20 ],
            },
            SerdeTestCase {
                value: ExtensionValue::Bool(true),
                expected_json: "true",
                expected_cbor: vec![ 0xf5 ],
            },
            SerdeTestCase {
                value: ExtensionValue::Bytes(vec![0x1, 0x02, 0x03].into()),
                expected_json: "\"[base64]:AQID\"",
                expected_cbor: vec![
                    0x43, // bstr(3)
                      0x01, 0x02, 0x03,
                ],
            },
            SerdeTestCase {
                value: ExtensionValue::Text("test value".into()),
                expected_json: "\"test value\"",
                expected_cbor: vec![
                    0x6a, // tstr(10)
                    0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x61, 0x6c, // "test val"
                    0x75, 0x65,                                     // "ue"
                ],
            },
            SerdeTestCase {
                value: ExtensionValue::Array(vec![
                    ExtensionValue::Uint(1.into()),
                    ExtensionValue::Uint(2.into()),
                    ExtensionValue::Uint(3.into()),
                ].into()),
                expected_json: "[1,2,3]",
                expected_cbor: vec![
                    0x83, // array(3)
                      0x01,
                      0x02,
                      0x03,
                ],
            },
            SerdeTestCase {
                value: ExtensionValue::Map(BTreeMap::from([
                   (Label::Text("foo".into()), ExtensionValue::Uint(1.into())),
                   (Label::Int(1.into()), ExtensionValue::Uint(2.into())),
                ])),
                expected_json: r#"{"1":2,"foo":1}"#,
                expected_cbor: vec![
                    0xa2, // map(2)
                      0x63, // key: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x01, // value: 1
                      0x01, // key: 1
                      0x02, // value: 2
                ],
            },
            SerdeTestCase {
                value: ExtensionValue::Tag(1337, Box::new(ExtensionValue::Uint(1.into()))),
                expected_json: r#"{"tag":1337,"value":1}"#,
                expected_cbor: vec![
                    0xd9, 0x05, 0x39, // tag(1337)
                      0x01,
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_one_or_more_serde() {
        let uri_test_cases: Vec<SerdeTestCase<OneOrMore<Uri>>> = vec![
            SerdeTestCase {
                value: OneOrMore::One("foo".into()),
                expected_json: r#"{"type":"uri","value":"foo"}"#,
                expected_cbor: vec![
                    0xd8, 0x20, // tag(32) [uri]
                      0x63, // tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                ],
            },
            SerdeTestCase {
                value: OneOrMore::More(vec!["foo".into(), "bar".into()]),
                expected_json: r#"[{"type":"uri","value":"foo"},{"type":"uri","value":"bar"}]"#,
                expected_cbor: vec![
                    0x82,
                      0xd8, 0x20, // tag(32) [uri]
                        0x63, // tstr(3)
                          0x66, 0x6f, 0x6f, // "foo"
                      0xd8, 0x20, // tag(32) [uri]
                        0x63, // tstr(3)
                          0x62, 0x61, 0x72, // "bar"
                ],
            },
        ];

        let int_test_cases: Vec<SerdeTestCase<OneOrMore<Int>>> = vec![
            SerdeTestCase {
                value: OneOrMore::One(1.into()),
                expected_json: "1",
                expected_cbor: vec![0x01],
            },
            SerdeTestCase {
                value: OneOrMore::More(vec![1.into(), 2.into()]),
                expected_json: "[1,2]",
                expected_cbor: vec![
                    0x82, // array(2)
                      0x01, // [0]1
                      0x02, // [1]2
                ],
            },
        ];

        for tc in uri_test_cases.into_iter() {
            tc.run();
        }

        for tc in int_test_cases.into_iter() {
            tc.run();
        }
    }

    #[test]
    fn test_global_attribute_value() {
        let test_cases: Vec<SerdeTestCase<AttributeValue>> = vec! [
            SerdeTestCase {
                value: 1i64.into(),
                expected_json: "1",
                expected_cbor: vec![0x01],
            },
            SerdeTestCase {
                value: "foo".into(),
                expected_json: "\"foo\"",
                expected_cbor: vec![
                    0x63, // tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                ],
            },
            SerdeTestCase {
                value: [1, 2, 3].as_slice().into(),
                expected_json: "[1,2,3]",
                expected_cbor: vec![
                    0x83, // array(3)
                      0x01,
                      0x02,
                      0x03,
                ],
            },
            SerdeTestCase {
                value: ["foo", "bar", "qux"].as_slice().into(),
                expected_json: r#"["foo","bar","qux"]"#,
                expected_cbor: vec![
                    0x83, // array(3)
                      0x63, // [0]tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x63, // [1]tstr(3)
                        0x62, 0x61, 0x72, // "bar"
                      0x63, // [2]tstr(3)
                        0x71, 0x75, 0x78, // "qux"
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }

        let value: AttributeValue = [1].as_slice().into();

        assert!(value.is_one());

        let mut actual_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&value, &mut actual_cbor).unwrap();

        let expected_cbor: Vec<u8> = vec![0x01];

        assert_eq!(actual_cbor, expected_cbor);
    }

    #[test]
    fn test_text_or_bytes_sized_serde() {
        let test_cases: Vec<SerdeTestCase<TextOrBytesSized<3>>> = vec! [
            SerdeTestCase {
                value: "foo".into(),
                expected_json: r#""foo""#,
                expected_cbor: vec![
                    0x63, // tstr(3)
                      0x66, 0x6f, 0x6f, // "foo"
                ],
            },
            SerdeTestCase {
                value: vec![0x01, 0x02, 0x03].try_into().unwrap(),
                expected_json: r#""AQID""#,
                expected_cbor: vec![
                    0x43, // bstr(3)
                      0x01, 0x02, 0x03,
                ],
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }
}
