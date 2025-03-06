// SPDX-License-Identifier: MIT

//! Fixed-length byte array types with serialization support
//!
//! This module provides a wrapper type for fixed-length byte arrays that implements
//! serialization and deserialization via serde. It's particularly useful when working
//! with protocols or formats that require exact-sized byte sequences.
//!
//! # Examples
//!
//! ```rust
//! use corim_rs::fixed_bytes::FixedBytes;
//!
//! // Create a 32-byte fixed array
//! let bytes: FixedBytes<32> = FixedBytes([0u8; 32]);
//!
//! // Access underlying array
//! let array: &[u8; 32] = bytes.as_ref();
//! ```
//!
//! # Serialization
//!
//! The type implements serde's `Serialize` and `Deserialize` traits, ensuring that:
//!
//! - Serialization always outputs the exact bytes
//! - Deserialization validates the input length matches the expected size
//! - Both borrowed and owned byte sequences are supported
//!
//! # Features
//!
//! - Compile-time size checking via const generics
//! - Implements common traits like `Deref`, `AsRef`, etc.
//! - Efficient zero-copy deserialization when possible
//! - Clear error messages for size mismatches
use std::marker::PhantomData;

use derive_more::{AsMut, AsRef, Deref, DerefMut, From};
use serde::{
    de::{Error, Visitor},
    Deserialize, Serialize, Serializer,
};

/// Visitor implementation for deserializing fixed-size byte arrays
struct FixedBytesVisitor<'de, const N: usize>(PhantomData<&'de [u8; N]>);

impl<'de, const N: usize> Visitor<'de> for FixedBytesVisitor<'de, N> {
    type Value = FixedBytes<N>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a byte array of length {}", N)
    }

    fn visit_borrowed_bytes<E: Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(v)
    }

    fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        self.visit_bytes(&v)
    }

    fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        if value.len() != N {
            return Err(E::custom(format!(
                "expected a byte array of length {}, but got {}",
                N,
                value.len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(value);
        Ok(FixedBytes(arr))
    }
}

#[derive(From, AsMut, AsRef, Deref, DerefMut)]
/// A fixed-length byte array wrapper with serialization support
///
/// This type wraps a byte array of size `N` and provides serialization/deserialization
/// capabilities while ensuring the size remains constant.
///
/// # Type Parameters
///
/// * `N` - The fixed size of the byte array
///
/// # Examples
///
/// ```rust
/// use corim_rs::fixed_bytes::FixedBytes;
///
/// // Create a 16-byte array
/// let bytes = FixedBytes([0u8; 200]);
///
/// // Access as slice
/// let slice: &[u8] = &bytes[..];
/// ```
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(FixedBytesVisitor(PhantomData))
    }
}

impl<const N: usize> std::fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FixedBytes<{}>{:02x?}", N, &self.0[..])
    }
}

impl<const N: usize> Default for FixedBytes<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_bytes_creation() {
        let bytes: FixedBytes<4> = FixedBytes([1, 2, 3, 4]);
        assert_eq!(&bytes[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_fixed_bytes_as_ref() {
        let bytes: FixedBytes<3> = FixedBytes([5, 6, 7]);
        let array: &[u8; 3] = bytes.as_ref();
        assert_eq!(array, &[5, 6, 7]);
    }

    #[test]
    fn test_fixed_bytes_debug_format() {
        let bytes: FixedBytes<3> = FixedBytes([10, 11, 12]);
        assert_eq!(format!("{:?}", bytes), "FixedBytes<3>[0a, 0b, 0c]");
    }

    #[test]
    fn test_fixed_bytes_deref() {
        let bytes: FixedBytes<2> = FixedBytes([1, 2]);
        assert_eq!(*bytes, [1, 2]);
    }

    #[test]
    fn test_fixed_bytes_deref_mut() {
        let mut bytes: FixedBytes<2> = FixedBytes([1, 2]);
        bytes[0] = 3;
        assert_eq!(*bytes, [3, 2]);
    }
}
