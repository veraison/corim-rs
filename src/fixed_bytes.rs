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
use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut, Index, IndexMut},
};

use derive_more::From;
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

#[derive(From, PartialEq, Eq, PartialOrd, Ord, Clone)]
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
/// // Create a 200-byte array
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

impl<const N: usize> Index<usize> for FixedBytes<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> IndexMut<usize> for FixedBytes<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<const N: usize> AsMut<[u8]> for FixedBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Deref for FixedBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const N: usize> AsMut<T> for FixedBytes<N>
where
    <FixedBytes<N> as Deref>::Target: AsMut<T>,
{
    fn as_mut(&mut self) -> &mut T {
        self.deref_mut().as_mut()
    }
}

impl<const N: usize> DerefMut for FixedBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_bytes_creation() {
        let bytes: FixedBytes<4> = FixedBytes([1, 2, 3, 4]);
        assert_eq!(&*bytes, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_fixed_bytes_as_ref() {
        let bytes: FixedBytes<3> = FixedBytes([5, 6, 7]);
        let array: &[u8; 3] = &bytes;
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

    #[test]
    fn test_fixed_bytes_ciborium_serialize() {
        let expected = [0x45, 0x01, 0x02, 0x03, 0x04, 0x05];
        let bytes: FixedBytes<5> = FixedBytes([1, 2, 3, 4, 5]);
        let mut serialized_bytes = vec![];
        ciborium::into_writer(&bytes, &mut serialized_bytes).unwrap();
        assert_eq!(&serialized_bytes, &expected);
    }

    #[test]
    fn test_fixed_bytes_ciborium_deserialize() {
        let expected = FixedBytes([1, 2, 3, 4, 5]);
        let serialized_bytes: [u8; 6] = [0x45, 0x01, 0x02, 0x03, 0x04, 0x05];
        let deserialized_bytes: FixedBytes<5> =
            ciborium::from_reader(serialized_bytes.as_slice()).unwrap();
        assert_eq!(deserialized_bytes, expected);
    }
}
