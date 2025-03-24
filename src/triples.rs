// SPDX-License-Identifier: MIT

//! Module for handling triple records used in CoMID tags.
//!
//! Triple records are used to express relationships between environments, measurements,
//! and various security properties. This module implements the different types of triples
//! defined in the CoRIM specification.
//!
//! # Triple Record Types
//!
//! - Reference triples ([`ReferenceTripleRecord`]): Link environments to measurements
//! - Identity triples ([`IdentityTripleRecord`]): Associate keys with environments
//! - Endorsement triples ([`EndorsedTripleRecord`]): Express verification requirements
//! - Attestation key triples ([`AttestKeyTripleRecord`]): Define keys for attestation
//! - Domain dependency triples ([`DomainDependencyTripleRecord`]): Express domain relationships
//! - Domain membership triples ([`DomainMembershipTripleRecord`]): Define domain membership
//! - CoSWID triples ([`CoswidTripleRecord`]): Link to software identification tags
//! - Conditional endorsement triples ([`ConditionalEndorsementTripleRecord`]): Complex verification
//!
//! # Key Types
//!
//! The module supports various cryptographic key and certificate formats through [`CryptoKeyTypeChoice`]:
//! - PKIX certificates (base64 encoded)
//! - PKIX certificate paths
//! - COSE keys
//! - Cryptographic thumbprints
//! - ASN.1 DER encoded certificates
//!
//! # Networking Support
//!
//! Network identification is handled through:
//! - [`MacAddrTypeChoice`]: Supports both EUI-48 and EUI-64 MAC addresses
//! - [`IpAddrTypeChoice`]: Supports both IPv4 and IPv6 addresses
//!
//! # Measurement Values
//!
//! The [`MeasurementValuesMap`] structure contains comprehensive measurement data including:
//! - Version information
//! - Security version numbers (SVN)
//! - Cryptographic digests
//! - Security state flags
//! - Network addressing
//! - Serial numbers
//! - UUIDs and UEIDs
//! - Cryptographic keys
//! - Integrity register values
//!
//! # Status Flags
//!
//! The [`FlagsMap`] structure provides detailed security and configuration state including:
//! - Configuration state
//! - Security state
//! - Recovery mode
//! - Debug status
//! - Replay protection
//! - Integrity protection
//! - Runtime measurement status
//! - Immutability
//! - TCB inclusion
//! - Confidentiality protection
//!
//! # Example Usage
//!
//! ```rust
//! use corim_rs::triples::{ReferenceTripleRecord, EnvironmentMap, MeasurementMap};
//!
//! // Create a reference triple
//! let triple = ReferenceTripleRecord {
//!     ref_env: EnvironmentMap {
//!         class: None,
//!         instance: None,
//!         group: None,
//!     },
//!     ref_claims: vec![
//!         MeasurementMap {
//!             mkey: None,
//!             mval: Default::default(),
//!             authorized_by: None,
//!         }
//!     ].into(),
//! };
//! ```
//!
//! # Conditional Endorsements
//!
//! The module supports complex conditional endorsement scenarios through:
//! - [`ConditionalEndorsementTripleRecord`]: For single condition endorsements
//! - [`ConditionalEndorsementSeriesTripleRecord`]: For series-based conditional changes
//! - [`StatefulEnvironmentRecord`]: For tracking environment state
//! - [`ConditionalSeriesRecord`]: For defining measurement changes

use std::{
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};

use crate::{
    core::PkixBase64CertPathType, Bytes, CertPathThumbprintType, CertThumprintType,
    ConciseSwidTagId, CoseKeyType, Digest, ExtensionMap, MinSvnType, OidType, OneOrMore,
    PkixAsn1DerCertType, PkixBase64CertType, PkixBase64KeyType, RawValueType, Result, SvnType,
    Text, ThumbprintType, TriplesError, Tstr, UeidType, Uint, Ulabel, UuidType, VersionScheme,
};
use derive_more::{Constructor, From, TryFrom};
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A reference triple record containing environment and measurement claims
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ReferenceTripleRecord<'a> {
    /// The environment being referenced
    pub ref_env: EnvironmentMap<'a>,
    /// One or more measurement claims about the environment
    pub ref_claims: Vec<MeasurementMap<'a>>,
}

impl<'a> Serialize for ReferenceTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.ref_env)?;
        seq.serialize_element(&self.ref_claims)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for ReferenceTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReferenceTripleRecordVisitor<'a>(std::marker::PhantomData<&'a ()>);

        impl<'de, 'a> serde::de::Visitor<'de> for ReferenceTripleRecordVisitor<'a> {
            type Value = ReferenceTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a reference triple record")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let ref_env = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let ref_claims = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ReferenceTripleRecord {
                    ref_env,
                    ref_claims,
                })
            }
        }

        deserializer.deserialize_seq(ReferenceTripleRecordVisitor(std::marker::PhantomData))
    }
}
/// Map describing an environment's characteristics
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct EnvironmentMap<'a> {
    /// Optional classification information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "0")]
    pub class: Option<ClassMap<'a>>,
    /// Optional instance identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "1")]
    pub instance: Option<InstanceIdTypeChoice<'a>>,
    /// Optional group identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "2")]
    pub group: Option<GroupIdTypeChoice>,
}

pub struct EnvironmentMapBuilder<'a> {
    /// Optional classification information
    pub class: Option<ClassMap<'a>>,
    /// Optional instance identifier
    pub instance: Option<InstanceIdTypeChoice<'a>>,
    /// Optional group identifier
    pub group: Option<GroupIdTypeChoice>,
}

impl<'a> EnvironmentMapBuilder<'a> {
    pub fn class(mut self, values: ClassMap<'a>) -> Self {
        self.class = Some(values);
        self
    }

    pub fn instance(mut self, instance: InstanceIdTypeChoice<'a>) -> Self {
        self.instance = Some(instance);
        self
    }

    pub fn group(mut self, group: GroupIdTypeChoice) -> Self {
        self.group = Some(group);
        self
    }

    pub fn build(self) -> Result<EnvironmentMap<'a>> {
        if self.class.is_none() && self.instance.is_none() && self.group.is_none() {
            return Err(TriplesError::EmptyEnvironmentMap)?;
        }
        Ok(EnvironmentMap {
            class: self.class,
            instance: self.instance,
            group: self.group,
        })
    }
}
/// Classification information for an environment. It is **HIGHLY** recommend to use ClassMapBuilder to ensure the CDDL enforcement of
/// at least one field being present.
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ClassMap<'a> {
    /// Optional class identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "0")]
    pub class_id: Option<ClassIdTypeChoice>,
    /// Optional vendor name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "1")]
    pub vendor: Option<Tstr<'a>>,
    /// Optional model identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "2")]
    pub model: Option<Tstr<'a>>,
    /// Optional layer number
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "3")]
    pub layer: Option<Uint>,
    /// Optional index number
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "4")]
    pub index: Option<Uint>,
}

#[derive(Default)]
pub struct ClassMapBuilder<'a> {
    /// Optional class identifier
    pub class_id: Option<ClassIdTypeChoice>,
    /// Optional vendor name
    pub vendor: Option<Tstr<'a>>,
    /// Optional model identifier
    pub model: Option<Tstr<'a>>,
    /// Optional layer number
    pub layer: Option<Uint>,
    /// Optional index number
    pub index: Option<Uint>,
}

impl<'a> ClassMapBuilder<'a> {
    pub fn class_id(mut self, value: ClassIdTypeChoice) -> Self {
        self.class_id = Some(value);
        self
    }

    pub fn vendor(mut self, value: Tstr<'a>) -> Self {
        self.vendor = Some(value);
        self
    }

    pub fn model(mut self, value: Tstr<'a>) -> Self {
        self.model = Some(value);
        self
    }

    pub fn layer(mut self, value: Uint) -> Self {
        self.layer = Some(value);
        self
    }

    pub fn index(mut self, value: Uint) -> Self {
        self.index = Some(value);
        self
    }

    pub fn build(self) -> Result<ClassMap<'a>> {
        if self.class_id.is_none()
            && self.vendor.is_none()
            && self.model.is_none()
            && self.layer.is_none()
            && self.index.is_none()
        {
            return Err(TriplesError::EmptyClassMap)?;
        }
        Ok(ClassMap {
            class_id: self.class_id,
            vendor: self.vendor,
            model: self.model,
            layer: self.layer,
            index: self.index,
        })
    }
}

/// Possible types for class identifiers
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum ClassIdTypeChoice {
    /// Object Identifier (OID)
    Oid(OidType),
    /// UUID identifier
    Uuid(UuidType),
    /// Raw bytes
    Bytes(Bytes),
}

impl ClassIdTypeChoice {
    /// Returns a byte slice reference to the underlying data regardless of variant type
    ///
    /// This method provides uniform access to the internal bytes of a ClassIdTypeChoice,
    /// normalizing access across the different variant types.
    ///
    /// # Returns
    ///
    /// A slice of bytes (`&[u8]`) representing the raw data of the identifier
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::triples::ClassIdTypeChoice;
    /// use corim_rs::Bytes;
    ///
    /// let id = ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]));
    /// let bytes = id.as_bytes();
    /// assert_eq!(bytes, &[1, 2, 3, 4]);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Oid(oid_type) => oid_type.as_ref(),
            Self::Uuid(uuid_type) => uuid_type.as_ref().as_ref(),
            Self::Bytes(bytes) => bytes.as_ref(),
        }
    }

    /// Returns the byte representation if this is an OID variant, or None otherwise
    ///
    /// This method is useful when you specifically need to work with OID data
    /// and want to verify the variant type before accessing.
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` containing the OID bytes if this is an OID variant
    /// - `None` if this is any other variant
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::triples::ClassIdTypeChoice;
    /// use corim_rs::{OidType, Bytes};
    ///
    /// // An OID variant
    /// let oid_id = ClassIdTypeChoice::Oid(OidType::from(vec![1, 2, 840, 113741, 1, 2]));
    /// assert!(oid_id.as_oid_bytes().is_some());
    ///
    /// // Not an OID variant
    /// let bytes_id = ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]));
    /// assert!(bytes_id.as_oid_bytes().is_none());
    /// ```
    pub fn as_oid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Oid(_) => Some(Self::as_bytes(self)),
            _ => None,
        }
    }

    /// Returns the byte representation if this is a UUID variant, or None otherwise
    ///
    /// This method is useful when you specifically need to work with UUID data
    /// and want to verify the variant type before accessing.
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` containing the UUID bytes if this is a UUID variant
    /// - `None` if this is any other variant
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::triples::ClassIdTypeChoice;
    /// use corim_rs::{UuidType, FixedBytes, Bytes};
    ///
    /// // A UUID variant
    /// let uuid_bytes = [0; 16];
    /// let uuid_id = ClassIdTypeChoice::Uuid(UuidType(FixedBytes::from(uuid_bytes)));
    /// assert!(uuid_id.as_uuid_bytes().is_some());
    ///
    /// // Not a UUID variant
    /// let bytes_id = ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]));
    /// assert!(bytes_id.as_uuid_bytes().is_none());
    /// ```
    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(_) => Some(Self::as_bytes(self)),
            _ => None,
        }
    }

    /// Returns the byte representation if this is a raw Bytes variant, or None otherwise
    ///
    /// This method is useful when you specifically need to work with raw byte data
    /// and want to verify the variant type before accessing.
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` containing the raw bytes if this is a Bytes variant
    /// - `None` if this is any other variant
    ///
    /// # Example
    ///
    /// ```ignore
    /// use corim_rs::triples::ClassIdTypeChoice;
    /// use corim_rs::{OidType, Bytes};
    ///
    /// // A Bytes variant
    /// let bytes_id = ClassIdTypeChoice::Bytes(Bytes::from(vec![1, 2, 3, 4]));
    /// assert!(bytes_id.as_raw_bytes().is_some());
    ///
    /// // Not a Bytes variant
    /// let oid_id = ClassIdTypeChoice::Oid(OidType::from(vec![1, 2, 840, 113741, 1, 2]));
    /// assert!(oid_id.as_raw_bytes().is_none());
    /// ```
    pub fn as_raw_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(_) => Some(Self::as_bytes(self)),
            _ => None,
        }
    }
}

/// Possible types for instance identifiers
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum InstanceIdTypeChoice<'a> {
    /// Unique Entity Identifier
    Ueid(UeidType),
    /// UUID identifier
    Uuid(UuidType),
    /// Cryptographic key identifier
    CryptoKey(CryptoKeyTypeChoice<'a>),
    /// Raw bytes
    Bytes(Bytes),
}

impl<'a> InstanceIdTypeChoice<'a> {
    pub fn as_ueid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ueid(ueid) => Some(ueid.as_ref()),
            _ => None,
        }
    }

    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(uuid) => Some(uuid.as_ref()),
            _ => None,
        }
    }

    pub fn as_crypto_key(&self) -> Option<CryptoKeyTypeChoice> {
        match self {
            Self::CryptoKey(key) => Some(key.clone()),
            _ => None,
        }
    }

    pub fn as_ref_crypto_key(&self) -> Option<&CryptoKeyTypeChoice> {
        match self {
            Self::CryptoKey(key) => Some(key),
            _ => None,
        }
    }

    pub fn as_raw_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes.as_ref()),
            _ => None,
        }
    }
}

impl<'a> From<&'a [u8]> for InstanceIdTypeChoice<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Bytes(value.to_vec().into())
    }
}

/// Types of cryptographic keys and certificates
///
/// This enum supports all key and certificate formats defined in the CoRIM specification:
///
/// - PKIX formats use base64 encoding for certificates and keys
/// - COSE keys follow the COSE_Key structure from RFC 8152
/// - Thumbprints provide cryptographic hashes of keys/certificates
/// - ASN.1 DER supports raw certificate encoding
///
/// # Variants
///
/// * `PkixBase64Key` - Base64-encoded PKIX key
/// * `PkixBase64Cert` - Base64-encoded PKIX certificate
/// * `PkixBase64CertPath` - Base64-encoded PKIX certificate path
/// * `CoseKey` - COSE key structure (RFC 8152)
/// * `Thumbprint` - Generic cryptographic thumbprint
/// * `CertThumbprint` - Certificate thumbprint
/// * `CertPathThumbprint` - Certificate path thumbprint  
/// * `PkixAsn1DerCert` - ASN.1 DER encoded PKIX certificate
/// * `Bytes` - Raw bytes
///
/// # Example
///
/// # Example
///
/// ```rust
/// use corim_rs::triples::CryptoKeyTypeChoice;
/// use corim_rs::core::{PkixBase64CertType, CoseKeyType, CoseKeySetOrKey, CoseKey, Bytes, TaggedBytes, AlgLabel, Label, CoseAlgorithm, Vec};
///
/// // Base64 encoded certificate
/// let cert = CryptoKeyTypeChoice::PkixBase64Cert(
///     PkixBase64CertType::new("MIIBIjANBgkq...".into())
/// );
///
/// // COSE key structure
/// let cose = CryptoKeyTypeChoice::CoseKey(
///     CoseKeyType::new(CoseKeySetOrKey::Key(CoseKey {
///         kty: Label::Int(1),  // EC2 key type
///         kid: TaggedBytes::new(vec![1, 2, 3]),  // Key ID
///         alg: AlgLabel::Int(CoseAlgorithm::ES256),  // ES256 algorithm
///         key_ops: vec![
///             Label::Int(1),  // sign
///             Label::Int(2),  // verify
///         ].into(),
///         base_iv: TaggedBytes::new(vec![4, 5, 6]),  // Initialization vector
///         extension: None,  // No extensions
///     }))
/// );
///
/// // Raw key bytes
/// let raw = CryptoKeyTypeChoice::Bytes(
///     Bytes::from(vec![0x01, 0x02, 0x03])
/// );
/// ```
///
/// Each variant provides appropriate constructors and implements common traits
/// like `From`, `TryFrom`, `Serialize`, and `Deserialize`.
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum CryptoKeyTypeChoice<'a> {
    /// Base64-encoded PKIX key
    PkixBase64Key(PkixBase64KeyType<'a>),
    /// Base64-encoded PKIX certificate
    PkixBase64Cert(PkixBase64CertType<'a>),
    /// Base64-encoded PKIX certificate path
    PkixBase64CertPath(PkixBase64CertPathType<'a>),
    /// COSE key structure
    CoseKey(CoseKeyType<'a>),
    /// Generic cryptographic thumbprint
    Thumbprint(ThumbprintType<'a>),
    /// Certificate thumbprint
    CertThumbprint(CertThumprintType<'a>),
    /// Certificate path thumbprint
    CertPathThumbprint(CertPathThumbprintType<'a>),
    /// ASN.1 DER encoded PKIX certificate
    PkixAsn1DerCert(PkixAsn1DerCertType),
    /// Raw bytes
    Bytes(Bytes),
}

impl<'a> CryptoKeyTypeChoice<'a> {
    pub fn as_pkix_key(&self) -> Option<PkixBase64KeyType> {
        match self {
            Self::PkixBase64Key(key) => Some(key.clone()),
            _ => None,
        }
    }

    pub fn as_ref_pkix_key(&self) -> Option<&PkixBase64KeyType> {
        match self {
            Self::PkixBase64Key(key) => Some(key),
            _ => None,
        }
    }

    pub fn as_pkix_cert(&self) -> Option<PkixBase64CertType> {
        match self {
            Self::PkixBase64Cert(cert) => Some(cert.clone()),
            _ => None,
        }
    }

    pub fn as_ref_pkix_cert(&self) -> Option<&PkixBase64CertType> {
        match self {
            Self::PkixBase64Cert(cert) => Some(cert),
            _ => None,
        }
    }

    pub fn as_pkix_cert_path(&self) -> Option<PkixBase64CertPathType> {
        match self {
            Self::PkixBase64CertPath(cert_path) => Some(cert_path.clone()),
            _ => None,
        }
    }

    pub fn as_ref_pkix_cert_path(&self) -> Option<&PkixBase64CertPathType> {
        match self {
            Self::PkixBase64CertPath(cert_path) => Some(cert_path),
            _ => None,
        }
    }

    pub fn as_cose_key(&self) -> Option<CoseKeyType> {
        match self {
            Self::CoseKey(key) => Some(key.clone()),
            _ => None,
        }
    }

    pub fn as_ref_cose_key(&self) -> Option<&CoseKeyType> {
        match self {
            Self::CoseKey(key) => Some(key),
            _ => None,
        }
    }

    pub fn as_thumbprint(&self) -> Option<ThumbprintType> {
        match self {
            Self::Thumbprint(thumbprint) => Some(thumbprint.clone()),
            _ => None,
        }
    }

    pub fn as_ref_thumbprint(&self) -> Option<&ThumbprintType> {
        match self {
            Self::Thumbprint(thumbprint) => Some(thumbprint),
            _ => None,
        }
    }

    pub fn as_cert_thumbprint(&self) -> Option<CertThumprintType> {
        match self {
            Self::CertThumbprint(thumbprint) => Some(thumbprint.clone()),
            _ => None,
        }
    }

    pub fn as_ref_cert_thumbprint(&self) -> Option<&CertThumprintType> {
        match self {
            Self::CertThumbprint(thumbprint) => Some(thumbprint),
            _ => None,
        }
    }

    pub fn as_cert_path_thumbprint(&self) -> Option<CertPathThumbprintType> {
        match self {
            Self::CertPathThumbprint(thumbprint) => Some(thumbprint.clone()),
            _ => None,
        }
    }

    pub fn as_ref_cert_path_thumbprint(&self) -> Option<&CertPathThumbprintType> {
        match self {
            Self::CertPathThumbprint(thumbprint) => Some(thumbprint),
            _ => None,
        }
    }

    pub fn as_pkix_asn1_der_cert(&self) -> Option<PkixAsn1DerCertType> {
        match self {
            Self::PkixAsn1DerCert(cert) => Some(cert.clone()),
            _ => None,
        }
    }

    pub fn as_ref_pkix_asn1_der_cert(&self) -> Option<&PkixAsn1DerCertType> {
        match self {
            Self::PkixAsn1DerCert(cert) => Some(cert),
            _ => None,
        }
    }

    pub fn as_raw_bytes(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes.as_ref(),
            _ => &[],
        }
    }
}

/// Types of group identifiers
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum GroupIdTypeChoice {
    /// UUID identifier
    Uuid(UuidType),
    /// Raw bytes
    Bytes(Bytes),
}

impl GroupIdTypeChoice {
    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(uuid) => Some(uuid.as_ref()),
            _ => None,
        }
    }

    pub fn as_raw_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes.as_ref()),
            _ => None,
        }
    }
}

/// Map containing measurement values and metadata
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct MeasurementMap<'a> {
    /// Optional measurement key identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "0")]
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    /// Measurement values
    #[serde(rename = "1")]
    pub mval: MeasurementValuesMap<'a>,
    /// Optional list of authorizing keys
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "2")]
    pub authorized_by: Option<Vec<CryptoKeyTypeChoice<'a>>>,
}

/// Types of measured element identifiers
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum MeasuredElementTypeChoice<'a> {
    /// Object Identifier (OID)
    Oid(OidType),
    /// UUID identifier
    Uuid(UuidType),
    /// Unsigned integer
    UInt(Uint),
    /// Text string
    Tstr(Tstr<'a>),
}

impl<'a> MeasuredElementTypeChoice<'a> {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Oid(oid) => oid.is_empty(),
            Self::Uuid(uuid) => uuid.is_empty(),
            Self::UInt(_) => false,
            Self::Tstr(tstr) => tstr.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Oid(oid) => oid.len(),
            Self::Uuid(uuid) => uuid.len(),
            Self::UInt(_) => 4,
            Self::Tstr(tstr) => tstr.len(),
        }
    }

    pub fn as_oid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Oid(oid) => Some(oid.as_ref()),
            _ => None,
        }
    }

    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(uuid) => Some(uuid.as_ref()),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u32> {
        match self {
            Self::UInt(uint) => Some(*uint),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Tstr(tstr) => Some(tstr),
            _ => None,
        }
    }
}

impl<'a> From<&'a str> for MeasuredElementTypeChoice<'a> {
    fn from(value: &'a str) -> Self {
        Self::Tstr(value.into())
    }
}

/// Collection of measurement values and attributes. It is **HIGHLY** recommend to use MeasurementValuesMapBuilder
/// to ensure the CDDL enforcement of at least one field being present.
#[derive(Default, Debug, Serialize, Deserialize, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct MeasurementValuesMap<'a> {
    /// Optional version information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "0")]
    pub version: Option<VersionMap<'a>>,
    /// Optional security version number
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "1")]
    pub svn: Option<SvnTypeChoice>,
    /// Optional cryptographic digest
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "2")]
    pub digest: Option<DigestsType<'a>>,
    /// Optional status flags
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "3")]
    pub flags: Option<FlagsMap<'a>>,
    /// Optional raw measurement value
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawValueType>,
    /// Optional MAC address
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "6")]
    pub mac_addr: Option<MacAddrTypeChoice>,
    /// Optional IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "7")]
    pub ip_addr: Option<IpAddrTypeChoice>,
    /// Optional serial number
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "8")]
    pub serial_number: Option<Text<'a>>,
    /// Optional UEID
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "9")]
    pub ueid: Option<UeidType>,
    /// Optional UUID
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "10")]
    pub uuid: Option<UuidType>,
    /// Optional name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "11")]
    pub name: Option<Text<'a>>,
    /// Optional cryptographic keys
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "13")]
    pub cryptokeys: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    /// Optional integrity register values
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "14")]
    pub integrity_registers: Option<IntegrityRegisters<'a>>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap<'a>>,
}

pub struct MeasurementValuesMapBuilder<'a> {
    /// Optional version information
    pub version: Option<VersionMap<'a>>,
    /// Optional security version number
    pub svn: Option<SvnTypeChoice>,
    /// Optional cryptographic digest
    pub digest: Option<DigestsType<'a>>,
    /// Optional status flags
    pub flags: Option<FlagsMap<'a>>,
    /// Optional raw measurement value
    pub raw: Option<RawValueType>,
    /// Optional MAC address
    pub mac_addr: Option<MacAddrTypeChoice>,
    /// Optional IP address
    pub ip_addr: Option<IpAddrTypeChoice>,
    /// Optional serial number
    pub serial_number: Option<Text<'a>>,
    /// Optional UEID
    pub ueid: Option<UeidType>,
    /// Optional UUID
    pub uuid: Option<UuidType>,
    /// Optional name
    pub name: Option<Text<'a>>,
    /// Optional cryptographic keys
    pub cryptokeys: Option<Vec<CryptoKeyTypeChoice<'a>>>,
    /// Optional integrity register values
    pub integrity_registers: Option<IntegrityRegisters<'a>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl<'a> MeasurementValuesMapBuilder<'a> {
    pub fn version(mut self, value: VersionMap<'a>) -> Self {
        self.version = Some(value);
        self
    }
    pub fn svn(mut self, value: SvnTypeChoice) -> Self {
        self.svn = Some(value);
        self
    }
    pub fn digest(mut self, value: DigestsType<'a>) -> Self {
        self.digest = Some(value);
        self
    }
    pub fn flags(mut self, value: FlagsMap<'a>) -> Self {
        self.flags = Some(value);
        self
    }
    pub fn raw(mut self, value: RawValueType) -> Self {
        self.raw = Some(value);
        self
    }
    pub fn mac_addr(mut self, value: MacAddrTypeChoice) -> Self {
        self.mac_addr = Some(value);
        self
    }
    pub fn ip_addr(mut self, value: IpAddrTypeChoice) -> Self {
        self.ip_addr = Some(value);
        self
    }
    pub fn serial_number(mut self, value: Text<'a>) -> Self {
        self.serial_number = Some(value);
        self
    }
    pub fn ueid(mut self, value: UeidType) -> Self {
        self.ueid = Some(value);
        self
    }
    pub fn uuid(mut self, value: UuidType) -> Self {
        self.uuid = Some(value);
        self
    }
    pub fn name(mut self, value: Text<'a>) -> Self {
        self.name = Some(value);
        self
    }
    pub fn cryptokeys(mut self, value: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.cryptokeys = Some(value);
        self
    }
    pub fn integrity_registers(mut self, value: IntegrityRegisters<'a>) -> Self {
        self.integrity_registers = Some(value);
        self
    }
    pub fn extensions(mut self, value: ExtensionMap<'a>) -> Self {
        self.extensions = Some(value);
        self
    }

    pub fn build(self) -> Result<MeasurementValuesMap<'a>> {
        if self.version.is_none()
            && self.svn.is_none()
            && self.digest.is_none()
            && self.flags.is_none()
            && self.raw.is_none()
            && self.mac_addr.is_none()
            && self.ip_addr.is_none()
            && self.serial_number.is_none()
            && self.ueid.is_none()
            && self.uuid.is_none()
            && self.name.is_none()
            && self.cryptokeys.is_none()
            && self.integrity_registers.is_none()
            && self.extensions.is_none()
        {
            return Err(TriplesError::EmptyMeasurementValuesMap)?;
        }
        Ok(MeasurementValuesMap {
            version: self.version,
            svn: self.svn,
            digest: self.digest,
            flags: self.flags,
            raw: self.raw,
            mac_addr: self.mac_addr,
            ip_addr: self.ip_addr,
            serial_number: self.serial_number,
            ueid: self.ueid,
            uuid: self.uuid,
            name: self.name,
            cryptokeys: self.cryptokeys,
            integrity_registers: self.integrity_registers,
            extensions: self.extensions,
        })
    }
}

/// Version information with optional versioning scheme
#[derive(
    Default, Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct VersionMap<'a> {
    /// Version identifier string
    pub version: Text<'a>,
    /// Optional version numbering scheme
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_scheme: Option<VersionScheme>,
}

/// Security version number types
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum SvnTypeChoice {
    /// Regular SVN as an unsigned integer
    Svn(Uint),
    /// SVN with CBOR tag 552
    TaggedSvn(SvnType),
    /// Minimum SVN with CBOR tag 553
    TaggedMinSvn(MinSvnType),
}

impl SvnTypeChoice {
    pub fn as_svn(&self) -> Option<u32> {
        match self {
            Self::Svn(svn) => Some(*svn),
            _ => None,
        }
    }

    pub fn as_tagged_svn(&self) -> Option<u32> {
        match self {
            Self::TaggedSvn(svn) => Some(*svn.as_ref()),
            _ => None,
        }
    }

    pub fn as_tagged_min_svn(&self) -> Option<u32> {
        match self {
            Self::TaggedMinSvn(svn) => Some(*svn.as_ref()),
            _ => None,
        }
    }
}

/// Collection of one or more cryptographic digests
pub type DigestsType<'a> = Vec<Digest<'a>>;

/// Status flags indicating various security and configuration states
#[derive(Default, Debug, Serialize, Deserialize, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct FlagsMap<'a> {
    /// Whether the environment is configured
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "0")]
    pub is_configured: Option<bool>,
    /// Whether the environment is in a secure state
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "1")]
    pub is_secure: Option<bool>,
    /// Whether the environment is in recovery mode
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "2")]
    pub is_recovery: Option<bool>,
    /// Whether debug features are enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "3")]
    pub is_debug: Option<bool>,
    /// Whether replay protection is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "4")]
    pub is_replay_protected: Option<bool>,
    /// Whether integrity protection is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "5")]
    pub is_integrity_protected: Option<bool>,
    /// Whether runtime measurements are enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "6")]
    pub is_runtime_meas: Option<bool>,
    /// Whether the environment is immutable
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "7")]
    pub is_immutable: Option<bool>,
    /// Whether the environment is part of the TCB
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "8")]
    pub is_tcb: Option<bool>,
    /// Whether confidentiality protection is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "9")]
    pub is_confidentiality_protected: Option<bool>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap<'a>>,
}

/// Types of MAC addresses supporting both EUI-48 and EUI-64 formats
///
/// Implements standard traits for byte access:
/// - `AsRef<[u8]>`/`AsMut<[u8]>` for buffer access
/// - `Deref`/`DerefMut` for direct byte manipulation
/// - `From` for construction from byte arrays
/// - `TryFrom` for fallible construction from slices
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum MacAddrTypeChoice {
    /// 48-bit EUI address
    Eui48Addr(Eui48AddrType),
    /// 64-bit EUI address
    Eui64Addr(Eui64AddrType),
}

impl MacAddrTypeChoice {
    pub fn as_eui48_addr(&self) -> Option<&[u8]> {
        match self {
            Self::Eui48Addr(addr) => Some(addr),
            _ => None,
        }
    }

    pub fn as_eui64_addr(&self) -> Option<&[u8]> {
        match self {
            Self::Eui64Addr(addr) => Some(addr),
            _ => None,
        }
    }
}

impl From<Eui48AddrType> for MacAddrTypeChoice {
    fn from(value: Eui48AddrType) -> Self {
        Self::Eui48Addr(value)
    }
}

impl From<Eui64AddrType> for MacAddrTypeChoice {
    fn from(value: Eui64AddrType) -> Self {
        Self::Eui64Addr(value)
    }
}

impl TryFrom<&[u8]> for MacAddrTypeChoice {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        match value.len() {
            6 => Ok(Self::Eui48Addr(value.try_into().unwrap())),
            8 => Ok(Self::Eui64Addr(value.try_into().unwrap())),
            _ => Err(<[u8; 0]>::try_from(&[][..]).unwrap_err()),
        }
    }
}

impl AsRef<[u8]> for MacAddrTypeChoice {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Eui48Addr(addr) => addr,
            Self::Eui64Addr(addr) => addr,
        }
    }
}

impl AsMut<[u8]> for MacAddrTypeChoice {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Eui48Addr(addr) => addr,
            Self::Eui64Addr(addr) => addr,
        }
    }
}

impl Deref for MacAddrTypeChoice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Eui48Addr(addr) => addr,
            Self::Eui64Addr(addr) => addr,
        }
    }
}

impl DerefMut for MacAddrTypeChoice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Eui48Addr(addr) => addr,
            Self::Eui64Addr(addr) => addr,
        }
    }
}

/// 48-bit MAC address type
pub type Eui48AddrType = [u8; 6];
/// 64-bit MAC address type
pub type Eui64AddrType = [u8; 8];

/// Types of IP addresses supporting both IPv4 and IPv6
///
/// Storage uses network byte order (big-endian) following RFC 791/8200.
/// Implements the same traits as MacAddrTypeChoice for consistent handling.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
#[serde(untagged)]
pub enum IpAddrTypeChoice {
    /// IPv4 address
    Ipv4(Ipv4AddrType),
    /// IPv6 address
    Ipv6(Ipv6AddrType),
}

impl IpAddrTypeChoice {
    pub fn as_ipv4_addr(&self) -> Option<&[u8]> {
        match self {
            Self::Ipv4(addr) => Some(addr),
            _ => None,
        }
    }

    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Ipv4(addr) => Some(Ipv4Addr::from(*addr)),
            _ => None,
        }
    }

    pub fn as_ipv6_addr(&self) -> Option<&[u8]> {
        match self {
            Self::Ipv6(addr) => Some(addr),
            _ => None,
        }
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Self::Ipv6(addr) => Some(Ipv6Addr::from(*addr)),
            _ => None,
        }
    }
}

impl From<Ipv4AddrType> for IpAddrTypeChoice {
    fn from(value: Ipv4AddrType) -> Self {
        Self::Ipv4(value)
    }
}
impl From<Ipv6AddrType> for IpAddrTypeChoice {
    fn from(value: Ipv6AddrType) -> Self {
        Self::Ipv6(value)
    }
}

impl TryFrom<&[u8]> for IpAddrTypeChoice {
    type Error = std::array::TryFromSliceError;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        match value.len() {
            4 => Ok(Self::Ipv4(value.try_into()?)),
            16 => Ok(Self::Ipv6(value.try_into()?)),
            _ => Err(<[u8; 0]>::try_from(&[][..]).unwrap_err()),
        }
    }
}

impl Deref for IpAddrTypeChoice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Ipv4(addr) => addr,
            Self::Ipv6(addr) => addr,
        }
    }
}

impl DerefMut for IpAddrTypeChoice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Ipv4(addr) => addr,
            Self::Ipv6(addr) => addr,
        }
    }
}

impl AsRef<[u8]> for IpAddrTypeChoice {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ipv4(addr) => addr,
            Self::Ipv6(addr) => addr,
        }
    }
}

impl AsMut<[u8]> for IpAddrTypeChoice {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Ipv4(addr) => addr,
            Self::Ipv6(addr) => addr,
        }
    }
}

/// IPv4 address as 4 bytes
pub type Ipv4AddrType = [u8; 4];
/// IPv6 address as 16 bytes
pub type Ipv6AddrType = [u8; 16];

/// Collection of integrity register values
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct IntegrityRegisters<'a>(pub OneOrMore<Ulabel<'a>>);

/// Record containing an endorsement for a specific environmental condition
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct EndorsedTripleRecord<'a> {
    /// Environmental condition being endorsed
    pub condition: EnvironmentMap<'a>,
    /// One or more measurement endorsements
    pub endorsement: Vec<MeasurementMap<'a>>,
}

impl<'a> Serialize for EndorsedTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.condition)?;
        seq.serialize_element(&self.endorsement)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for EndorsedTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<EndorsedTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EndorsedTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for EndorsedTripleRecordVisitor<'a> {
            type Value = EndorsedTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of [EnvironmentMap, Vec<MeasurementMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<EndorsedTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let condition = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let endorsement = seq
                    .next_element::<Vec<MeasurementMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(EndorsedTripleRecord::new(condition, endorsement))
            }
        }

        deserializer.deserialize_seq(EndorsedTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record containing identity information for an environment
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct IdentityTripleRecord<'a> {
    /// Environment being identified
    pub environment: EnvironmentMap<'a>,
    /// List of cryptographic keys associated with the identity
    pub key_list: Vec<CryptoKeyTypeChoice<'a>>,
    /// Optional conditions for the identity
    pub conditions: Option<TriplesRecordCondition<'a>>,
}

impl<'a> Serialize for IdentityTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.conditions.is_none() {
            let mut seq = serializer.serialize_seq(Some(2))?;
            seq.serialize_element(&self.environment)?;
            seq.serialize_element(&self.key_list)?;
            seq.end()
        } else {
            let mut seq = serializer.serialize_seq(Some(3))?;
            seq.serialize_element(&self.environment)?;
            seq.serialize_element(&self.key_list)?;
            seq.serialize_element(&self.conditions)?;
            seq.end()
        }
    }
}

impl<'de, 'a> Deserialize<'de> for IdentityTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<IdentityTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdentityTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for IdentityTripleRecordVisitor<'a> {
            type Value = IdentityTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [EnvironmentMap, Vec<CryptoKeyTypeChoice>, Option<TriplesRecordCondition>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<IdentityTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let key_list = seq
                    .next_element::<Vec<CryptoKeyTypeChoice>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let conditions = seq.next_element::<Option<TriplesRecordCondition>>()?;

                if let Some(conditions) = conditions {
                    return Ok(IdentityTripleRecord::new(environment, key_list, conditions));
                } else {
                    return Ok(IdentityTripleRecord::new(environment, key_list, None));
                }
            }
        }

        deserializer.deserialize_seq(IdentityTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Conditions that must be met for a triple record to be valid.It is
/// **HIGHLY** recommended to use the TriplesRecordConditionBuilder, to ensure the CDDL enforcement of
/// at least one field being present.
#[derive(Debug, Serialize, Deserialize, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct TriplesRecordCondition<'a> {
    /// Optional measurement key identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "0")]
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    /// Keys authorized to verify the condition
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "1")]
    pub authorized_by: Option<Vec<CryptoKeyTypeChoice<'a>>>,
}

pub struct TriplesRecordConditionBuilder<'a> {
    /// Optional measurement key identifier
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    /// Keys authorized to verify the condition
    pub authorized_by: Option<Vec<CryptoKeyTypeChoice<'a>>>,
}

impl<'a> TriplesRecordConditionBuilder<'a> {
    pub fn mkey(mut self, value: MeasuredElementTypeChoice<'a>) -> Self {
        self.mkey = Some(value);
        self
    }

    pub fn authorized_by(mut self, value: Vec<CryptoKeyTypeChoice<'a>>) -> Self {
        self.authorized_by = Some(value);
        self
    }

    pub fn build(self) -> Result<TriplesRecordCondition<'a>> {
        if self.mkey.is_none() && self.authorized_by.is_none() {
            return Err(TriplesError::EmptyTripleRecordCondition)?;
        }
        Ok(TriplesRecordCondition {
            mkey: self.mkey,
            authorized_by: self.authorized_by,
        })
    }
}

/// Record containing attestation key information for an environment
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct AttestKeyTripleRecord<'a> {
    /// Environment the keys belong to
    pub environment: EnvironmentMap<'a>,
    /// List of attestation keys
    pub key_list: Vec<CryptoKeyTypeChoice<'a>>,
    /// Optional conditions for key usage
    pub conditions: Option<TriplesRecordCondition<'a>>,
}

impl<'a> Serialize for AttestKeyTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.conditions.is_none() {
            let mut seq = serializer.serialize_seq(Some(2))?;
            seq.serialize_element(&self.environment)?;
            seq.serialize_element(&self.key_list)?;
            seq.end()
        } else {
            let mut seq = serializer.serialize_seq(Some(3))?;
            seq.serialize_element(&self.environment)?;
            seq.serialize_element(&self.key_list)?;
            seq.serialize_element(&self.conditions)?;
            seq.end()
        }
    }
}

impl<'de, 'a> Deserialize<'de> for AttestKeyTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<AttestKeyTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AttestKeyTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for AttestKeyTripleRecordVisitor<'a> {
            type Value = AttestKeyTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [EnvironmentMap, Vec<CryptoKeyTypeChoice>, Option<TriplesRecordCondition>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<AttestKeyTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let key_list = seq
                    .next_element::<Vec<CryptoKeyTypeChoice>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let conditions = seq.next_element::<Option<TriplesRecordCondition>>()?;

                if let Some(conditions) = conditions {
                    return Ok(AttestKeyTripleRecord::new(
                        environment,
                        key_list,
                        conditions,
                    ));
                } else {
                    return Ok(AttestKeyTripleRecord::new(environment, key_list, None));
                }
            }
        }

        deserializer.deserialize_seq(AttestKeyTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record describing dependencies between domains and environments
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct DomainDependencyTripleRecord<'a> {
    /// Domain identifier
    pub domain_choice: DomainTypeChoice<'a>,
    /// One or more dependent environments
    pub environment_map: Vec<EnvironmentMap<'a>>,
}

// Need to implement Serialize / Deserialize here.
impl<'a> Serialize for DomainDependencyTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.domain_choice)?;
        seq.serialize_element(&self.environment_map)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for DomainDependencyTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DomainDependencyTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for DomainDependencyTripleRecordVisitor<'a> {
            type Value = DomainDependencyTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [DomainTypeChoice, Vec<EnvironmentMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<DomainDependencyTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let domain_choice = seq
                    .next_element::<DomainTypeChoice>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let environment_map = seq
                    .next_element::<Vec<EnvironmentMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(DomainDependencyTripleRecord::new(
                    domain_choice,
                    environment_map,
                ))
            }
        }

        deserializer.deserialize_seq(DomainDependencyTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Types of domain identifiers
#[derive(Debug, Serialize, Deserialize, From, TryFrom, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(untagged)]
pub enum DomainTypeChoice<'a> {
    /// Unsigned integer identifier
    Uint(Uint),
    /// Text string identifier
    Text(Text<'a>),
    /// UUID identifier
    Uuid(UuidType),
    /// Object Identifier (OID)
    Oid(OidType),
}

impl<'a> DomainTypeChoice<'a> {
    pub fn as_uint(&self) -> Option<u32> {
        match self {
            Self::Uint(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_uuid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Uuid(value) => Some(value.as_ref()),
            _ => None,
        }
    }

    pub fn as_oid_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Oid(value) => Some(value.as_ref()),
            _ => None,
        }
    }
}

/// Record describing domain membership associations
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct DomainMembershipTripleRecord<'a> {
    /// Domain identifier
    pub domain_choice: DomainTypeChoice<'a>,
    /// One or more member environments
    pub environment_map: Vec<EnvironmentMap<'a>>,
}

impl<'a> Serialize for DomainMembershipTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.domain_choice)?;
        seq.serialize_element(&self.environment_map)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for DomainMembershipTripleRecord<'a> {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<DomainMembershipTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DomainMembershipTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for DomainMembershipTripleRecordVisitor<'a> {
            type Value = DomainMembershipTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [DomainTypeChoice, Vec<EnvironmentMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<DomainMembershipTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let domain_choice = seq
                    .next_element::<DomainTypeChoice>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let environment_map = seq
                    .next_element::<Vec<EnvironmentMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(DomainMembershipTripleRecord::new(
                    domain_choice,
                    environment_map,
                ))
            }
        }

        deserializer.deserialize_seq(DomainMembershipTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record linking environments to CoSWID tags
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct CoswidTripleRecord<'a> {
    /// Environment the CoSWID tags belong to
    pub environment_map: EnvironmentMap<'a>,
    /// List of associated CoSWID tag identifiers
    pub coswid_tags: Vec<ConciseSwidTagId<'a>>,
}

impl<'a> Serialize for CoswidTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.environment_map)?;
        seq.serialize_element(&self.coswid_tags)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for CoswidTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<CoswidTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoswidTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CoswidTripleRecordVisitor<'a> {
            type Value = CoswidTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [EnvironmentMap, Vec<ConciseSwidTagId>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<CoswidTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment_map = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let coswid_tags = seq
                    .next_element::<Vec<ConciseSwidTagId>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(CoswidTripleRecord::new(environment_map, coswid_tags))
            }
        }

        deserializer.deserialize_seq(CoswidTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record describing a series of conditional endorsements
///
/// This type implements complex endorsement scenarios where measurements
/// may change over time in a defined sequence. The record tracks:
///
/// 1. Initial environment state and measurements
/// 2. Series of allowed measurement changes
/// 3. Required verification at each step
///
/// # Processing Rules
///
/// - Changes must be applied in sequence order
/// - Each change requires matching the selection criteria
/// - New measurements are added only when selections match
/// - Previous measurements remain valid unless replaced
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConditionalEndorsementSeriesTripleRecord<'a> {
    /// Initial environmental condition
    pub condition: StatefulEnvironmentRecord<'a>,
    /// Series of conditional changes
    pub series: Vec<ConditionalSeriesRecord<'a>>,
}

impl<'a> Serialize for ConditionalEndorsementSeriesTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.condition)?;
        seq.serialize_element(&self.series)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for ConditionalEndorsementSeriesTripleRecord<'a> {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<ConditionalEndorsementSeriesTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConditionalEndorsementSeriesTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for ConditionalEndorsementSeriesTripleRecordVisitor<'a> {
            type Value = ConditionalEndorsementSeriesTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "A sequence of [StatefulEnvironmentRecord, Vec<ConditionalSeriesRecord>]",
                )
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<ConditionalEndorsementSeriesTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let condition = seq
                    .next_element::<StatefulEnvironmentRecord>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let series = seq
                    .next_element::<Vec<ConditionalSeriesRecord>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ConditionalEndorsementSeriesTripleRecord::new(
                    condition, series,
                ))
            }
        }

        deserializer.deserialize_seq(ConditionalEndorsementSeriesTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record containing environment state and measurement claims
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct StatefulEnvironmentRecord<'a> {
    /// Environment being described
    pub environment: EnvironmentMap<'a>,
    /// List of measurement claims about the environment
    pub claims_list: Vec<MeasurementMap<'a>>,
}

impl<'a> Serialize for StatefulEnvironmentRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.environment)?;
        seq.serialize_element(&self.claims_list)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for StatefulEnvironmentRecord<'a> {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<StatefulEnvironmentRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatefulEnvironmentRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for StatefulEnvironmentRecordVisitor<'a> {
            type Value = StatefulEnvironmentRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [EnvironmentMap, [+ MeasurementMap]]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<StatefulEnvironmentRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let claims_list = seq
                    .next_element::<Vec<MeasurementMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(StatefulEnvironmentRecord::new(environment, claims_list))
            }
        }

        deserializer.deserialize_seq(StatefulEnvironmentRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record describing conditional changes to measurements
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConditionalSeriesRecord<'a> {
    /// Measurements that must match for changes to apply
    pub selection: Vec<MeasurementMap<'a>>,
    /// Measurements to add when selection matches
    pub addition: Vec<MeasurementMap<'a>>,
}

impl<'a> Serialize for ConditionalSeriesRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.selection)?;
        seq.serialize_element(&self.addition)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for ConditionalSeriesRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<ConditionalSeriesRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConditionalSeriesRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for ConditionalSeriesRecordVisitor<'a> {
            type Value = ConditionalSeriesRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("A sequence of [Vec<MeasurementMap>, Vec<MeasurementMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<ConditionalSeriesRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let selection = seq
                    .next_element::<Vec<MeasurementMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let addition = seq
                    .next_element::<Vec<MeasurementMap>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ConditionalSeriesRecord::new(selection, addition))
            }
        }

        deserializer.deserialize_seq(ConditionalSeriesRecordVisitor {
            marker: PhantomData,
        })
    }
}

/// Record containing conditional endorsements
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConditionalEndorsementTripleRecord<'a> {
    /// List of environmental conditions
    pub conditions: Vec<StatefulEnvironmentRecord<'a>>,
    /// List of endorsements that apply when conditions are met
    pub endorsements: Vec<EndorsedTripleRecord<'a>>,
}

impl<'a> Serialize for ConditionalEndorsementTripleRecord<'a> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.conditions)?;
        seq.serialize_element(&self.endorsements)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for ConditionalEndorsementTripleRecord<'a> {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<ConditionalEndorsementTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConditionalEndorsementTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for ConditionalEndorsementTripleRecordVisitor<'a> {
            type Value = ConditionalEndorsementTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "A sequence of [Vec<StatefulEnvironmentRecord>, Vec<EndorsedTripleRecord>]",
                )
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<ConditionalEndorsementTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let conditions = seq
                    .next_element::<Vec<StatefulEnvironmentRecord>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let endorsements = seq
                    .next_element::<Vec<EndorsedTripleRecord>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ConditionalEndorsementTripleRecord::new(
                    conditions,
                    endorsements,
                ))
            }
        }

        deserializer.deserialize_seq(ConditionalEndorsementTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}
