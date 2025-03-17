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

use std::ops::{Deref, DerefMut};

use crate::{
    core::{NonEmptyVec, PkixBase64CertPathType},
    Bytes, CertPathThumbprintType, CertThumprintType, ConciseSwidTagId, CoseKeyType, Digest,
    ExtensionMap, MinSvnType, OidType, OneOrMore, PkixAsn1DerCertType, PkixBase64CertType,
    PkixBase64KeyType, RawValueType, Result, SvnType, Text, ThumbprintType, TriplesError, Tstr,
    UeidType, Uint, Ulabel, UuidType, VersionScheme,
};
use derive_more::{Constructor, From, TryFrom};
use serde::{Deserialize, Serialize};

/// A reference triple record containing environment and measurement claims
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ReferenceTripleRecord<'a> {
    /// The environment being referenced
    pub ref_env: EnvironmentMap<'a>,
    /// One or more measurement claims about the environment
    pub ref_claims: NonEmptyVec<MeasurementMap<'a>>,
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

impl<'a> From<&'a [u8]> for InstanceIdTypeChoice<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self::Bytes(value.to_vec())
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
/// use corim_rs::core::{PkixBase64CertType, CoseKeyType, CoseKeySetOrKey, CoseKey, Bytes, TaggedBytes, AlgLabel, Label, CoseAlgorithm, NonEmptyVec};
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
    pub authorized_by: Option<NonEmptyVec<CryptoKeyTypeChoice<'a>>>,
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
    pub digest: Option<DigestType<'a>>,
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
    pub cryptokeys: Option<NonEmptyVec<CryptoKeyTypeChoice<'a>>>,
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
    pub digest: Option<DigestType<'a>>,
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
    pub cryptokeys: Option<NonEmptyVec<CryptoKeyTypeChoice<'a>>>,
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
    pub fn digest(mut self, value: DigestType<'a>) -> Self {
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
    pub fn cryptokeys(mut self, value: NonEmptyVec<CryptoKeyTypeChoice<'a>>) -> Self {
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

/// Collection of one or more cryptographic digests
pub type DigestType<'a> = NonEmptyVec<Digest<'a>>;

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
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct EndorsedTripleRecord<'a> {
    /// Environmental condition being endorsed
    pub condition: EnvironmentMap<'a>,
    /// One or more measurement endorsements
    pub endorsement: NonEmptyVec<MeasurementMap<'a>>,
}

/// Record containing identity information for an environment
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct IdentityTripleRecord<'a> {
    /// Environment being identified
    pub environment: EnvironmentMap<'a>,
    /// List of cryptographic keys associated with the identity
    pub key_list: NonEmptyVec<CryptoKeyTypeChoice<'a>>,
    /// Optional conditions for the identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<TriplesRecordCondition<'a>>,
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
    pub authorized_by: Option<NonEmptyVec<CryptoKeyTypeChoice<'a>>>,
}

pub struct TriplesRecordConditionBuilder<'a> {
    /// Optional measurement key identifier
    pub mkey: Option<MeasuredElementTypeChoice<'a>>,
    /// Keys authorized to verify the condition
    pub authorized_by: Option<NonEmptyVec<CryptoKeyTypeChoice<'a>>>,
}

impl<'a> TriplesRecordConditionBuilder<'a> {
    pub fn mkey(mut self, value: MeasuredElementTypeChoice<'a>) -> Self {
        self.mkey = Some(value);
        self
    }

    pub fn authorized_by(mut self, value: NonEmptyVec<CryptoKeyTypeChoice<'a>>) -> Self {
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
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct AttestKeyTripleRecord<'a> {
    /// Environment the keys belong to
    pub environment: EnvironmentMap<'a>,
    /// List of attestation keys
    pub key_list: NonEmptyVec<CryptoKeyTypeChoice<'a>>,
    /// Optional conditions for key usage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<TriplesRecordCondition<'a>>,
}

/// Record describing dependencies between domains and environments
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct DomainDependencyTripleRecord<'a> {
    /// Domain identifier
    #[serde(flatten)]
    pub domain_choice: DomainTypeChoice<'a>,
    /// One or more dependent environments
    #[serde(flatten)]
    pub environment_map: NonEmptyVec<EnvironmentMap<'a>>,
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

/// Record describing domain membership associations
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct DomainMembershipTripleRecord<'a> {
    /// Domain identifier
    #[serde(flatten)]
    pub domain_choice: DomainTypeChoice<'a>,
    /// One or more member environments
    #[serde(flatten)]
    pub environment_map: NonEmptyVec<EnvironmentMap<'a>>,
}

/// Record linking environments to CoSWID tags
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct CoswidTripleRecord<'a> {
    /// Environment the CoSWID tags belong to
    #[serde(flatten)]
    pub environment_map: EnvironmentMap<'a>,
    /// List of associated CoSWID tag identifiers
    #[serde(flatten)]
    pub coswid_tags: NonEmptyVec<ConciseSwidTagId<'a>>,
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
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ConditionalEndorsementSeriesTripleRecord<'a> {
    /// Initial environmental condition
    pub condition: StatefulEnvironmentRecord<'a>,
    /// Series of conditional changes
    pub series: NonEmptyVec<ConditionalSeriesRecord<'a>>,
}

/// Record containing environment state and measurement claims
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct StatefulEnvironmentRecord<'a> {
    /// Environment being described
    pub environment: EnvironmentMap<'a>,
    /// List of measurement claims about the environment
    pub claims_list: NonEmptyVec<MeasurementMap<'a>>,
}

/// Record describing conditional changes to measurements
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ConditionalSeriesRecord<'a> {
    /// Measurements that must match for changes to apply
    pub selection: NonEmptyVec<MeasurementMap<'a>>,
    /// Measurements to add when selection matches
    pub addition: NonEmptyVec<MeasurementMap<'a>>,
}

/// Record containing conditional endorsements
#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ConditionalEndorsementTripleRecord<'a> {
    /// List of environmental conditions
    pub conditions: NonEmptyVec<StatefulEnvironmentRecord<'a>>,
    /// List of endorsements that apply when conditions are met
    pub endorsements: NonEmptyVec<EndorsedTripleRecord<'a>>,
}
