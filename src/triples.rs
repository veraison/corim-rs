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
//! # Environment Description
//!
//! The [`EnvironmentMap`] structure is central to all triple records and can include:
//! - Classification information
//! - Instance identifiers
//! - Group identifiers
//! - Measurement values
//! - Security state flags
//! - Network addressing
//! - Integrity registers
//!
//! # Example
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

use crate::{
    Bytes, CertPathThumbprintType, CertThumprintType, ConciseSwidTagId, CoseKeyType, Digest,
    ExtensionMap, MinSvnType, OidType, OneOrMore, PkixAsn1DerCertType, PkixBase64CertType,
    PkixBase64KeyType, RawValueType, SvnType, Text, ThumbprintType, Tstr, UeidType, Uint, Ulabel,
    UuidType, VersionScheme,
};
use serde::{Deserialize, Serialize};

/// A reference triple record containing environment and measurement claims
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ReferenceTripleRecord {
    /// The environment being referenced
    pub ref_env: EnvironmentMap,
    /// One or more measurement claims about the environment
    pub ref_claims: OneOrMore<MeasurementMap>,
}

/// Map describing an environment's characteristics
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct EnvironmentMap {
    /// Optional classification information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<ClassMap>,
    /// Optional instance identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<InstanceIdTypeChoice>,
    /// Optional group identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupIdTypeChoice>,
}

/// Classification information for an environment
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ClassMap {
    /// Optional class identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_id: Option<ClassIdTypeChoice>,
    /// Optional vendor name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<Tstr>,
    /// Optional model identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<Tstr>,
    /// Optional layer number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<Uint>,
    /// Optional index number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<Uint>,
}

/// Possible types for class identifiers
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum ClassIdTypeChoice {
    /// Object Identifier (OID)
    Oid(OidType),
    /// UUID identifier
    Uuid(UuidType),
    /// Raw bytes
    Bytes(Bytes),
}

/// Possible types for instance identifiers
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum InstanceIdTypeChoice {
    /// Unique Entity Identifier
    Ueid(UeidType),
    /// UUID identifier
    Uuid(UuidType),
    /// Cryptographic key identifier
    CryptoKey(CryptoKeyTypeChoice),
    /// Raw bytes
    Bytes(Bytes),
}

/// Types of cryptographic keys and certificates
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum CryptoKeyTypeChoice {
    /// Base64-encoded PKIX key
    PkixBase64Key(PkixBase64KeyType),
    /// Base64-encoded PKIX certificate
    PkixBase64Cert(PkixBase64CertType),
    /// Base64-encoded PKIX certificate path
    PkixBase64CertPath(PkixBase64CertType),
    /// COSE key structure
    CoseKey(CoseKeyType),
    /// Generic cryptographic thumbprint
    Thumbprint(ThumbprintType),
    /// Certificate thumbprint
    CertThumbprint(CertThumprintType),
    /// Certificate path thumbprint
    CertPathThumbprint(CertPathThumbprintType),
    /// ASN.1 DER encoded PKIX certificate
    PkixAsn1DerCert(PkixAsn1DerCertType),
    /// Raw bytes
    Bytes(Bytes),
}

/// Types of group identifiers
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum GroupIdTypeChoice {
    /// UUID identifier
    Uuid(UuidType),
    /// Raw bytes
    Bytes(Bytes),
}

/// Map containing measurement values and metadata
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct MeasurementMap {
    /// Optional measurement key identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mkey: Option<MeasuredElementTypeChoice>,
    /// Measurement values
    pub mval: MeasurementValuesMap,
    /// Optional list of authorizing keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_by: Option<OneOrMore<CryptoKeyTypeChoice>>,
}

/// Types of measured element identifiers
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum MeasuredElementTypeChoice {
    /// Object Identifier (OID)
    Oid(OidType),
    /// UUID identifier
    Uuid(UuidType),
    /// Unsigned integer
    UInt(Uint),
    /// Text string
    Tstr(Tstr),
}

/// Collection of measurement values and attributes
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct MeasurementValuesMap {
    /// Optional version information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<VersionMap>,
    /// Optional security version number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svn: Option<SvnTypeChoice>,
    /// Optional cryptographic digest
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<DigestType>,
    /// Optional status flags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<FlagsMap>,
    /// Optional raw measurement value
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawValueType>,
    /// Optional MAC address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_addr: Option<MacAddrTypeChoice>,
    /// Optional IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_addr: Option<IpAddrTypeChoice>,
    /// Optional serial number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<Text>,
    /// Optional UEID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ueid: Option<UeidType>,
    /// Optional UUID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<UuidType>,
    /// Optional name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Text>,
    /// Optional cryptographic keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptokeys: Option<OneOrMore<CryptoKeyTypeChoice>>,
    /// Optional integrity register values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_registers: Option<IntegrityRegisters>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap>,
}

/// Version information with optional versioning scheme
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct VersionMap {
    /// Version identifier string
    pub version: Text,
    /// Optional version numbering scheme
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_scheme: Option<VersionScheme>,
}

/// Security version number types
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum SvnTypeChoice {
    /// Regular SVN as an unsigned integer
    Svn(Uint),
    /// SVN with CBOR tag 552
    TaggedSvn(SvnType),
    /// Minimum SVN with CBOR tag 553
    TaggedMinSvn(MinSvnType),
}

/// Collection of one or more cryptographic digests
pub type DigestType = OneOrMore<Digest>;

/// Status flags indicating various security and configuration states
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct FlagsMap {
    /// Whether the environment is configured
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_configured: Option<bool>,
    /// Whether the environment is in a secure state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_secure: Option<bool>,
    /// Whether the environment is in recovery mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_recovery: Option<bool>,
    /// Whether debug features are enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_debug: Option<bool>,
    /// Whether replay protection is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_replay_protected: Option<bool>,
    /// Whether integrity protection is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_integrity_protected: Option<bool>,
    /// Whether runtime measurements are enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_runtime_meas: Option<bool>,
    /// Whether the environment is immutable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_immutable: Option<bool>,
    /// Whether the environment is part of the TCB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_tcb: Option<bool>,
    /// Whether confidentiality protection is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_confidentiality_protected: Option<bool>,
    /// Optional extensible attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub extensions: Option<ExtensionMap>,
}

/// Types of MAC addresses
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum MacAddrTypeChoice {
    /// 48-bit EUI address
    Eui48Addr(Eui48AddrType),
    /// 64-bit EUI address
    Eui64Addr(Eui64AddrType),
}

/// 48-bit MAC address type
pub type Eui48AddrType = [u8; 6];
/// 64-bit MAC address type
pub type Eui64AddrType = [u8; 8];

/// Types of IP addresses
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub enum IpAddrTypeChoice {
    /// IPv4 address
    Ipv4(Ipv4AddrType),
    /// IPv6 address
    Ipv6(Ipv6AddrType),
}

/// IPv4 address as 4 bytes
pub type Ipv4AddrType = [u8; 4];
/// IPv6 address as 16 bytes
pub type Ipv6AddrType = [u8; 16];

/// Collection of integrity register values
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct IntegrityRegisters {
    /// One or more register values identified by labels
    #[serde(flatten)]
    pub field: OneOrMore<Ulabel>,
}

/// Record containing an endorsement for a specific environmental condition
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct EndorsedTripleRecord {
    /// Environmental condition being endorsed
    pub condition: EnvironmentMap,
    /// One or more measurement endorsements
    pub endorsement: OneOrMore<MeasurementMap>,
}

/// Record containing identity information for an environment
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct IdentityTripleRecord {
    /// Environment being identified
    pub environment: EnvironmentMap,
    /// List of cryptographic keys associated with the identity
    pub key_list: OneOrMore<CryptoKeyTypeChoice>,
    /// Optional conditions for the identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<TripleRecordCondition>,
}

/// Conditions that must be met for a triple record to be valid
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct TripleRecordCondition {
    /// Optional measurement key identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mkey: Option<MeasuredElementTypeChoice>,
    /// Keys authorized to verify the condition
    pub authorized_by: OneOrMore<CryptoKeyTypeChoice>,
}

/// Record containing attestation key information for an environment
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct AttestKeyTripleRecord {
    /// Environment the keys belong to
    pub environment: EnvironmentMap,
    /// List of attestation keys
    pub key_list: OneOrMore<CryptoKeyTypeChoice>,
    /// Optional conditions for key usage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<TripleRecordCondition>,
}

/// Record describing dependencies between domains and environments
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct DomainDependencyTripleRecord {
    /// Domain identifier
    #[serde(flatten)]
    pub domain_choice: DomainTypeChoice,
    /// One or more dependent environments
    #[serde(flatten)]
    pub environment_map: OneOrMore<EnvironmentMap>,
}

/// Types of domain identifiers
#[derive(Serialize, Deserialize)]
pub enum DomainTypeChoice {
    /// Unsigned integer identifier
    Uint(Uint),
    /// Text string identifier
    Text(Text),
    /// UUID identifier
    Uuid(UuidType),
    /// Object Identifier (OID)
    Oid(OidType),
}
/// Record describing domain membership associations
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct DomainMembershipTripleRecord {
    /// Domain identifier
    #[serde(flatten)]
    pub domain_choice: DomainTypeChoice,
    /// One or more member environments
    #[serde(flatten)]
    pub environment_map: OneOrMore<EnvironmentMap>,
}

/// Record linking environments to CoSWID tags
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct CoswidTripleRecord {
    /// Environment the CoSWID tags belong to
    #[serde(flatten)]
    pub environment_map: EnvironmentMap,
    /// List of associated CoSWID tag identifiers
    #[serde(flatten)]
    pub coswid_tags: OneOrMore<ConciseSwidTagId>,
}

/// Record describing a series of conditional endorsements
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ConditionalEndorsementSeriesTripleRecord {
    /// Initial environmental condition
    pub condition: StatefulEnvironmentRecord,
    /// Series of conditional changes
    pub series: OneOrMore<ConditionalSeriesRecord>,
}

/// Record containing environment state and measurement claims
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct StatefulEnvironmentRecord {
    /// Environment being described
    pub environment: EnvironmentMap,
    /// List of measurement claims about the environment
    pub claims_list: OneOrMore<MeasurementMap>,
}

/// Record describing conditional changes to measurements
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ConditionalSeriesRecord {
    /// Measurements that must match for changes to apply
    pub selection: OneOrMore<MeasurementMap>,
    /// Measurements to add when selection matches
    pub addition: OneOrMore<MeasurementMap>,
}

/// Record containing conditional endorsements
#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct ConditionalEndorsementTripleRecord {
    /// List of environmental conditions
    pub conditions: OneOrMore<StatefulEnvironmentRecord>,
    /// List of endorsements that apply when conditions are met
    pub endorsements: OneOrMore<EndorsedTripleRecord>,
}
