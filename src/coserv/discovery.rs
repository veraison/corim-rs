// SPDX-License-Identifier: MIT

//! CoSERV Discovery Document implementation
//!
//! This module implements the CoSERV discovery document as defined in Section 6.1.1.1
//! of the CoSERV Internet Draft: https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#section-6.1.1.1
//!
//! The purpose of the discovery document is to bootstrap the interaction with a CoSERV-enabled
//! endorsement service or reference value provider service. Such services make the discovery
//! document available from the `/.well-known/coserv-configuration` URL path, relative to the base
//! URL of the service.
//!
//! The discovery document is an entirely separate data model from the rest of CoSERV. It is never
//! a component of a CoSERV query or result set. Its purpose is to provide a description of the
//! service and its capabilities.
//!
//! This module provides the data types to model the discovery document contents, along with
//! the serialization and deserialization functionality for both JSON and CBOR formats. You can
//! use this module in a client-side context to parse and inspect a discovery document that has
//! been received from the well-known URL of a server. You can also use it in a server-side context
//! to create a discovery document from scratch and then serialize it for a consumer.
//!
//! The top-level type is [`DiscoveryDocument`], which models the root of the document.
//!
//! # Examples
//!
//! Deserialize a discovery document from CBOR and write it back out again:
//!
//! ```rust
//! use corim_rs::coserv::discovery::DiscoveryDocument;
//!
//! // Example CBOR bytes for a valid discovery document
//! let source_cbor: Vec<u8> = vec![
//!         0xbf, 0x01, 0x6a, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2d, 0x62, 0x65, 0x74, 0x61, 0x02,
//!         0x81, 0xbf, 0x01, 0x78, 0x48, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
//!         0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x73, 0x65, 0x72, 0x76, 0x2b, 0x63, 0x6f, 0x73, 0x65,
//!         0x3b, 0x20, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x3d, 0x22, 0x74, 0x61, 0x67,
//!         0x3a, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x32, 0x30,
//!         0x32, 0x35, 0x3a, 0x63, 0x63, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d,
//!         0x23, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x22, 0x02, 0x82, 0x69, 0x63, 0x6f, 0x6c, 0x6c,
//!         0x65, 0x63, 0x74, 0x65, 0x64, 0x66, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0xff, 0x03,
//!         0xa1, 0x75, 0x43, 0x6f, 0x53, 0x45, 0x52, 0x56, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
//!         0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x78, 0x2b, 0x2f, 0x65, 0x6e,
//!         0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x2d, 0x64, 0x69, 0x73, 0x74,
//!         0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f,
//!         0x73, 0x65, 0x72, 0x76, 0x2f, 0x7b, 0x71, 0x75, 0x65, 0x72, 0x79, 0x7d, 0x04, 0x81,
//!         0xa6, 0x01, 0x02, 0x02, 0x45, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x03, 0x26, 0x20, 0x01,
//!         0x21, 0x44, 0x1a, 0x2b, 0x3c, 0x4d, 0x22, 0x44, 0x5e, 0x6f, 0x7a, 0x8b, 0xff,
//!     ];
//!
//! // Read from CBOR
//! let discovery_document: DiscoveryDocument =
//!     ciborium::from_reader(source_cbor.as_slice()).unwrap();
//!
//! // Write back out to CBOR
//! let mut emitted_cbor: Vec<u8> = vec![];
//! ciborium::into_writer(&discovery_document, &mut emitted_cbor).unwrap();
//! ```
//!
//! Deserialize a discovery document from JSON and write it back out again:
//!
//! ```rust
//! use corim_rs::coserv::discovery::DiscoveryDocument;
//!
//! let source_json = r#"
//!        {
//!          "version": "1.2.3-beta",
//!          "capabilities": [
//!            {
//!              "media-type": "application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\"",
//!              "artifact-support": [
//!                "source",
//!                "collected"
//!              ]
//!            }
//!          ],
//!          "api-endpoints": {
//!            "CoSERVRequestResponse": "/endorsement-distribution/v1/coserv/{query}"
//!          },
//!          "result-verification-key": [
//!            {
//!               "alg": "ES256",
//!              "crv": "P-256",
//!              "kty": "EC",
//!              "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
//!              "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
//!              "kid": "key1"
//!            }
//!          ]
//!        }
//!    "#;
//!
//!  // Read from JSON
//!  let discovery_document: DiscoveryDocument = serde_json::from_str(source_json).unwrap();
//!
//!  // Write back out again
//!  // Write it back out to JSON
//!  let emitted_json = serde_json::to_string(&discovery_document).unwrap();
//! ```
//!
//! To create a discovery document from scratch, use the struct members directly as follows. Note that the
//! verification key is left undefined in the following example, meaning that the result cannot be
//! serialized to either JSON or CBOR. Use the documentation for [`coset::CoseKey`] or
//! [`jsonwebkey::JsonWebKey`] as applicable for instructions to create keys for the target output
//! format.
//!
//! ```rust
//! use std::collections::{HashMap, HashSet};
//!
//! use corim_rs::coserv::discovery::{
//!    ArtifactType, Capability, DiscoveryDocument, ResultVerificationKey,
//! };
//!
//! use semver::Version;
//!
//! let doc = DiscoveryDocument {
//!    version: Version::parse("1.2.3-beta").unwrap(),
//!    capabilities: vec![Capability {
//!        media_type:
//!            "application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\""
//!                .to_string()
//!                .parse()
//!                .unwrap(),
//!        artifact_support: HashSet::from([ArtifactType::Source, ArtifactType::Collected]),
//!    }],
//!    api_endpoints: HashMap::from([(
//!        "CoSERVRequestResponse".to_string(),
//!        "/endorsement-distribution/v1/coserv/{query}".to_string(),
//!    )]),
//!    result_verification_key: ResultVerificationKey::Undefined,
//! };
//! ```

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;

use ciborium::Value;
use coset::{AsCborValue, CoseKey};
use jsonwebkey::JsonWebKey;

use semver::{BuildMetadata, Prerelease, Version};

use mime::Mime;

use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Error as _, Serialize, SerializeMap},
};

use crate::error::CoservError;
use crate::error::Error;

/// The media type that describes the CoSERV discovery document in JSON format.
///
/// See: https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#name-application-coserv-discovery
pub const DISCOVERY_DOCUMENT_JSON: &str = "application/coserv-discovery+json";

/// The media type that describes the CoSERV discovery document in CBOR format.
///
/// See: https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#name-application-coserv-discover
pub const DISCOVERY_DOCUMENT_CBOR: &str = "application/coserv-discovery+cbor";

/// A single, complete CoSERV discovery document.
///
/// This structure models the CoSERV discovery document contents as described in Section 6.1.1.1
/// of the CoSERV Internet Draft: https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#section-6.1.1.1
///
/// Discovery documents can be serialized to either JSON or CBOR. They can also be deserialized
/// from either JSON or CBOR. But please note that it is **not** possible to deserialize a
/// document from JSON and then serialize the same document instance to CBOR, or vice versa.
/// This is because the verification keys are modelled using JSON-specific or CBOR-specific data
/// types in each case. In cases where you need to switch between formats, you will need to
/// manually create a fresh `DiscoveryDocument` instance, and perform the required conversions
/// between the COSE and JOSE key types.
#[derive(Debug, Clone)]
pub struct DiscoveryDocument {
    /// Implementation-specific version of the service as a semver structure.
    ///
    /// See section 6.1.1.1.1 of the CoSERV draft for further details:
    /// https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#name-version
    pub version: Version,

    /// Capabilities of the service.
    ///
    /// A valid discovery document must contain at least one capability.
    ///
    /// Each capability describes a profiled variant of the `application/coserv+cbor`
    /// or `application/coserv+cose` media type, along with the categories of artifact
    /// (either source or collected) for that media type.
    ///
    /// See section 6.1.1.1.2 of the CoSERV draft for further details:
    /// https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#name-capabilities
    pub capabilities: Vec<Capability>,

    /// The individual API endpoints provided by the service.
    ///
    /// A discovery document must contain at least one API endpoint.
    ///
    /// The keys in the map are the symbolic names of the endpoints, and the values are the URL
    /// paths relative to the base URL of the service. An example key might be
    /// `CoSERVRequestResponse`, and its corresponding value might be
    /// `/endorsement-distribution/v1/coserv`. Assuming that the base URL of the service
    /// is `https://coserv.example`, this would mean that the service provides a CoSERV
    /// request-response API at `https://coserv.example/endorsement-distribution/v1/coserv`.
    ///
    /// See Section 6.1.1.1.3 of the CoSERV draft for further details:
    /// https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#name-api-endpoints
    pub api_endpoints: HashMap<String, String>,

    /// The public keys that the client can use to cryptographically verify the CoSERV
    /// result sets.
    ///
    /// See section 6.1.1.1.4 of the CoSERV draft for further details:
    /// https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#name-result-verification-key
    pub result_verification_key: ResultVerificationKey,
}

/// This type represents the two categories of artifact that are defined in the CoSERV draft:
/// source artifacts and collected artifacts.
///
/// See section 3.2 of the CoSERV draft for further details:
/// https://www.ietf.org/archive/id/draft-ietf-rats-coserv-01.html#name-artifacts
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    /// Source artifacts are those obtained from primary supply chain sources.
    Source,

    /// Collected artifacts are those obtained from secondary supply chain sources, such
    /// as aggregators.
    Collected,
}

/// This struct defines the categories of artifact that the service can provide for a given
/// CoSERV media type.
#[derive(Debug, Clone)]
pub struct Capability {
    /// A profiled CoSERV media type, e.g. `"application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\""`.
    pub media_type: Mime,

    /// Non-empty set containing either one or both artifact categories.
    pub artifact_support: HashSet<ArtifactType>,
}

/// The public verification keys that can be used to verify the signatures of CoSERV result sets.
///
/// A CoSERV service must include one or more verification keys.
///
/// Verification keys are of type [`coset::CoseKey`] in CBOR-formatted documents, and
/// [`jsonwebkey::JsonWebKey`] in JSON-formatted documents.
#[derive(Debug, Clone)]
pub enum ResultVerificationKey {
    /// An undefined stub value, used when initializing the structure. It is an error to attempt
    /// to serialize a discovery document with the verification key in this state.
    Undefined,

    /// COSE keys for use with CBOR-formatted discovery documents.
    Cose(Vec<CoseKey>),

    /// JOSE keys for use with JSON-formatted discovery documents.
    Jose(Vec<JsonWebKey>),
}

impl Capability {
    pub fn new() -> Capability {
        Capability {
            media_type: mime::TEXT_PLAIN,
            artifact_support: HashSet::new(),
        }
    }
}

impl Default for Capability {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for Capability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        let mut arsup = Vec::new();
        if self.artifact_support.contains(&ArtifactType::Collected) {
            arsup.push("collected")
        }
        if self.artifact_support.contains(&ArtifactType::Source) {
            arsup.push("source")
        }

        if is_human_readable {
            map.serialize_entry("media-type", &self.media_type.to_string())?;
            map.serialize_entry("artifact-support", &arsup)?;
        } else {
            // !is_human_readable
            map.serialize_entry(&1, &self.media_type.to_string())?;
            map.serialize_entry(&2, &arsup)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CapabilityVisitor {
            pub is_human_readable: bool,
        }

        impl<'de> Visitor<'de> for CapabilityVisitor {
            type Value = Capability;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a CBOR map or JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut capability = Capability::new();
                let mut arsup = Vec::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("media-type") => {
                                capability.media_type = map
                                    .next_value::<String>()?
                                    .parse()
                                    .map_err(de::Error::custom)?
                            }
                            Some("artifact-support") => arsup = map.next_value::<Vec<String>>()?,
                            Some(name) => {
                                return Err(de::Error::custom(Error::Coserv(
                                    CoservError::InvalidName(name.to_string()),
                                )))
                            }
                            None => break,
                        }
                    } else {
                        // !is_human_readable
                        match map.next_key::<i32>()? {
                            Some(1) => {
                                capability.media_type = map
                                    .next_value::<String>()?
                                    .parse()
                                    .map_err(de::Error::custom)?
                            }
                            Some(2) => arsup = map.next_value::<Vec<String>>()?,
                            Some(k) => {
                                return Err(de::Error::custom(Error::Coserv(
                                    CoservError::InvalidKey(k),
                                )))
                            }
                            None => break,
                        }
                    }
                }

                if arsup.contains(&"source".to_string()) {
                    capability.artifact_support.insert(ArtifactType::Source);
                }

                if arsup.contains(&"collected".to_string()) {
                    capability.artifact_support.insert(ArtifactType::Collected);
                }

                Ok(capability)
            }
        }

        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(CapabilityVisitor {
            is_human_readable: is_hr,
        })
    }
}

impl DiscoveryDocument {
    pub fn new() -> DiscoveryDocument {
        DiscoveryDocument {
            version: Version {
                major: 0,
                minor: 0,
                patch: 0,
                pre: Prerelease::EMPTY,
                build: BuildMetadata::EMPTY,
            },
            api_endpoints: HashMap::new(),
            capabilities: Vec::new(),
            result_verification_key: ResultVerificationKey::Undefined,
        }
    }

    /// Checks whether the discovery document is well-populated.
    ///
    /// A well-populated discovery document must have at least one API endpoint and at least
    /// one capability. Also, if any of the capabilities describe signed results (COSE), then
    /// the verification key must be present.
    pub fn validate(&self) -> Result<(), CoservError> {
        if self.api_endpoints.is_empty() {
            return Err(CoservError::ValidationError(
                "No API endpoints defined".to_string(),
            ));
        }

        if self.capabilities.is_empty() {
            return Err(CoservError::ValidationError("No capabilities".to_string()));
        }

        if self
            .capabilities
            .iter()
            .any(|c| c.artifact_support.is_empty())
        {
            return Err(CoservError::ValidationError(
                "Capability without any artifact types".to_string(),
            ));
        }

        if self
            .capabilities
            .iter()
            .any(|cap| cap.media_type.essence_str() == "application/coserv+cose")
        {
            match self.result_verification_key {
                ResultVerificationKey::Undefined => {
                    return Err(CoservError::ValidationError(
                        "Signed CoSERV requires a verification key".to_string(),
                    ));
                }
                _ => {}
            }
        }

        Ok(())
    }
}

impl Default for DiscoveryDocument {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for DiscoveryDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(S::Error::custom)?;

        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("version", &self.version.to_string())?;
            map.serialize_entry("capabilities", &self.capabilities)?;
            map.serialize_entry("api-endpoints", &self.api_endpoints)?;
            match &self.result_verification_key {
                ResultVerificationKey::Undefined => {
                    // Skip optional field
                }
                ResultVerificationKey::Cose(_) => {
                    return Err(S::Error::custom(Error::Coserv(
                        CoservError::WrongVerificationKeyType,
                    )))
                }
                ResultVerificationKey::Jose(keyset) => {
                    map.serialize_entry("result-verification-key", keyset)?
                }
            }
        } else {
            // !is_human_readable
            map.serialize_entry(&1, &self.version.to_string())?;
            map.serialize_entry(&2, &self.capabilities)?;
            map.serialize_entry(&3, &self.api_endpoints)?;
            match &self.result_verification_key {
                ResultVerificationKey::Undefined => {
                    // Skip optional field
                }
                ResultVerificationKey::Jose(_) => {
                    return Err(S::Error::custom(Error::Coserv(
                        CoservError::WrongVerificationKeyType,
                    )))
                }
                ResultVerificationKey::Cose(keyset) => {
                    let mut cbor_vec = Vec::new();
                    for k in keyset.iter() {
                        let v = k.clone().to_cbor_value().map_err(S::Error::custom)?;
                        cbor_vec.push(v);
                    }
                    map.serialize_entry(&4, &cbor_vec)?;
                }
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for DiscoveryDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DiscoveryDocumentVisitor {
            pub is_human_readable: bool,
        }

        impl<'de> Visitor<'de> for DiscoveryDocumentVisitor {
            type Value = DiscoveryDocument;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a CBOR map or JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut discovery_document = DiscoveryDocument::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("version") => {
                                discovery_document.version =
                                    Version::parse(&map.next_value::<String>()?)
                                        .map_err(de::Error::custom)?
                            }
                            Some("capabilities") => {
                                discovery_document.capabilities =
                                    map.next_value::<Vec<Capability>>()?
                            }
                            Some("api-endpoints") => {
                                discovery_document.api_endpoints =
                                    map.next_value::<HashMap<String, String>>()?
                            }
                            Some("result-verification-key") => {
                                discovery_document.result_verification_key =
                                    ResultVerificationKey::Jose(
                                        map.next_value::<Vec<JsonWebKey>>()?,
                                    )
                            }
                            Some(name) => {
                                return Err(de::Error::custom(Error::Coserv(
                                    CoservError::InvalidName(name.to_string()),
                                )))
                            }
                            None => break,
                        }
                    } else {
                        // !is_human_readable
                        match map.next_key::<i32>()? {
                            Some(1) => {
                                discovery_document.version =
                                    Version::parse(&map.next_value::<String>()?)
                                        .map_err(de::Error::custom)?
                            }
                            Some(2) => {
                                discovery_document.capabilities =
                                    map.next_value::<Vec<Capability>>()?
                            }
                            Some(3) => {
                                discovery_document.api_endpoints =
                                    map.next_value::<HashMap<String, String>>()?
                            }
                            Some(4) => {
                                let cbor_vec = map.next_value::<Vec<Value>>()?;
                                let mut cose_keys: Vec<CoseKey> = Vec::new();
                                for k in cbor_vec.iter() {
                                    let cose_key = CoseKey::from_cbor_value(k.clone())
                                        .map_err(de::Error::custom)?;
                                    cose_keys.push(cose_key);
                                }
                                discovery_document.result_verification_key =
                                    ResultVerificationKey::Cose(cose_keys);
                            }
                            Some(k) => {
                                return Err(de::Error::custom(Error::Coserv(
                                    CoservError::InvalidKey(k),
                                )))
                            }
                            None => break,
                        }
                    }
                }

                discovery_document.validate().map_err(de::Error::custom)?;

                Ok(discovery_document)
            }
        }

        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(DiscoveryDocumentVisitor {
            is_human_readable: is_hr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coserv_discovery_serde_round_trip_cbor() {
        let source_cbor: Vec<u8> = vec![
            0xbf, 0x01, 0x6a, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2d, 0x62, 0x65, 0x74, 0x61, 0x02,
            0x81, 0xbf, 0x01, 0x78, 0x48, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x73, 0x65, 0x72, 0x76, 0x2b, 0x63, 0x6f, 0x73, 0x65,
            0x3b, 0x20, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x3d, 0x22, 0x74, 0x61, 0x67,
            0x3a, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x32, 0x30,
            0x32, 0x35, 0x3a, 0x63, 0x63, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d,
            0x23, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x22, 0x02, 0x82, 0x69, 0x63, 0x6f, 0x6c, 0x6c,
            0x65, 0x63, 0x74, 0x65, 0x64, 0x66, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0xff, 0x03,
            0xa1, 0x75, 0x43, 0x6f, 0x53, 0x45, 0x52, 0x56, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
            0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x78, 0x2b, 0x2f, 0x65, 0x6e,
            0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x2d, 0x64, 0x69, 0x73, 0x74,
            0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f,
            0x73, 0x65, 0x72, 0x76, 0x2f, 0x7b, 0x71, 0x75, 0x65, 0x72, 0x79, 0x7d, 0x04, 0x81,
            0xa6, 0x01, 0x02, 0x02, 0x45, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x03, 0x26, 0x20, 0x01,
            0x21, 0x44, 0x1a, 0x2b, 0x3c, 0x4d, 0x22, 0x44, 0x5e, 0x6f, 0x7a, 0x8b, 0xff,
        ];

        let discovery_document: DiscoveryDocument =
            ciborium::from_reader(source_cbor.as_slice()).unwrap();

        // Example document version field should be semver("1.2.3-beta")
        assert_eq!(discovery_document.version.major, 1);
        assert_eq!(discovery_document.version.minor, 2);
        assert_eq!(discovery_document.version.patch, 3);
        assert_eq!(discovery_document.version.pre.to_string(), "beta");

        // There should be exactly 1 capability
        assert_eq!(discovery_document.capabilities.len(), 1);

        // The capability should support both source and collected artifacts for the example CoSERV profile in
        // the I-D.
        let capability = &discovery_document.capabilities[0];
        assert_eq!(
            capability.media_type.to_string(),
            "application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\""
        );
        assert_eq!(
            capability.artifact_support,
            HashSet::from([ArtifactType::Source, ArtifactType::Collected])
        );

        // There should be exactly one API endpoint for CoSERVRequestResponse
        assert_eq!(discovery_document.api_endpoints.len(), 1);
        assert_eq!(
            discovery_document
                .api_endpoints
                .get("CoSERVRequestResponse"),
            Some(&"/endorsement-distribution/v1/coserv/{query}".to_string())
        );

        // There should be exactly one verification key (COSE)
        if let ResultVerificationKey::Cose(keyset) =
            discovery_document.clone().result_verification_key
        {
            assert_eq!(keyset.len(), 1);
            let key = &keyset[0];

            // Just some light testing that we have the right key ID (kid), because CoseKey serde functionality is not
            // implemented in this crate. If the kid is right, then all the fields should be right.
            assert_eq!(key.key_id, vec![0xAB, 0xCD, 0xEF, 0x12, 0x34]);
        } else {
            // Unexpected key type if we get here.
            panic!("Expected a COSE key.");
        }

        // Write back out to CBOR
        let mut emitted_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&discovery_document, &mut emitted_cbor).unwrap();

        // We should end up with the same as the source bytes
        assert_eq!(emitted_cbor, source_cbor);
    }

    #[test]
    fn test_coserv_discovery_serde_round_trip_json() {
        let source_json = r#"
            {
              "version": "1.2.3-beta",
              "capabilities": [
                {
                  "media-type": "application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\"",
                  "artifact-support": [
                    "source",
                    "collected"
                  ]
                }
              ],
              "api-endpoints": {
                "CoSERVRequestResponse": "/endorsement-distribution/v1/coserv/{query}"
              },
              "result-verification-key": [
                {
                  "alg": "ES256",
                  "crv": "P-256",
                  "kty": "EC",
                  "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                  "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                  "kid": "key1"
                }
              ]
            }
        "#;

        let discovery_document: DiscoveryDocument = serde_json::from_str(source_json).unwrap();

        // Example document version field should be semver("1.2.3-beta")
        assert_eq!(discovery_document.version.major, 1);
        assert_eq!(discovery_document.version.minor, 2);
        assert_eq!(discovery_document.version.patch, 3);
        assert_eq!(discovery_document.version.pre.to_string(), "beta");

        // There should be exactly 1 capability
        assert_eq!(discovery_document.capabilities.len(), 1);

        // The capability should support both source and collected artifacts for the example CoSERV profile in
        // the I-D.
        let capability = &discovery_document.capabilities[0];
        assert_eq!(
            capability.media_type.to_string(),
            "application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\""
        );
        assert_eq!(
            capability.artifact_support,
            HashSet::from([ArtifactType::Source, ArtifactType::Collected])
        );

        // There should be exactly one API endpoint for CoSERVRequestResponse
        assert_eq!(discovery_document.api_endpoints.len(), 1);
        assert_eq!(
            discovery_document
                .api_endpoints
                .get("CoSERVRequestResponse"),
            Some(&"/endorsement-distribution/v1/coserv/{query}".to_string())
        );

        // There should be exactly one verification key (JOSE)
        if let ResultVerificationKey::Jose(keyset) =
            discovery_document.clone().result_verification_key
        {
            assert_eq!(keyset.len(), 1);
            let key = &keyset[0];

            // Just some light testing that we have the right key ID (kid), because JsonWebKey serde functionality is not
            // implemented in this crate. If the kid is right, then all the fields should be right.
            assert_eq!(key.key_id, Some("key1".to_string()));
        } else {
            // Unexpected key type if we get here.
            panic!("Expected a JOSE key.");
        }

        // Write it back out to JSON
        let emitted_json = serde_json::to_string(&discovery_document).unwrap();
        let expected_json = "{\"version\":\"1.2.3-beta\",\"capabilities\":[{\"media-type\":\"application/coserv+cose; profile=\\\"tag:vendor.com,2025:cc_platform#1.0.0\\\"\",\"artifact-support\":[\"collected\",\"source\"]}],\"api-endpoints\":{\"CoSERVRequestResponse\":\"/endorsement-distribution/v1/coserv/{query}\"},\"result-verification-key\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8\",\"y\":\"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4\",\"kid\":\"key1\",\"alg\":\"ES256\"}]}".to_string();
        assert_eq!(emitted_json, expected_json);
    }

    #[test]
    fn test_coserv_discovery_serde_round_trip_cbor_unsigned() {
        let source_cbor: Vec<u8> = vec![
            0xbf, 0x01, 0x6a, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2d, 0x62, 0x65, 0x74, 0x61, 0x02,
            0x81, 0xbf, 0x01, 0x78, 0x48, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x73, 0x65, 0x72, 0x76, 0x2b, 0x63, 0x62, 0x6f, 0x72,
            0x3b, 0x20, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x3d, 0x22, 0x74, 0x61, 0x67,
            0x3a, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x32, 0x30,
            0x32, 0x35, 0x3a, 0x63, 0x63, 0x5f, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d,
            0x23, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x22, 0x02, 0x81, 0x69, 0x63, 0x6f, 0x6c, 0x6c,
            0x65, 0x63, 0x74, 0x65, 0x64, 0xff, 0x03, 0xa1, 0x75, 0x43, 0x6f, 0x53, 0x45, 0x52,
            0x56, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
            0x73, 0x65, 0x78, 0x2b, 0x2f, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65,
            0x6e, 0x74, 0x2d, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f,
            0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x73, 0x65, 0x72, 0x76, 0x2f, 0x7b, 0x71,
            0x75, 0x65, 0x72, 0x79, 0x7d, 0xff,
        ];

        let discovery_document: DiscoveryDocument =
            ciborium::from_reader(source_cbor.as_slice()).unwrap();

        // We won't duplicate all the deserialization tests here. Just check that we have an undefined key, which is expected.
        match discovery_document.result_verification_key {
            ResultVerificationKey::Undefined => {}
            _ => panic!("The key should be undefined in this case"),
        };

        // Write back out to CBOR
        let mut emitted_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&discovery_document, &mut emitted_cbor).unwrap();

        // We should end up with the same as the source bytes
        assert_eq!(emitted_cbor, source_cbor);
    }

    #[test]
    fn test_coserv_discovery_serde_round_trip_json_unsigned() {
        let source_json = r#"
            {
              "version": "1.2.3-beta",
              "capabilities": [
                {
                  "media-type": "application/coserv+cbor; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\"",
                  "artifact-support": [
                    "source",
                    "collected"
                  ]
                }
              ],
              "api-endpoints": {
                "CoSERVRequestResponse": "/endorsement-distribution/v1/coserv/{query}"
              }
            }
        "#;

        let discovery_document: DiscoveryDocument = serde_json::from_str(source_json).unwrap();

        // We won't duplicate all the deserialization tests here. Just check that we have an undefined key, which is expected.
        match discovery_document.result_verification_key {
            ResultVerificationKey::Undefined => {}
            _ => panic!("The key should be undefined in this case"),
        };

        // Write it back out to JSON
        let emitted_json = serde_json::to_string(&discovery_document).unwrap();
        let expected_json = "{\"version\":\"1.2.3-beta\",\"capabilities\":[{\"media-type\":\"application/coserv+cbor; profile=\\\"tag:vendor.com,2025:cc_platform#1.0.0\\\"\",\"artifact-support\":[\"collected\",\"source\"]}],\"api-endpoints\":{\"CoSERVRequestResponse\":\"/endorsement-distribution/v1/coserv/{query}\"}}".to_string();
        assert_eq!(emitted_json, expected_json);
    }

    #[test]
    fn test_validate_ok() {
        let key_source = r#"{
                "alg": "ES256",
                "crv": "P-256",
                "kty": "EC",
                "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
                "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                "kid": "key1"
            }"#;
        ResultVerificationKey::Jose(vec![key_source.parse().unwrap()]);

        let doc = DiscoveryDocument {
            version: Version::parse("1.2.3-beta").unwrap(),
            capabilities: vec![Capability {
                media_type:
                    "application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\""
                        .to_string()
                        .parse()
                        .unwrap(),
                artifact_support: HashSet::from([ArtifactType::Source, ArtifactType::Collected]),
            }],
            api_endpoints: HashMap::from([(
                "CoSERVRequestResponse".to_string(),
                "/endorsement-distribution/v1/coserv/{query}".to_string(),
            )]),
            result_verification_key: ResultVerificationKey::Jose(vec![key_source.parse().unwrap()]),
        };

        assert!(doc.validate().is_ok());
    }

    #[test]
    fn test_validate_no_endpoints() {
        let doc = DiscoveryDocument {
            version: Version::parse("1.2.3-beta").unwrap(),
            capabilities: vec![Capability {
                media_type:
                    "application/coserv+bor; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\""
                        .to_string()
                        .parse()
                        .unwrap(),
                artifact_support: HashSet::from([ArtifactType::Source, ArtifactType::Collected]),
            }],
            api_endpoints: HashMap::new(),
            result_verification_key: ResultVerificationKey::Undefined,
        };

        assert_eq!(
            doc.validate().err().unwrap().to_string(),
            "Validation error: No API endpoints defined"
        );
    }

    #[test]
    fn test_validate_no_capabilities() {
        let doc = DiscoveryDocument {
            version: Version::parse("1.2.3-beta").unwrap(),
            capabilities: Vec::new(),
            api_endpoints: HashMap::from([(
                "CoSERVRequestResponse".to_string(),
                "/endorsement-distribution/v1/coserv/{query}".to_string(),
            )]),
            result_verification_key: ResultVerificationKey::Undefined,
        };

        assert_eq!(
            doc.validate().err().unwrap().to_string(),
            "Validation error: No capabilities"
        );
    }

    #[test]
    fn test_validate_no_verification_key() {
        let doc = DiscoveryDocument {
            version: Version::parse("1.2.3-beta").unwrap(),
            capabilities: vec![Capability {
                media_type:
                    "application/coserv+cose; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\""
                        .to_string()
                        .parse()
                        .unwrap(),
                artifact_support: HashSet::from([ArtifactType::Source, ArtifactType::Collected]),
            }],
            api_endpoints: HashMap::from([(
                "CoSERVRequestResponse".to_string(),
                "/endorsement-distribution/v1/coserv/{query}".to_string(),
            )]),
            result_verification_key: ResultVerificationKey::Undefined,
        };

        assert_eq!(
            doc.validate().err().unwrap().to_string(),
            "Validation error: Signed CoSERV requires a verification key"
        );
    }

    #[test]
    fn test_validate_capability_without_artifacts() {
        let doc = DiscoveryDocument {
            version: Version::parse("1.2.3-beta").unwrap(),
            capabilities: vec![Capability {
                media_type:
                    "application/coserv+bor; profile=\"tag:vendor.com,2025:cc_platform#1.0.0\""
                        .to_string()
                        .parse()
                        .unwrap(),
                artifact_support: HashSet::new(),
            }],
            api_endpoints: HashMap::from([(
                "CoSERVRequestResponse".to_string(),
                "/endorsement-distribution/v1/coserv/{query}".to_string(),
            )]),
            result_verification_key: ResultVerificationKey::Undefined,
        };

        assert_eq!(
            doc.validate().err().unwrap().to_string(),
            "Validation error: Capability without any artifact types"
        );
    }
}
