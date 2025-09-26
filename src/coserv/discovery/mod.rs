// SPDX-License-Identifier: MIT

//! CoSERV Discovery Document implementation

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

#[derive(Debug, Clone)]
pub struct DiscoveryDocument {
    pub version: Version,
    pub capabilities: Vec<Capability>,
    pub api_endpoints: HashMap<String, String>,
    pub result_verification_key: ResultVerificationKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    Source,
    Collected,
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub media_type: Mime,
    pub artifact_support: HashSet<ArtifactType>,
}

#[derive(Debug, Clone)]
pub enum ResultVerificationKey {
    Undefined,
    Cose(Vec<CoseKey>),
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
                                capability.media_type = map.next_value::<String>()?.parse().unwrap()
                            }
                            Some("artifact-support") => arsup = map.next_value::<Vec<String>>()?,
                            Some(name) => panic!("Invalid JSON key: {}", name),
                            None => break,
                        }
                    } else {
                        // !is_human_readable
                        match map.next_key::<i32>()? {
                            Some(1) => {
                                capability.media_type = map.next_value::<String>()?.parse().unwrap()
                            }
                            Some(2) => arsup = map.next_value::<Vec<String>>()?,
                            Some(k) => panic!("Invalid CBOR key: {}", k),
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
}

impl Serialize for DiscoveryDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("version", &self.version.to_string())?;
            map.serialize_entry("capabilities", &self.capabilities)?;
            map.serialize_entry("api-endpoints", &self.api_endpoints)?;
            match &self.result_verification_key {
                ResultVerificationKey::Undefined => panic!("There is no key set to serialize"),
                ResultVerificationKey::Cose(_) => {
                    panic!("Trying to serialize a COSE key set as JSON")
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
                ResultVerificationKey::Undefined => panic!("There is no key set to serialize"),
                ResultVerificationKey::Jose(_) => {
                    panic!("Trying to serialize a JSON key set as CBOR")
                }
                ResultVerificationKey::Cose(keyset) => {
                    let mut cbor_vec = Vec::new();
                    for k in keyset.iter() {
                        let v = k.clone().to_cbor_value().unwrap();
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
                                    Version::parse(&map.next_value::<String>()?).unwrap()
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
                            Some(name) => panic!("Invalid JSON key: {}", name),
                            None => break,
                        }
                    } else {
                        // !is_human_readable
                        match map.next_key::<i32>()? {
                            Some(1) => {
                                discovery_document.version =
                                    Version::parse(&map.next_value::<String>()?).unwrap()
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
                                    let cose_key = CoseKey::from_cbor_value(k.clone()).unwrap();
                                    cose_keys.push(cose_key);
                                }
                                discovery_document.result_verification_key =
                                    ResultVerificationKey::Cose(cose_keys);
                            }
                            Some(k) => panic!("Invalid CBOR key: {}", k),
                            None => break,
                        }
                    }
                }

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
    use serde_json::Value;

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
            0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x78, 0x2a, 0x65, 0x6e, 0x64,
            0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x2d, 0x64, 0x69, 0x73, 0x74, 0x72,
            0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x73,
            0x65, 0x72, 0x76, 0x2f, 0x7b, 0x71, 0x75, 0x65, 0x72, 0x79, 0x7d, 0x04, 0x81, 0xa6,
            0x01, 0x02, 0x02, 0x45, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x03, 0x26, 0x20, 0x01, 0x21,
            0x44, 0x1a, 0x2b, 0x3c, 0x4d, 0x22, 0x44, 0x5e, 0x6f, 0x7a, 0x8b, 0xff,
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
            Some(&"endorsement-distribution/v1/coserv/{query}".to_string())
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
            assert!(false);
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
                "CoSERVRequestResponse": "endorsement-distribution/v1/coserv/{query}"
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
            Some(&"endorsement-distribution/v1/coserv/{query}".to_string())
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
            assert!(false);
        }

        // Write it back out to JSON
        let emitted_json = serde_json::to_string(&discovery_document).unwrap();
        let expected_json = "{\"version\":\"1.2.3-beta\",\"capabilities\":[{\"media-type\":\"application/coserv+cose; profile=\\\"tag:vendor.com,2025:cc_platform#1.0.0\\\"\",\"artifact-support\":[\"collected\",\"source\"]}],\"api-endpoints\":{\"CoSERVRequestResponse\":\"endorsement-distribution/v1/coserv/{query}\"},\"result-verification-key\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8\",\"y\":\"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4\",\"kid\":\"key1\",\"alg\":\"ES256\"}]}".to_string();
        assert_eq!(emitted_json, expected_json);
    }
}
