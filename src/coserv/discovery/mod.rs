// SPDX-License-Identifier: MIT

//! CoSERV Discovery Document implementation

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
    pub api_endpoints: Vec<Endpoint>,
    pub result_verification_key: ResultVerificationKey,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub name: String,
    pub path: String,
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

impl Endpoint {
    pub fn new() -> Endpoint {
        Endpoint {
            name: "".to_string(),
            path: "".to_string(),
        }
    }
}

impl Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("name", &self.name)?;
            map.serialize_entry("path", &self.path)?;
        } else {
            // !is_human_readable
            map.serialize_entry(&1, &self.name)?;
            map.serialize_entry(&2, &self.path)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(EndpointVisitor {
            is_human_readable: is_hr,
        })
    }
}

struct EndpointVisitor {
    pub is_human_readable: bool,
}

impl<'de> Visitor<'de> for EndpointVisitor {
    type Value = Endpoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CBOR map or JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut endpoint = Endpoint::new();

        loop {
            if self.is_human_readable {
                match map.next_key::<&str>()? {
                    Some("name") => endpoint.name = map.next_value::<String>()?,
                    Some("path") => endpoint.path = map.next_value::<String>()?,
                    Some(name) => panic!("Invalid JSON key: {}", name),
                    None => break,
                }
            } else {
                // !is_human_readable
                match map.next_key::<i32>()? {
                    Some(1) => endpoint.name = map.next_value::<String>()?,
                    Some(2) => endpoint.path = map.next_value::<String>()?,
                    Some(k) => panic!("Invalid CBOR key: {}", k),
                    None => break,
                }
            }
        }

        Ok(endpoint)
    }
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
        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(CapabilityVisitor {
            is_human_readable: is_hr,
        })
    }
}

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
                    Some(1) => capability.media_type = map.next_value::<String>()?.parse().unwrap(),
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
            api_endpoints: Vec::new(),
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
        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(DiscoveryDocumentVisitor {
            is_human_readable: is_hr,
        })
    }
}

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
                        discovery_document.capabilities = map.next_value::<Vec<Capability>>()?
                    }
                    Some("api-endpoints") => {
                        discovery_document.api_endpoints = map.next_value::<Vec<Endpoint>>()?
                    }
                    Some("result-verification-key") => {
                        discovery_document.result_verification_key =
                            ResultVerificationKey::Jose(map.next_value::<Vec<JsonWebKey>>()?)
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
                        discovery_document.capabilities = map.next_value::<Vec<Capability>>()?
                    }
                    Some(3) => {
                        discovery_document.api_endpoints = map.next_value::<Vec<Endpoint>>()?
                    }
                    Some(4) => {
                        let cbor_vec = map.next_value::<Vec<Value>>()?;
                        let mut cose_keys: Vec<CoseKey> = Vec::new();
                        for k in cbor_vec.iter() {
                            let cose_key = CoseKey::from_cbor_value(k.clone()).unwrap();
                            cose_keys.push(cose_key);
                        }
                        discovery_document.result_verification_key = ResultVerificationKey::Cose(cose_keys);
                    }
                    Some(k) => panic!("Invalid CBOR key: {}", k),
                    None => break,
                }
            }
        }

        Ok(discovery_document)
    }
}
