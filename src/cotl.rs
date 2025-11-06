// SPDX-License-Identifier: MIT

use std::marker::PhantomData;

use derive_more::{Constructor, From};
use serde::{
    de::{self, Visitor},
    ser::SerializeMap,
    Deserialize, Serialize,
};

use crate::{
    generate_tagged, CotlError, IntegerTime, TagIdTypeChoice, TagIdentityMap, TagVersionType,
    ValidityMap,
};

generate_tagged!((
    508,
    TaggedConciseTlTag,
    ConciseTlTag<'a>,
    'a,
    "cotl",
    r#"A Concise Trust List (CoTL) tag structure tagged with CBOR tag 508

CoTL tags provide a mechanism to maintain lists of trusted CoMID and CoSWID tags. 
They can be used to establish trust relationships and manage tag distribution."#
));

#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConciseTlTag<'a> {
    /// Identity information for this trust list tag
    pub tag_identity: TagIdentityMap<'a>,

    /// List of trusted tags referenced by this trust list
    pub tags_list: Vec<TagIdentityMap<'a>>,

    /// Validity period for this trust list
    pub tl_validity: ValidityMap,
}

impl Serialize for ConciseTlTag<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("tag-identity", &self.tag_identity)?;
            map.serialize_entry("tags-list", &self.tags_list)?;
            map.serialize_entry("tl-validity", &self.tl_validity)?;
        } else {
            map.serialize_entry(&0, &self.tag_identity)?;
            map.serialize_entry(&1, &self.tags_list)?;
            map.serialize_entry(&2, &self.tl_validity)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ConciseTlTag<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ConciseTlTagVisitor<'a> {
            pub is_human_readable: bool,
            data: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for ConciseTlTagVisitor<'a> {
            type Value = ConciseTlTag<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing ConciseTlTag fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut builder = ConciseTlTagBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("tag-identity") => {
                                builder = builder.tag_identity(map.next_value::<TagIdentityMap>()?);
                            }
                            Some("tags-list") => {
                                builder =
                                    builder.tags_list(map.next_value::<Vec<TagIdentityMap>>()?);
                            }
                            Some("tl-validity") => {
                                builder = builder.tl_validity(map.next_value::<ValidityMap>()?);
                            }
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field name \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                builder = builder.tag_identity(map.next_value::<TagIdentityMap>()?);
                            }
                            Some(1) => {
                                builder =
                                    builder.tags_list(map.next_value::<Vec<TagIdentityMap>>()?);
                            }
                            Some(2) => {
                                builder = builder.tl_validity(map.next_value::<ValidityMap>()?);
                            }
                            Some(key) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field key \"{key}\""
                                )))
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(ConciseTlTagVisitor {
            is_human_readable: is_hr,
            data: PhantomData,
        })
    }
}

#[derive(Default)]
pub struct ConciseTlTagBuilder<'a> {
    pub tag_id: Option<TagIdTypeChoice<'a>>,
    pub tag_version: Option<TagVersionType>,
    pub tags_list: Option<Vec<TagIdentityMap<'a>>>,
    pub not_before: Option<IntegerTime>,
    pub not_after: Option<IntegerTime>,
}

impl<'a> ConciseTlTagBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tag_id(mut self, tag_id: TagIdTypeChoice<'a>) -> Self {
        self.tag_id = Some(tag_id);
        self
    }

    pub fn tag_version(mut self, tag_version: TagVersionType) -> Self {
        self.tag_version = Some(tag_version);
        self
    }

    pub fn tag_identity(mut self, tag_identity: TagIdentityMap<'a>) -> Self {
        self.tag_id = Some(tag_identity.tag_id);
        self.tag_version = tag_identity.tag_version;
        self
    }

    pub fn tags_list(mut self, tags_list: Vec<TagIdentityMap<'a>>) -> Self {
        self.tags_list = Some(tags_list);
        self
    }

    pub fn add_tag(mut self, tag: TagIdentityMap<'a>) -> Self {
        if let Some(tags_list) = &mut self.tags_list {
            tags_list.push(tag)
        } else {
            self.tags_list = Some(vec![tag])
        }
        self
    }

    pub fn not_before(mut self, not_before: IntegerTime) -> Self {
        self.not_before = Some(not_before);
        self
    }

    pub fn not_after(mut self, not_after: IntegerTime) -> Self {
        self.not_after = Some(not_after);
        self
    }

    pub fn tl_validity(mut self, tl_validity: ValidityMap) -> Self {
        self.not_before = tl_validity.not_before;
        self.not_after = Some(tl_validity.not_after);
        self
    }

    pub fn build(self) -> Result<ConciseTlTag<'a>, CotlError> {
        if self.tag_id.is_none() {
            return Err(CotlError::unset_mandatory_field("TagIdentityMap", "tag_id"));
        }

        if self.tags_list.is_none() {
            return Err(CotlError::unset_mandatory_field(
                "ConciseTlTag",
                "tags_list",
            ));
        } else if self.tags_list.as_ref().unwrap().is_empty() {
            return Err(CotlError::custom("empty tags_list"));
        }

        if self.not_after.is_none() {
            return Err(CotlError::unset_mandatory_field("ValidityMap", "not_after"));
        }

        Ok(ConciseTlTag {
            tag_identity: TagIdentityMap {
                tag_id: self.tag_id.unwrap(),
                tag_version: self.tag_version,
            },
            tags_list: self.tags_list.unwrap(),
            tl_validity: ValidityMap {
                not_before: self.not_before,
                not_after: self.not_after.unwrap(),
            },
        })
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(vec)]
mod test {
    use super::*;
    use crate::test::SerdeTestCase;

    #[test]
    fn test_cotl_serde() {
        let test_cases = vec! [
            SerdeTestCase {
                value: ConciseTlTagBuilder::new()
                    .tag_id("foo".into())
                    .tag_version(1.into())
                    .add_tag(
                        TagIdentityMap {
                            tag_id: TagIdTypeChoice::Tstr("bar".into()),
                            tag_version: None,
                        },
                    )
                    .not_after(1.into())
                    .build()
                    .unwrap(),
                expected_cbor: vec! [
                  0xbf, // map(indef) [concise-tl-tag]
                    0x00, // key: 0 [tag-identity]
                    0xbf, // value: map(indef) [tag-identity-map]
                      0x00, // key: 0 [tag-id]
                      0x63, // value: tstr(3)
                        0x66, 0x6f, 0x6f, // "foo"
                      0x01, // key: 1 [tag-version]
                      0x01, // value: 1
                    0xff, // break
                    0x01, // key: 1 [tags-list]
                    0x81, // value: array(1)
                      0xbf, // map(indef) [tag-identity-map]
                        0x00, // key: 0 [tag-id]
                        0x63, // value: tstr(3)
                          0x62, 0x61, 0x72, // "bar"
                      0xff, // break
                    0x02, // key: 2 [tl-validity]
                    0xa1, // value: map(1) [validity-map]
                      0x01, // key: 1 [not-after]
                      0xc1, // value: tag(1) [time]
                        0x01,  // 1
                  0xff, // break
                ],
                expected_json: r#"{"tag-identity":{"tag-id":"foo","tag-version":1},"tags-list":[{"tag-id":"bar"}],"tl-validity":{"not-after":{"type":"time","value":1}}}"#,
            },
        ];

        for tc in test_cases.into_iter() {
            tc.run();
        }
    }
}
