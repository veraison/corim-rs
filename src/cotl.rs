// SPDX-License-Identifier: MIT

use ciborium::tag::Accepted;
use derive_more::{Constructor, From};
use serde::{Deserialize, Serialize};

use crate::{OneOrMore, TagIdentityMap, ValidityMap};

// A Concise Trust List (CoTL) tag structure tagged with CBOR tag 507
///
/// CoTL tags provide a mechanism to maintain lists of trusted CoMID and CoSWID tags.
/// They can be used to establish trust relationships and manage tag distribution.
#[derive(Serialize, Deserialize, From, Constructor)]
pub struct TaggedConciseTlTag {
    #[serde(flatten)]
    pub field: Accepted<ConciseTlTag, 508>,
}

#[derive(Serialize, Deserialize, From, Constructor)]
#[repr(C)]
pub struct ConciseTlTag {
    /// Identity information for this trust list tag
    #[serde(rename = "tag-identity")]
    pub tag_identity: TagIdentityMap,

    /// List of trusted tags referenced by this trust list
    #[serde(rename = "tags-list")]
    pub tags_list: OneOrMore<TagIdentityMap>,

    /// Validity period for this trust list
    #[serde(rename = "tl-validity")]
    pub tl_validity: ValidityMap,
}
