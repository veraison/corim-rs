// SPDX-License-Identifier: MIT

use derive_more::{Constructor, From};
use serde::{Deserialize, Serialize};

use crate::{generate_tagged, TagIdentityMap, ValidityMap};

generate_tagged!((
    508,
    TaggedConciseTlTag,
    ConciseTlTag<'a>,
    'a,
    r#"A Concise Trust List (CoTL) tag structure tagged with CBOR tag 507

CoTL tags provide a mechanism to maintain lists of trusted CoMID and CoSWID tags. 
They can be used to establish trust relationships and manage tag distribution."#
));

#[derive(
    Debug, Serialize, Deserialize, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[repr(C)]
pub struct ConciseTlTag<'a> {
    /// Identity information for this trust list tag
    #[serde(rename = "0")]
    pub tag_identity: TagIdentityMap<'a>,

    /// List of trusted tags referenced by this trust list
    #[serde(rename = "1")]
    pub tags_list: Vec<TagIdentityMap<'a>>,

    /// Validity period for this trust list
    #[serde(rename = "2")]
    pub tl_validity: ValidityMap,
}
