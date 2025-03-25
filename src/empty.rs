// SPDX-License-Identifier: MIT

use serde::{Deserialize, Deserializer};

pub trait Empty {
    fn is_empty(&self) -> bool;
}

pub fn empty_map_as_none<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Empty,
{
    let opt: Option<T> = Option::deserialize(deserializer)?;
    Ok(opt.filter(|value| !value.is_empty()))
}
