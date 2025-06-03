// SPDX-License-Identifier: MIT

use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

pub(crate) struct SerdeTestCase<T> {
    pub(crate) value: T,
    pub(crate) expected_json: &'static str,
    pub(crate) expected_cbor: Vec<u8>,
}

impl<'de, T> SerdeTestCase<T>
where
    T: Debug + Serialize + DeserializeOwned + Eq,
{
    pub(crate) fn run(&self) {
        let mut actual_cbor: Vec<u8> = vec![];
        ciborium::into_writer(&self.value, &mut actual_cbor).unwrap();

        assert_eq!(actual_cbor, self.expected_cbor);

        let value_de: T = ciborium::from_reader(actual_cbor.as_slice()).unwrap();

        assert_eq!(value_de, self.value);

        let actual_json = serde_json::to_string(&self.value).unwrap();

        assert_eq!(actual_json, self.expected_json);

        let value_de: T = serde_json::from_str(actual_json.as_str()).unwrap();

        assert_eq!(value_de, self.value);
    }
}
