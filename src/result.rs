// SPDX-License-Identifier: MIT

use crate::error::Error;

/// CoRIM Result
pub type Result<T> = std::result::Result<T, Error>;
