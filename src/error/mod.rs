// SPDX-License-Identifier: MIT

mod comid;
mod core;
mod corim;
mod coswid;
mod cotl;
mod triples;

pub use comid::*;
pub use core::*;
pub use corim::*;
pub use coswid::*;
pub use cotl::*;
use derive_more::From;
pub use triples::*;

#[derive(Debug, From)]
pub enum Error {
    Comid(ComidError),
    Core(CoreError),
    Corim(CorimError),
    Coswid(CoswidError),
    Cotl(CotlError),
    Triples(TriplesError),
    Custom(String, String),
    Unknown,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Comid(err) => write!(f, "{err}"),
            Self::Core(err) => write!(f, "{err}"),
            Self::Corim(err) => write!(f, "{err}"),
            Self::Coswid(err) => write!(f, "{err}"),
            Self::Cotl(err) => write!(f, "{err}"),
            Self::Triples(err) => write!(f, "{err}"),
            Self::Unknown => write!(f, "unknown error encountered!"),
            Self::Custom(err, msg) => write!(f, "{} - {}", err, msg),
        }
    }
}
