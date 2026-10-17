//! Core library for `stash`: the encrypted vault format and its operations.
//!
//! See `docs/threat-model.md` in the repository for the security design.

pub mod crypto;
mod error;
pub mod generate;
pub mod item;
mod name;
pub mod otp;
pub mod reference;
mod vault;

pub use crypto::KdfParams;
pub use error::Error;
pub use item::{Field, FieldKind, Item, Kind};
pub use name::validate_name;
pub use vault::Vault;

pub type Result<T, E = Error> = std::result::Result<T, E>;
