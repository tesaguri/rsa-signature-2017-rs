#![warn(rust_2018_idioms)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(not(feature = "std"))]
compile_error!(concat!(
    "no_std support of `rsa-signature-2017` crate is not implemented (just yet!). ",
    "Please enable `std` crate feature for now"
));

#[cfg(feature = "serde")]
pub mod serde;

mod error;
mod sign;
mod signature_options;
mod util;

pub use self::error::Error;
pub use self::sign::{SignOptions, Signature, SignatureType};
