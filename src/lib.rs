//! A library for signing and verifying signatures with (a variant of) the `RsaSignature2017`
//! signature suite of the [Linked Data Signatures] specification.
//!
//! ## Caveats
//!
//! Strictly speaking, the library uses the RDFC 1.0 canonicalization algorithm instead of the
//! GCA2015 algorithm (aka. URDNA2015), which the original `RsaSignature2017` algorithm uses.
//!
//! The difference between these algorithms is handling of some control characters. So, please just
//! don't give it those characters, thanks!
//!
//!
//! [Linked Data Signatures]: <https://github.com/w3c-ccg/ld-signatures/blob/d0af56856684924156a94838f9482a27766bb2be/index.html>

#![warn(rust_2018_idioms)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(not(feature = "std"))]
compile_error!(concat!(
    "no_std support of `rsa-signature-2017` crate is not implemented (just yet!). ",
    "Please enable `std` crate feature for now"
));

#[macro_use]
mod util;

pub mod error;
#[cfg(feature = "json-ld")]
pub mod json_ld;
#[cfg(feature = "serde")]
pub mod serde;
pub mod sign;
pub mod verify;

mod common;

pub use self::sign::{sign_rsa_signature_2017, SignOptions, Signature};
pub use self::verify::verify_rsa_signature_2017;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize))]
#[non_exhaustive]
pub enum SignatureType {
    RsaSignature2017,
}

#[cfg(test)]
mod tests {
    use rsa::{BigUint, RsaPrivateKey};
    use sophia_iri::Iri;

    use crate::common::SignatureOptions;
    use crate::util::test::parse_nq;
    use crate::SignOptions;

    use super::*;

    #[test]
    fn roundtrip() {
        const DATASET: &str = r#"
            _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Note> .
            _:b0 <https://www.w3.org/ns/activitystreams#content> "Hello, world!" .
        "#;
        const N: &[u8] = b"\x00\xa7\x73\xe0\x0f\x71\x95\xeb\xd4\xcb\x36\x25\x2f\x4b\x25\xed\x6e\x3f\x37\xdb\x8a\x3d\x2b\x61\x67\xf2\xea\xe4\x98\x5b\xdb\x56\x5b\x1a\x2c\xa2\xaf\xf7\x65\xcf\xdf\xb5\xa1\x61\x76\x63\x76\x9f\xd2\x64\x18\x05\xd2\x32\x7e\x52\x51\x31\xb2\x8d\x8b\x5a\xa4\x01\x29";
        const D: &[u8] = b"\x00\x8c\x32\x92\x07\x9c\x1b\xdf\x65\x3b\xf6\x4b\x4f\xbb\x65\x37\xd2\xb4\x0f\x3a\x3a\x15\x58\xba\xa6\xe3\x55\x12\xab\x15\x4d\x20\x90\xae\x53\x71\x9a\xc6\x8b\xd5\xd1\xaa\x94\x63\xbb\x9e\xe2\x72\x90\x10\xb4\x14\xf7\x86\xc4\x03\xaa\x6f\x28\x7d\x1e\x7b\xc7\xa4\x61";
        const P: &[u8] = b"\x00\xde\x79\xa1\x11\xd2\xac\x22\x86\xc7\xdc\xb2\x03\x01\x05\xcc\x73\x9e\x17\x3c\xef\x9d\x31\x13\x39\x9f\x81\xe6\x68\x85\xdc\xe7\x0d";
        const Q: &[u8] = b"\x00\xc0\xaf\xa8\x21\x8b\x40\xca\x59\xd5\x00\xd0\x55\x68\xf6\x7f\x35\xd0\x29\xfb\xb6\xb3\x38\x33\xe4\x81\xd6\x6b\x5d\x93\x6b\xfb\x8d";

        let dataset = parse_nq(DATASET);
        let key = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(N),
            BigUint::from(65537u64),
            BigUint::from_bytes_be(D),
            vec![BigUint::from_bytes_be(P), BigUint::from_bytes_be(Q)],
        )
        .unwrap();
        let creator = Iri::new("https://example.com/#me").unwrap();

        let signature = <SignOptions<'_, '_>>::new()
            .created("2024-01-01T00:00:00Z")
            .nonce(Some("deadbeef12345678"))
            .sign_rsa_signature_2017(&dataset, &key, creator)
            .unwrap();

        let options = SignatureOptions {
            created: &signature.created,
            creator: signature.creator,
            domain: signature.domain,
            nonce: signature.nonce.as_deref(),
        };
        verify_rsa_signature_2017(
            &dataset,
            &options.to_dataset(),
            key.as_ref(),
            &signature.signature_value,
        )
        .unwrap();
    }
}
