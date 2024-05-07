pub mod consts;

use std::io::Write;

use either::Either;
use sha2::digest::generic_array::GenericArray;
use sha2::digest::OutputSizeUser;
use sha2::{Digest, Sha256};
use sophia_api::dataset::{MutableDataset, SetDataset};
use sophia_api::term::{BnodeId, SimpleTerm};
use sophia_api::MownStr;
use sophia_c14n::rdfc10;
use sophia_inmem::dataset::LightDataset;
use sophia_iri::{Iri, IriRef};

use crate::error::DatasetError;
use crate::util::DigestWrite;

pub struct SignatureOptions<'a> {
    pub created: &'a str,
    pub creator: Iri<&'a str>,
    pub domain: Option<&'a str>,
    pub nonce: Option<&'a str>,
}

impl<'a> SignatureOptions<'a> {
    pub fn to_dataset(&self) -> LightDataset {
        const ID: MownStr<'_> = MownStr::from_str("b0");

        let mut ret = LightDataset::new();

        // Unwrapping is fine because `LightDataset::insert` returns error only when too many terms
        // are inserted.
        ret.insert(
            BnodeId::new_unchecked(ID),
            IriRef::new_unchecked(consts::CREATED),
            SimpleTerm::LiteralDatatype(
                self.created.into(),
                IriRef::new_unchecked(consts::DATETIME),
            ),
            None::<&'static SimpleTerm<'_>>,
        )
        .unwrap();
        ret.insert(
            BnodeId::new_unchecked(ID),
            IriRef::new_unchecked(consts::CREATOR),
            self.creator,
            None::<&'static SimpleTerm<'_>>,
        )
        .unwrap();
        if let Some(domain) = self.domain {
            ret.insert(
                BnodeId::new_unchecked(ID),
                IriRef::new_unchecked(consts::DOMAIN),
                domain,
                None::<&'static SimpleTerm<'_>>,
            )
            .unwrap();
        }
        if let Some(nonce) = self.nonce {
            ret.insert(
                BnodeId::new_unchecked(ID),
                IriRef::new_unchecked(consts::NONCE),
                nonce,
                None::<&'static SimpleTerm<'_>>,
            )
            .unwrap();
        }

        ret
    }
}

/// Performs the Create Verify Hash Algorithm of the spec and returns its output.
pub fn create_verify_hash<D, O>(
    dataset: &D,
    options: &O,
) -> Result<
    GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
    Either<DatasetError<D::Error>, DatasetError<O::Error>>,
>
where
    D: SetDataset,
    O: SetDataset,
{
    // A hasher for the `output` variable of the Algorithm's spec.
    let mut to_be_signed = Sha256::default();
    // A hasher to be haphazardly reused throughout the method just to be stingy.
    let mut hasher = Sha256::default();

    // Separating to another function to reduce monomorphization bloat with `D`.
    hash_canonicalized_options_document(options, &mut to_be_signed, &mut hasher)
        .map_err(Either::Right)?;

    fn hash_canonicalized_options_document<O>(
        options: &O,
        to_be_signed: &mut Sha256,
        hasher: &mut Sha256,
    ) -> Result<(), DatasetError<O::Error>>
    where
        O: SetDataset,
    {
        rdfc10::normalize(options, DigestWrite::new(hasher))
            .map_err(DatasetError::from_c14n_error)?;
        let output = hasher.finalize_reset();
        write!(DigestWrite::new(to_be_signed), "{}", hex::encode(&output)).unwrap();
        Ok(())
    }

    rdfc10::normalize(dataset, DigestWrite::new(&mut hasher))
        .map_err(|e| Either::Left(DatasetError::from_c14n_error(e)))?;

    return Ok(finalize(to_be_signed, hasher));

    fn finalize(
        mut to_be_signed: Sha256,
        document_hasher: Sha256,
    ) -> GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize> {
        let mut digest = document_hasher.finalize();
        write!(
            DigestWrite::new(&mut to_be_signed),
            "{}",
            hex::encode(&digest)
        )
        .unwrap();

        to_be_signed.finalize_into(&mut digest);

        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::test::parse_nq;

    #[test]
    fn options_to_dataset() {
        let options = SignatureOptions {
            created: "2024-01-01T00:00:00Z",
            creator: Iri::new("https://example.com/users/1#main-key").unwrap(),
            domain: Some("https://w3id.org/security#assertionMethod"),
            nonce: Some("deadbeef12345678"),
        };

        const EXPECTED: &str = r#"
            _:b0 <http://purl.org/dc/terms/created> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            _:b0 <http://purl.org/dc/terms/creator> <https://example.com/users/1#main-key> .
            _:b0 <https://w3id.org/security#domain> "https://w3id.org/security#assertionMethod" .
            _:b0 <https://w3id.org/security#nonce> "deadbeef12345678" .
        "#;

        assert_eq_dataset!(options.to_dataset(), parse_nq(EXPECTED));
    }

    #[test]
    fn create_verify_hash() {
        let options = SignatureOptions {
            created: "2024-01-01T00:00:00Z",
            creator: Iri::new("https://example.com/users/1#main-key").unwrap(),
            domain: Some("https://w3id.org/security#assertionMethod"),
            nonce: Some("deadbeef12345678"),
        };

        const DATASET: &str = r#"
            _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Note> .
            _:b0 <https://www.w3.org/ns/activitystreams#content> "Hello, world!" .
        "#;

        assert_eq!(
            hex::encode(
                super::create_verify_hash(&parse_nq(DATASET), &options.to_dataset()).unwrap()
            )
            .to_string(),
            "b09ad7a64f32905af0ddada6082d9e7af89a001dc6d03b62d983036c9f98161b"
        );
    }
}
