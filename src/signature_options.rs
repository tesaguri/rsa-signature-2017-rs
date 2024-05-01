use std::io::Write;
use std::time::SystemTime;

use sha2::digest::generic_array::GenericArray;
use sha2::digest::OutputSizeUser;
use sha2::{Digest, Sha256};
use sophia_api::dataset::{MutableDataset, SetDataset};
use sophia_api::term::{BnodeId, SimpleTerm};
use sophia_api::MownStr;
use sophia_c14n::{rdfc10, C14nError};
use sophia_inmem::dataset::LightDataset;
use sophia_iri::{Iri, IriRef};

use crate::util::{format_iso8601_time, DigestWrite};
use crate::Error;

pub struct SignatureOptions<'a> {
    pub created: Option<&'a str>,
    pub creator: Iri<&'a str>,
    pub domain: Option<&'a str>,
    pub nonce: Option<&'a str>,
}

impl<'a> SignatureOptions<'a> {
    /// Performs the Create Verify Hash Algorithm of the spec and returns the resulting `output` and
    /// `created` variables from it.
    pub fn create_verify_hash<D>(
        &self,
        dataset: &D,
    ) -> Result<
        (
            GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
            Option<String>,
        ),
        Error<D::Error>,
    >
    where
        D: SetDataset,
    {
        // A hasher for the `output` variable of the Algorithm's spec.
        let mut to_be_signed = Sha256::default();
        // A hasher to be haphazardly reused throughout the method just to be stingy.
        let mut hasher = Sha256::default();

        // Separating to another method to reduce monomorphization bloat with `D`.
        let created = self.hash_canonicalized_options_document(&mut to_be_signed, &mut hasher);

        if let Err(e) = rdfc10::normalize(dataset, DigestWrite::new(&mut hasher)) {
            match e {
                C14nError::Dataset(e) => return Err(Error::Dataset(e)),
                // We only write canonized outputs to `DigestWrite`, which never fails.
                C14nError::Io(_) => unreachable!(),
                C14nError::ToxicGraph(e) => return Err(Error::ToxicGraph(e)),
                C14nError::Unsupported(e) => return Err(Error::Unsupported(e)),
            }
        }

        Ok((self.finalize(to_be_signed, hasher), created))
    }

    fn hash_canonicalized_options_document(
        &self,
        to_be_signed: &mut Sha256,
        hasher: &mut Sha256,
    ) -> Option<String> {
        let created = {
            let (options, created) = self.to_dataset();
            rdfc10::normalize(&options, DigestWrite::new(hasher)).unwrap();
            created
        };

        let output = hasher.finalize_reset();
        write!(DigestWrite::new(to_be_signed), "{}", hex::encode(&output)).unwrap();

        created
    }

    fn finalize(
        &self,
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

    fn to_dataset(&self) -> (LightDataset, Option<String>) {
        const CREATED: MownStr<'_> = MownStr::from_str("http://purl.org/dc/terms/created");
        const CREATOR: MownStr<'_> = MownStr::from_str("http://purl.org/dc/terms/creator");
        const DOMAIN: MownStr<'_> = MownStr::from_str("https://w3id.org/security#domain");
        const NONCE: MownStr<'_> = MownStr::from_str("https://w3id.org/security#nonce");
        const DATETIME: MownStr<'_> =
            MownStr::from_str("http://www.w3.org/2001/XMLSchema#dateTime");
        const ID: MownStr<'_> = MownStr::from_str("b0");

        let mut created_owned = None;
        let created = if let Some(created) = self.created {
            created
        } else {
            created_owned = Some(format_iso8601_time(SystemTime::now()));
            created_owned.as_ref().unwrap()
        };
        let created = SimpleTerm::LiteralDatatype(created.into(), IriRef::new_unchecked(DATETIME));

        let mut ret = LightDataset::new();

        // Unwrapping is fine because `LightDataset::insert` returns error only when too many terms
        // are inserted.
        ret.insert(
            BnodeId::new_unchecked(ID),
            IriRef::new_unchecked(CREATED),
            created,
            None::<&'static SimpleTerm<'_>>,
        )
        .unwrap();
        ret.insert(
            BnodeId::new_unchecked(ID),
            IriRef::new_unchecked(CREATOR),
            self.creator,
            None::<&'static SimpleTerm<'_>>,
        )
        .unwrap();
        if let Some(domain) = self.domain {
            ret.insert(
                BnodeId::new_unchecked(ID),
                IriRef::new_unchecked(DOMAIN),
                domain,
                None::<&'static SimpleTerm<'_>>,
            )
            .unwrap();
        }
        if let Some(nonce) = self.nonce {
            ret.insert(
                BnodeId::new_unchecked(ID),
                IriRef::new_unchecked(NONCE),
                nonce,
                None::<&'static SimpleTerm<'_>>,
            )
            .unwrap();
        }

        (ret, created_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::test::parse_nq;

    #[test]
    fn to_dataset() {
        let options = SignatureOptions {
            created: Some("2024-01-01T00:00:00Z"),
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

        assert_eq_dataset!(options.to_dataset().0, parse_nq(EXPECTED));
    }

    #[test]
    fn create_verify_hash() {
        let options = SignatureOptions {
            created: Some("2024-01-01T00:00:00Z"),
            creator: Iri::new("https://example.com/users/1#main-key").unwrap(),
            domain: Some("https://w3id.org/security#assertionMethod"),
            nonce: Some("deadbeef12345678"),
        };

        const DATASET: &str = r#"
            _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Note> .
            _:b0 <https://www.w3.org/ns/activitystreams#content> "Hello, world!" .
        "#;

        assert_eq!(
            hex::encode(&options.create_verify_hash(&parse_nq(DATASET)).unwrap().0).to_string(),
            "b09ad7a64f32905af0ddada6082d9e7af89a001dc6d03b62d983036c9f98161b"
        );
    }
}
