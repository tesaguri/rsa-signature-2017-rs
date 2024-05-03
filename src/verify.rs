use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::Sha256;
use sophia_api::dataset::SetDataset;

use crate::common::create_verify_hash;
use crate::error::DatasetError;

/// Error while verifying a signature.
#[derive(Debug, thiserror::Error)]
pub enum Error<DE, OE = DE> {
    /// The input dataset raised an error.
    #[error("Error from dataset: {0}")]
    Dataset(DatasetError<DE>),
    /// The options dataset raised an error.
    #[error("Error from dataset: {0}")]
    Options(DatasetError<OE>),
    /// The signature didn't verify.
    #[error("Signature didn't verify: {0}")]
    Verification(rsa::Error),
}

/// Verifies the `signature` as an `RsaSignature2017` for the given `dataset` and the signature
/// `options`.
pub fn verify_rsa_signature_2017<D, O>(
    dataset: &D,
    options: &O,
    key: &RsaPublicKey,
    signature: &[u8],
) -> Result<(), Error<D::Error, O::Error>>
where
    D: SetDataset,
    O: SetDataset,
{
    let to_be_verified = create_verify_hash(dataset, options)
        .map_err(|e| e.either(Error::Dataset, Error::Options))?;
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &to_be_verified, signature)
        .map_err(Error::Verification)
}
