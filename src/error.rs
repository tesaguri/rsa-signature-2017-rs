use std::error;

use sophia_c14n::C14nError;

/// Error while canonicalizing a dataset.
#[derive(Debug, thiserror::Error)]
pub enum DatasetError<DE> {
    /// The dataset raised an error.
    #[error("Error from dataset: {0}")]
    Dataset(DE),
    /// The graph was deemed too complex by the canonicalization algorithm.
    #[error("Toxic graph detected: {0}")]
    ToxicGraph(String),
    /// The canonicalization algorithm does not support this dataset.
    #[error("Unsupported feature: {0}")]
    Unsupported(String),
}

impl<DE: error::Error> DatasetError<DE> {
    pub(crate) fn from_c14n_error(e: C14nError<DE>) -> Self {
        match e {
            C14nError::Dataset(e) => DatasetError::Dataset(e),
            // We only write canonized outputs to `DigestWrite`, which never fails.
            C14nError::Io(_) => unreachable!(),
            C14nError::ToxicGraph(e) => DatasetError::ToxicGraph(e),
            C14nError::Unsupported(e) => DatasetError::Unsupported(e),
        }
    }
}
