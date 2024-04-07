/// Errorwhile processing Linked Data Signatures.
#[derive(Debug, thiserror::Error)]
pub enum Error<DE> {
    /// The dataset raised an error.
    #[error("Error from dataset: {0}")]
    Dataset(#[from] DE),
    /// The graph was deemed too complex by the canonicalization algorithm.
    #[error("Toxic graph detected: {0}")]
    ToxicGraph(String),
    /// The canonicalization algorithm does not support this dataset.
    #[error("Unsupported feature: {0}")]
    Unsupported(String),
}
