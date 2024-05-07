mod context;

use core::fmt::{self, Display, Formatter};
use core::future;
use core::marker::PhantomData;

use json_ld::future::BoxFuture;
use json_ld::{Loader, RemoteDocument};
use rdf_types::IriVocabularyMut;
use sophia_jsonld::vocabulary::ArcIri;

/// A JSON-LD document [`Loader`] implementation that treats some well-known context IRIs as
/// already resolved.
///
/// The following is the list of the <q>well-known</q> IRIs:
///
/// - `https?://w3id.org/identity/v1`
/// - `https?://w3id.org/security/v1`
///
/// The former IRI was used by examples in the Linked Signatures spec and is commonly used by
/// existing implementations. But the domain the IRI redirects to has later been abandoned,
/// rendering many Linked Data Signatures documents unable to verify without the cached context.
/// The former content of the IRI is available at
/// <https://github.com/web-payments/web-payments.org/blob/2faef4c/contexts/identity-v1.jsonld>.
///
/// The latter IRI is the Security Vocabulary context, which also includes the term definitions used
/// by Linked Data Signatures and is alive as of this writing. This context is fairly stable and we
/// consider the context to be safe to cache.
pub struct PreloadedLoader<I = ArcIri> {
    marker: PhantomData<fn() -> I>,
}

#[derive(Debug)]
pub struct NotPreloaded<I> {
    iri: I,
}

impl<I> PreloadedLoader<I>
where
    I: Clone + Send,
{
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I> Default for PreloadedLoader<I>
where
    I: Clone + Send,
{
    fn default() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<I> Loader<I, locspan::Location<I>> for PreloadedLoader<I>
where
    I: Clone + Send,
{
    type Output = json_syntax::Value<locspan::Location<I>>;
    type Error = NotPreloaded<I>;

    fn load_with<'a>(
        &'a mut self,
        vocabulary: &mut impl IriVocabularyMut<Iri = I>,
        url: I,
    ) -> BoxFuture<'_, Result<RemoteDocument<I>, Self::Error>>
    where
        I: 'a,
    {
        let ret = if let Some(document) = context::preloaded(vocabulary, &url) {
            Ok(RemoteDocument::new(
                Some(url),
                Some("application/ld+json".parse().unwrap()),
                document,
            ))
        } else {
            Err(NotPreloaded { iri: url })
        };
        Box::pin(future::ready(ret))
    }
}

impl<I: Display> Display for NotPreloaded<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "the IRI is not preloaded: {}", self.iri)
    }
}
