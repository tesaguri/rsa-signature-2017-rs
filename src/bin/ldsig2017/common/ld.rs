mod context;

use core::future;
use core::hash::Hash;

use json_ld::future::BoxFuture;
use json_ld::{LoadingResult, RemoteDocument, ReqwestLoader};
use rdf_types::IriVocabularyMut;

pub struct Loader<I> {
    http: ReqwestLoader<I>,
}

impl<I> Default for Loader<I>
where
    I: Clone + Eq + Hash + Send + Sync,
{
    fn default() -> Self {
        Self {
            http: Default::default(),
        }
    }
}

impl<I> json_ld::Loader<I, locspan::Location<I>> for Loader<I>
where
    I: Clone + Eq + Hash + Send + Sync,
{
    type Output = json_syntax::Value<locspan::Location<I>>;
    type Error =
        json_ld::loader::reqwest::Error<json_ld::loader::reqwest::ParseError<locspan::Location<I>>>;

    fn load_with<'a>(
        &'a mut self,
        vocabulary: &'a mut (impl IriVocabularyMut<Iri = I> + Sync + Send),
        url: I,
    ) -> BoxFuture<'a, LoadingResult<I, locspan::Location<I>, Self::Output, Self::Error>>
    where
        I: 'a,
    {
        if let Some(document) = context::preloaded(vocabulary, &url) {
            Box::pin(future::ready(Ok(RemoteDocument::new(
                Some(url),
                Some("application/ld+json".parse().unwrap()),
                document,
            ))))
        } else {
            self.http.load_with(vocabulary, url)
        }
    }
}
