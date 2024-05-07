pub mod loader;

mod private {
    use sophia_jsonld::parser::JsonLdParser;

    pub struct JsonLdOptions<LF>(pub(super) JsonLdParser<LF>);
}

use core::slice;
use std::convert::Infallible;

use base64::Engine as _;
use futures_util::future;
use json_ld::RemoteDocument;
use rsa::RsaPublicKey;
use sophia_api::dataset::{CollectibleDataset, Dataset, MutableDataset, SetDataset};
use sophia_api::quad::Quad;
use sophia_api::source::{IntoQuadSource, QuadSource, StreamError};
use sophia_api::term::{matcher, Term, TermKind};
use sophia_iri::{Iri, IriRef};
use sophia_jsonld::loader_factory::{DefaultLoaderFactory, LoaderFactory};
use sophia_jsonld::parser::JsonLdParser;
use sophia_jsonld::vocabulary::ArcIri;
use sophia_jsonld::{JsonLdError, JsonLdQuadSource};

use crate::common::consts;
use crate::{verify, verify_rsa_signature_2017, SignatureType};

use self::loader::PreloadedLoader;

/// A signed document deserialized from JSON-LD.
#[derive(Debug)]
pub struct SignedDocument<D, O = D> {
    document: D,
    signatures: Vec<Signature<O>>,
}

#[derive(Debug)]
pub struct Signature<O> {
    options: O,
    id: Option<Box<str>>,
    kind: SignatureType,
    signature_value: Vec<u8>,
}

pub struct DocumentParser<LF = DefaultLoaderFactory<PreloadedLoader>, OO = UseDocumentOptions> {
    parser: JsonLdParser<LF>,
    options_parser: OO,
}

#[non_exhaustive]
pub struct UseDocumentOptions;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error<DE, OE> {
    MissingSignatureOptions,
    UnsupportedType,
    NestingSignatureNode,
    DuplicateSignatures,
    BadSubject,
    BadSignatureOptions,
    BadSignatureValue,
    Document(JsonLdError),
    Options(JsonLdError),
    DocumentDataset(DE),
    OptionsDataset(OE),
}

pub type JsonLdOptions<LF = DefaultLoaderFactory<PreloadedLoader>> =
    sophia_jsonld::options::JsonLdOptions<LF>;

impl<LF> DocumentParser<LF>
where
    LF: LoaderFactory + Default,
{
    pub fn new() -> Self {
        Self::default()
    }
}

impl<LF> DocumentParser<LF>
where
    LF: LoaderFactory,
{
    pub fn with_options(options: JsonLdOptions<LF>) -> Self {
        Self {
            parser: JsonLdParser::new_with_options(options),
            options_parser: UseDocumentOptions,
        }
    }
}

impl<LF, OO> DocumentParser<LF, OO> {
    pub fn options(&self) -> &JsonLdOptions<LF> {
        self.parser.options()
    }

    pub fn set_options<LF2>(self, options: JsonLdOptions<LF2>) -> DocumentParser<LF2, OO>
    where
        LF2: LoaderFactory,
    {
        DocumentParser {
            parser: JsonLdParser::new_with_options(options),
            options_parser: self.options_parser,
        }
    }

    pub fn set_options_options<OLF>(
        self,
        options_options: JsonLdOptions<OLF>,
    ) -> DocumentParser<LF, private::JsonLdOptions<OLF>>
    where
        OLF: LoaderFactory,
    {
        DocumentParser {
            parser: self.parser,
            options_parser: private::JsonLdOptions(JsonLdParser::new_with_options(options_options)),
        }
    }

    pub fn unset_options_options(self) -> DocumentParser<LF> {
        DocumentParser {
            parser: self.parser,
            options_parser: UseDocumentOptions,
        }
    }
}

impl<LF, OLF> DocumentParser<LF, private::JsonLdOptions<OLF>> {
    pub fn options_options(&self) -> &JsonLdOptions<OLF> {
        self.options_parser.0.options()
    }
}

impl<LF> DocumentParser<LF, UseDocumentOptions>
where
    LF: LoaderFactory,
{
    pub async fn parse<D, O>(
        self,
        document: RemoteDocument<ArcIri>,
    ) -> Result<SignedDocument<D, O>, Error<D::Error, O::Error>>
    where
        D: CollectibleDataset + SetDataset,
        O: CollectibleDataset + SetDataset + MutableDataset,
    {
        parse(document, &self.parser, &self.parser).await
    }
}

impl<LF, OLF> DocumentParser<LF, private::JsonLdOptions<OLF>>
where
    LF: LoaderFactory,
    OLF: LoaderFactory,
{
    pub async fn parse<D, O>(
        self,
        document: RemoteDocument<ArcIri>,
    ) -> Result<SignedDocument<D, O>, Error<D::Error, O::Error>>
    where
        D: CollectibleDataset + SetDataset,
        O: CollectibleDataset + SetDataset + MutableDataset,
    {
        parse(document, &self.parser, &self.options_parser.0).await
    }
}

impl<LF: Default> Default for DocumentParser<LF>
where
    LF: LoaderFactory,
{
    fn default() -> Self {
        Self::with_options(JsonLdOptions::default())
    }
}

impl SignedDocument<()> {
    pub fn parser() -> DocumentParser {
        DocumentParser::new()
    }
}

impl<D, O> SignedDocument<D, O>
where
    D: CollectibleDataset + SetDataset + MutableDataset,
    O: CollectibleDataset + SetDataset + MutableDataset,
{
    pub async fn parse(
        document: RemoteDocument<ArcIri>,
    ) -> Result<Self, Error<D::Error, O::Error>> {
        SignedDocument::parser().parse(document).await
    }
}

impl<D, O> SignedDocument<D, O>
where
    D: SetDataset,
    O: SetDataset,
{
    pub fn verify_rsa_signature_2017(
        &self,
        key: &RsaPublicKey,
    ) -> Result<(), verify::Error<D::Error, O::Error>> {
        for signature in &self.signatures {
            verify_rsa_signature_2017(
                &self.document,
                &signature.options,
                key,
                &signature.signature_value,
            )?;
        }
        Ok(())
    }
}

impl<O> Signature<O>
where
    O: Dataset,
{
    pub fn created(&self) -> Option<Result<Box<str>, O::Error>> {
        // This matches any nodes in the signature options dataset, which is fine because we reject
        // nesting nodes in `parse()`. While users can just reassign `self.options`, we trust them
        // not to mess up with the dataset too much :)
        self.options
            .quads_matching(
                matcher::Any,
                [Iri::new_unchecked(consts::CREATED)],
                matcher::DatatypeMatcher::new(IriRef::new_unchecked(consts::DATETIME)),
                matcher::Any,
            )
            .filter_map(|q| {
                q.map(|q| q.to_o().lexical_form().map(Into::into))
                    .transpose()
            })
            .next()
    }

    pub fn creator(&self) -> Option<Result<IriRef<Box<str>>, O::Error>> {
        self.options
            .quads_matching(
                matcher::Any,
                [Iri::new_unchecked(consts::CREATOR)],
                TermKind::Iri,
                matcher::Any,
            )
            .filter_map(|q| {
                q.map(|q| q.to_o().iri().map(|iri| iri.map_unchecked(Into::into)))
                    .transpose()
            })
            .next()
    }

    pub fn domain(&self) -> Option<Result<Box<str>, O::Error>> {
        self.options
            .quads_matching(
                matcher::Any,
                [Iri::new_unchecked(consts::DOMAIN)],
                TermKind::Literal,
                matcher::Any,
            )
            .filter_map(|q| {
                q.map(|q| q.to_o().lexical_form().map(Into::into))
                    .transpose()
            })
            .next()
    }

    pub fn nonce(&self) -> Option<Result<Box<str>, O::Error>> {
        self.options
            .quads_matching(
                matcher::Any,
                [Iri::new_unchecked(consts::NONCE)],
                TermKind::Literal,
                matcher::Any,
            )
            .filter_map(|q| {
                q.map(|q| q.to_o().lexical_form().map(Into::into))
                    .transpose()
            })
            .next()
    }
}

async fn parse<D, O, LF, OLF>(
    document: RemoteDocument<ArcIri>,
    parser: &JsonLdParser<LF>,
    options_parser: &JsonLdParser<OLF>,
) -> Result<SignedDocument<D, O>, Error<D::Error, O::Error>>
where
    D: CollectibleDataset + SetDataset,
    O: CollectibleDataset + SetDataset + MutableDataset,
    LF: LoaderFactory,
    OLF: LoaderFactory,
{
    let url = document.url().cloned();
    let content_type = document.content_type().cloned();
    let context_url = document.context_url().cloned();
    let mut document = document.into_document();

    let document_object = if let Some(object) = document.as_object_mut() {
        object
    } else {
        return Err(Error::MissingSignatureOptions);
    };

    // Remove the `signature` node from the default graph (Step 3. of the Signature Verification
    // Algorithm).
    // While the spec instructs to remove _any_ `signature` nodes from the document, existing
    // implementations only removes the top-level `signature` entry, and we follow the latter
    // behavior.
    // Also, we are lexically removing the entries without checking that the keys actually map to
    // the intended RDF properties. The loose check doesn't have (additional) security implication
    // because these entries are not secured by the Linked Data Signatures anyway (although you
    // should be aware of the unsecured nature of these terms and shouldn't rely on their values for
    // a security purpose). The lexical removal may also remove additional nodes if the `signature`
    // entry value contains nested node objects, in which case the intended semantics is unclear and
    // we conservatively treat it as an error (which we'll check later after deserializing the
    // signature options as RDF).
    let mut signatures = if let Some(signature_entry) = document_object.remove("signature").last() {
        signature_entry.value
    } else {
        return Err(Error::MissingSignatureOptions);
    };

    let signatures = if let Some(set) = signatures.as_array_mut() {
        set
    } else {
        slice::from_mut(&mut signatures)
    };

    let document_context_entry = document_object.get_entries("@context").last();

    let signatures: Vec<_> = signatures
        .iter_mut()
        .map(|options| {
            let options_object = match options.0 {
                json_syntax::Value::Object(ref mut options) => options,
                json_syntax::Value::Array(ref mut set) => {
                    let mut elms = set.iter_mut();
                    let elm = if let Some(elm) = elms.next() {
                        elm
                    } else {
                        return Err(Error::MissingSignatureOptions);
                    };
                    if elms.next().is_some() {
                        return Err(Error::DuplicateSignatures);
                    }
                    if let Some(options) = elm.as_object_mut() {
                        options
                    } else {
                        return Err(Error::BadSignatureOptions);
                    }
                }
                _ => return Err(Error::BadSignatureOptions),
            };

            // Inject the document-global context into the signature options.
            // Well, the "right" way of doing this would be expanding the whole document before
            // removing the signature options from it, but the JSON-LD processing would lose the
            // `signature` entry without a proper term definition in the `@context`, which is
            // unfortunately prevalent in the wild.
            if let Some(dce) = document_context_entry {
                if let Some(oc) = options_object.get_mut("@context").last() {
                    let dc = json_syntax::Value::force_as_array(&dce.value);
                    if let Some(array) = oc.as_array_mut() {
                        array.reserve(dc.len());
                        for c in dc.iter().rev() {
                            array.insert(0, c.clone());
                        }
                    } else {
                        let oc_orig = oc.take();
                        let mut oc_new = Vec::with_capacity(dc.len() + 1);
                        oc_new.extend_from_slice(&dc);
                        oc_new.push(locspan::Meta(oc_orig, oc.1.clone()));
                        oc.0 = json_syntax::Value::Array(oc_new);
                    }
                } else {
                    options_object.push_entry(dce.clone());
                }
            }

            // Remove `type`, `id` and `signatureValue` entries from the signature options (Step 2.
            // of Create Verify Hash Algorithm).
            // Here, we are lexically removing the entries just like we did for the `signature`
            // entry.

            let is_rsa_signature_2017 =
                options_object
                    .remove("type")
                    .last()
                    .map_or(false, |ty| match ty.value.0 {
                        json_syntax::Value::String(ref ty) => ty == "RsaSignature2017",
                        json_syntax::Value::Array(ref types) => types
                            .iter()
                            .any(|ty| ty.as_string() == Some("RsaSignature2017")),
                        _ => false,
                    });
            if !is_rsa_signature_2017 {
                return Err(Error::UnsupportedType);
            }

            let id = if let Some(entry) = options_object.remove("id").last() {
                entry.value.0.into_string().map(|s| s.into_boxed_str())
            } else {
                None
            };

            let signature_value =
                if let Some(entry) = options_object.remove("signatureValue").last() {
                    entry
                        .value
                        .0
                        .into_string()
                        .and_then(|v| {
                            base64::engine::general_purpose::STANDARD
                                .decode(v.as_bytes())
                                .ok()
                        })
                        .ok_or(Error::BadSignatureValue)?
                } else {
                    return Err(Error::MissingSignatureOptions);
                };

            Ok(Signature {
                options: RemoteDocument::new_full(
                    url.clone(),
                    content_type.clone(),
                    context_url.clone(),
                    Default::default(),
                    locspan::Meta(options.take(), options.1.clone()),
                ),
                id,
                kind: SignatureType::RsaSignature2017,
                signature_value,
            })
        })
        .collect::<Result<_, _>>()?;

    let document = RemoteDocument::new_full(
        url.clone(),
        content_type.clone(),
        context_url.clone(),
        Default::default(),
        document,
    );
    let document_fut =
        async { try_json_ld_qs(parser.parse_json(&document).await).map_err(Error::Document) };
    let signatures_fut = future::try_join_all(signatures.into_iter().map(
        |Signature {
             options,
             id,
             kind,
             signature_value,
         }| async move {
            let options = try_json_ld_qs(options_parser.parse_json(&options).await)
                .map_err(Error::Options)?;
            Ok(Signature {
                options,
                id,
                kind,
                signature_value,
            })
        },
    ));
    let (document, signatures) = future::try_join(document_fut, signatures_fut).await?;

    let document = D::from_quad_source(document).map_err(|e| match e {
        StreamError::SourceError(e) => match e {},
        StreamError::SinkError(e) => Error::DocumentDataset(e),
    })?;

    let signatures = signatures
        .into_iter()
        .map(
            |Signature {
                 options,
                 id,
                 kind,
                 signature_value,
             }| {
                let options = O::from_quad_source(options).map_err(|e| match e {
                    StreamError::SourceError(e) => match e {},
                    StreamError::SinkError(e) => Error::OptionsDataset(e),
                })?;
                let mut signature_subject: Option<<O::Quad<'_> as Quad>::Term> = None;
                for quad in options.quads() {
                    let ([s, _, _], g) = quad.map_err(Error::OptionsDataset)?.to_spog();
                    if let Some(ref ss) = signature_subject {
                        if !ss.eq(s) || g.is_some() {
                            return Err(Error::NestingSignatureNode);
                        }
                    } else if !s.is_blank_node() || g.is_some() {
                        // The signature node should have a blank node identifier since we have removed the `id`
                        // entry. A different term kind implies that either the `@id` is assigned in another way
                        // or the entry value contains a nested node. Also, named graphs shouldn't appear in a
                        // typically-structured document without a top-level `@graph` entry.
                        return Err(Error::NestingSignatureNode);
                    } else {
                        signature_subject = Some(s);
                    }
                }
                drop(signature_subject);

                Ok(Signature {
                    options,
                    id,
                    kind,
                    signature_value,
                })
            },
        )
        .collect::<Result<_, _>>()?;

    Ok(SignedDocument {
        document,
        signatures,
    })
}

fn try_json_ld_qs(
    qs: JsonLdQuadSource,
) -> Result<
    impl QuadSource<Quad<'static> = impl Quad<Term = impl Term>, Error = Infallible>,
    JsonLdError,
> {
    let quads = match qs {
        JsonLdQuadSource::Quads(quads) => quads,
        JsonLdQuadSource::Err(Some(e)) => return Err(e),
        JsonLdQuadSource::Err(None) => Vec::new().into_iter(),
    };
    Ok(quads.into_quad_source())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures_executor::block_on;
    use json_syntax::Parse as _;
    use sophia_inmem::dataset::LightDataset;
    use sophia_iri::Iri;

    use crate::util::test::parse_nq;

    use super::*;

    #[test]
    fn it_works() {
        const DOCUMENT: &str = r#"
            {
                "@context": [
                    "https://w3id.org/security/v1",
                    {
                        "content": "https://www.w3.org/ns/activitystreams#content"
                    }
                ],
                "type": "https://www.w3.org/ns/activitystreams#Note",
                "content": "Hello, world!",
                "signature": {
                    "@context": "https://w3id.org/identity/v1",
                    "type": "RsaSignature2017",
                    "created": "2024-01-01T00:00:00Z",
                    "creator": "https://example.com/#me",
                    "nonce": "deadbeef12345678",
                    "signatureValue": "EuukoY4e2Bdp18mQov48Q1E38XetV03SI+DHJOdFm/t8Cz+WP8qbgtM8fg0L9J15B8yyZ7J2+nSeqi2oAuuo7g=="
                }
            }
        "#;
        const DATASET: &str = r#"
            _:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Note> .
            _:b0 <https://www.w3.org/ns/activitystreams#content> "Hello, world!" .
        "#;
        const OPTIONS: &str = r#"
            _:b0 <http://purl.org/dc/terms/created> "2024-01-01T00:00:00Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
            _:b0 <http://purl.org/dc/terms/creator> <https://example.com/#me> .
            _:b0 <https://w3id.org/security#nonce> "deadbeef12345678" .
        "#;

        let placeholder_iri = Iri::new_unchecked(Arc::from("urn:x-placeholder"));
        let document = RemoteDocument::new(
            None,
            None,
            json_syntax::Value::parse_str(DOCUMENT, |span| {
                locspan::Location::new(placeholder_iri.clone(), span)
            })
            .unwrap(),
        );
        let SignedDocument {
            document,
            signatures,
        } = block_on(SignedDocument::<LightDataset>::parse(document)).unwrap();

        assert_eq_dataset!(document, parse_nq(DATASET));

        let [signature] = signatures.try_into().unwrap();
        assert_eq_dataset!(signature.options, parse_nq(OPTIONS));
        assert_eq!(signature.id, None);
        assert_eq!(signature.kind, SignatureType::RsaSignature2017);
        assert_eq!(signature.signature_value, base64::engine::general_purpose::STANDARD.decode("EuukoY4e2Bdp18mQov48Q1E38XetV03SI+DHJOdFm/t8Cz+WP8qbgtM8fg0L9J15B8yyZ7J2+nSeqi2oAuuo7g==").unwrap());
    }
}
