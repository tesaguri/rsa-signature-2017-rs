use std::borrow::Cow;

use rand_core::{CryptoRng, RngCore};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::Sha256;
use sophia_api::dataset::SetDataset;
use sophia_iri::Iri;

use crate::signature_options::SignatureOptions;
use crate::util::{gen_nonce, NeverRng};
use crate::Error;

#[derive(Debug)]
#[non_exhaustive]
pub struct SignOptions<'sig, 'this, R = NeverRng> {
    /// The date and time of the signature generation in the ISO 8601 format.
    pub created: Option<&'sig str>,
    /// The operational domain of the signature.
    pub domain: Option<&'sig str>,
    /// The nonce value of the signature.
    pub nonce: Option<Option<&'sig str>>,
    /// The random number generator used during the signature generation.
    pub rng: Option<&'this mut R>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Signature<'a> {
    #[cfg_attr(
        feature = "serde",
        serde(rename = "@context", serialize_with = "serialize_context")
    )]
    pub(crate) _context: (),
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    pub kind: SignatureType,
    pub created: Cow<'a, str>,
    pub creator: Iri<&'a str>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub domain: Option<&'a str>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub nonce: Option<Cow<'a, str>>,
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_bytes_base64"))]
    pub signature_value: Vec<u8>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum SignatureType {
    RsaSignature2017,
}

impl<'sig, 'this, R> SignOptions<'sig, 'this, R>
where
    R: RngCore + CryptoRng,
{
    /// Creates a new `SignOptions` with a default set of options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the datetime of the signature generation.
    ///
    /// By default, the datetime is automatically set during the signature operation. This method
    /// shouldn't be used in production!
    pub fn created(&mut self, created: impl Into<Option<&'sig str>>) -> &mut Self {
        self.created = created.into();
        self
    }

    /// Specifies the operational domain of the signature.
    pub fn domain(&mut self, domain: impl Into<Option<&'sig str>>) -> &mut Self {
        self.domain = domain.into();
        self
    }

    /// Sets the nonce value of the signature.
    ///
    /// By default, the nonce value is automatically set during the signature operation. This method
    /// shouldn't be used in production!
    pub fn nonce(&mut self, nonce: impl Into<Option<Option<&'sig str>>>) -> &mut Self {
        self.nonce = nonce.into();
        self
    }

    /// Sets a custom random number generator to be used during the signature generation.
    ///
    /// By default, [`rand::thread_rng`] is used.
    pub fn rng(&mut self, rng: impl Into<Option<&'this mut R>>) -> &mut Self {
        self.rng = rng.into();
        self
    }

    /// Signs the given `dataset` with (a variant of) the `RsaSignature2017` algorithm[^1].
    ///
    /// Strictly speaking, this uses the RDFC 1.0 canonicalization algorithm instead of the
    /// GCA2015 algorithm (aka. URDNA2015) used by the original `RsaSignature2017` algorithm. The
    /// difference between these algorithms is handling of some control characters — Please don't
    /// give it those characters, thanks!
    ///
    /// See also [`Signature::sign_rsa_signature_2017`] function, which is a shorthand for this
    /// method.
    ///
    /// [^1]: <https://github.com/w3c-ccg/ld-signatures/blob/d0af56856684924156a94838f9482a27766bb2be/index.html>
    pub fn sign_rsa_signature_2017<D>(
        &mut self,
        dataset: &D,
        key: &RsaPrivateKey,
        creator: Iri<&'sig str>,
    ) -> Result<Signature<'sig>, Error<D::Error>>
    where
        D: SetDataset,
    {
        let nonce = match self.nonce {
            Some(Some(nonce)) => Some(Cow::Borrowed(nonce)),
            Some(None) => None,
            None => {
                let owned = if let Some(rng) = self.rng.as_deref_mut() {
                    gen_nonce(rng)
                } else {
                    gen_nonce(&mut rand::thread_rng())
                };
                Some(Cow::Owned(owned))
            }
        };

        let options = SignatureOptions {
            created: self.created,
            creator,
            domain: self.domain,
            nonce: nonce.as_deref(),
        };
        let (to_be_signed, created) = options.create_verify_hash(dataset)?;

        let created = created
            .map(Cow::Owned)
            // We guarantee that`self.created` is `Some` when the returned `created` is `None`.
            // You may wonder why we don't just return a `Cow<'a, str>`, whose `Borrowed` variant
            // would contain the passed `created`. Well, we cannot do that because doing so would
            // make the returned `created` value borrow `'a`, which doesn't outlive the local
            // binding `nonce`. While we could assign different lifetime parameters to `created` and
            // `nonce` of `SignatureOptions`, I didn't want to expose such ad-hoc lifetime
            // parameters from `SignatureOptions`, which we might want to make public when
            // implementing the verification algorithm.
            .unwrap_or_else(|| Cow::Borrowed(self.created.unwrap()));

        let padding = Pkcs1v15Sign::new::<Sha256>();
        let signature_value = if let Some(rng) = self.rng.as_deref_mut() {
            key.sign_with_rng(rng, padding, &to_be_signed).unwrap()
        } else {
            key.sign_with_rng(&mut rand::thread_rng(), padding, &to_be_signed)
                .unwrap()
        };

        Ok(Signature {
            kind: SignatureType::RsaSignature2017,
            created,
            creator,
            domain: self.domain,
            nonce,
            signature_value,
            _context: (),
        })
    }
}

impl<'sig, 'this, R> Default for SignOptions<'sig, 'this, R> {
    fn default() -> Self {
        SignOptions {
            created: None,
            domain: None,
            nonce: None,
            rng: None,
        }
    }
}

impl<'a> Signature<'a> {
    pub fn options<'b>() -> SignOptions<'a, 'b> {
        SignOptions::new()
    }

    /// Shorthand for `<SignOptions>::new().sign_rsa_signature_2017(…)`. See also
    /// [`SignOptions::sign_rsa_signature_2017`].
    pub fn sign_rsa_signature_2017<D>(
        dataset: &D,
        key: &RsaPrivateKey,
        creator: Iri<&'a str>,
    ) -> Result<Self, Error<D::Error>>
    where
        D: SetDataset,
    {
        <SignOptions<'_, '_>>::new().sign_rsa_signature_2017(dataset, key, creator)
    }
}

#[cfg(feature = "serde")]
fn serialize_context<S>(_: &(), serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;

    #[derive(serde::Serialize)]
    struct InlineContext {
        #[serde(rename = "@vocab")]
        vocab: &'static str,
    }

    let mut seq = serializer.serialize_seq(Some(2))?;
    // The LD Signatures spec used the context URL of <https://w3id.org/identity/v1>, which is now a
    // dead link. Although its former content is available at
    // <https://github.com/web-payments/web-payments.org/blob/2faef4c/contexts/identity-v1.jsonld>
    // and many implementations treat the context as already retrieved, the terms used by LD
    // Signatures are defined in the Security Vocabulary context as well, and I think it's safer to
    // use the latter.
    seq.serialize_element("https://w3id.org/security/v1")?;
    seq.serialize_element(&InlineContext {
        // Required to make the `"type": "RsaSignature2017"` entry properly expand to
        // `"type": "sec:RsaSignature2017"`, although the LD Signatures algorithms explicitly ignore
        // the `type` term and many plain-JSON processors doesn't seem to care about it either.
        vocab: "sec:",
    })?;
    seq.end()
}

#[cfg(feature = "serde")]
fn serialize_bytes_base64<T, S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: serde::Serializer,
{
    use base64::display::Base64Display;

    serializer.collect_str(&Base64Display::new(
        bytes.as_ref(),
        &base64::engine::general_purpose::STANDARD,
    ))
}
