use json_syntax::object::{Entry, Object};
use json_syntax::{json, MetaValue, Value};
use locspan::{Location, Meta, Span};
use rdf_types::IriVocabularyMut;

pub fn preloaded<V, I>(vocabulary: &mut V, url: &I) -> Option<MetaValue<Location<I>>>
where
    V: IriVocabularyMut<Iri = I>,
    I: Clone,
{
    /// Like `json!`, but transparenrly adds the boilerplate metadata to every node.
    macro_rules! metajson {
        (@meta) => {
            Location::new(url.clone(), Span::default())
        };
        (@meta $value:expr) => {
            Meta($value, metajson!(@meta))
        };
        ({$($key:literal: $value:tt),*}) => {
            metajson!(@meta Value::Object(Object::from_vec(
                vec![$(Entry::new(metajson!(@meta $key.into()), metajson!($value))),*]
            )))
        };
        ($value:expr) => {
            json!($value @ metajson!(@meta))
        };
    }

    let iri = vocabulary.iri(url)?;
    match iri.as_str() {
        // <https://github.com/web-payments/web-payments.org/blob/2faef4c/contexts/identity-v1.jsonld>
        "https://w3id.org/identity/v1" | "http://w3id.org/identity/v1" => Some(metajson!(
            {
              "@context": {
                "id": "@id",
                "type": "@type",
                "cred": "https://w3id.org/credentials#",
                "dc": "http://purl.org/dc/terms/",
                "identity": "https://w3id.org/identity#",
                "perm": "https://w3id.org/permissions#",
                "ps": "https://w3id.org/payswarm#",
                "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
                "sec": "https://w3id.org/security#",
                "schema": "http://schema.org/",
                "xsd": "http://www.w3.org/2001/XMLSchema#",
                "Group": "https://www.w3.org/ns/activitystreams#Group",
                "claim": {
                  "@id": "cred:claim",
                  "@type": "@id"
                },
                "credential": {
                  "@id": "cred:credential",
                  "@type": "@id"
                },
                "issued": {
                  "@id": "cred:issued",
                  "@type": "xsd:dateTime"
                },
                "issuer": {
                  "@id": "cred:issuer",
                  "@type": "@id"
                },
                "recipient": {
                  "@id": "cred:recipient",
                  "@type": "@id"
                },
                "Credential": "cred:Credential",
                "CryptographicKeyCredential": "cred:CryptographicKeyCredential",
                "about": {
                  "@id": "schema:about",
                  "@type": "@id"
                },
                "address": {
                  "@id": "schema:address",
                  "@type": "@id"
                },
                "addressCountry": "schema:addressCountry",
                "addressLocality": "schema:addressLocality",
                "addressRegion": "schema:addressRegion",
                "comment": "rdfs:comment",
                "created": {
                  "@id": "dc:created",
                  "@type": "xsd:dateTime"
                },
                "creator": {
                  "@id": "dc:creator",
                  "@type": "@id"
                },
                "description": "schema:description",
                "email": "schema:email",
                "familyName": "schema:familyName",
                "givenName": "schema:givenName",
                "image": {
                  "@id": "schema:image",
                  "@type": "@id"
                },
                "label": "rdfs:label",
                "name": "schema:name",
                "postalCode": "schema:postalCode",
                "streetAddress": "schema:streetAddress",
                "title": "dc:title",
                "url": {
                  "@id": "schema:url",
                  "@type": "@id"
                },
                "Person": "schema:Person",
                "PostalAddress": "schema:PostalAddress",
                "Organization": "schema:Organization",
                "identityService": {
                  "@id": "identity:identityService",
                  "@type": "@id"
                },
                "idp": {
                  "@id": "identity:idp",
                  "@type": "@id"
                },
                "Identity": "identity:Identity",
                "paymentProcessor": "ps:processor",
                "preferences": {
                  "@id": "ps:preferences",
                  "@type": "@vocab"
                },
                "cipherAlgorithm": "sec:cipherAlgorithm",
                "cipherData": "sec:cipherData",
                "cipherKey": "sec:cipherKey",
                "digestAlgorithm": "sec:digestAlgorithm",
                "digestValue": "sec:digestValue",
                "domain": "sec:domain",
                "expires": {
                  "@id": "sec:expiration",
                  "@type": "xsd:dateTime"
                },
                "initializationVector": "sec:initializationVector",
                "member": {
                  "@id": "schema:member",
                  "@type": "@id"
                },
                "memberOf": {
                  "@id": "schema:memberOf",
                  "@type": "@id"
                },
                "nonce": "sec:nonce",
                "normalizationAlgorithm": "sec:normalizationAlgorithm",
                "owner": {
                  "@id": "sec:owner",
                  "@type": "@id"
                },
                "password": "sec:password",
                "privateKey": {
                  "@id": "sec:privateKey",
                  "@type": "@id"
                },
                "privateKeyPem": "sec:privateKeyPem",
                "publicKey": {
                  "@id": "sec:publicKey",
                  "@type": "@id"
                },
                "publicKeyPem": "sec:publicKeyPem",
                "publicKeyService": {
                  "@id": "sec:publicKeyService",
                  "@type": "@id"
                },
                "revoked": {
                  "@id": "sec:revoked",
                  "@type": "xsd:dateTime"
                },
                "signature": "sec:signature",
                "signatureAlgorithm": "sec:signatureAlgorithm",
                "signatureValue": "sec:signatureValue",
                "CryptographicKey": "sec:Key",
                "EncryptedMessage": "sec:EncryptedMessage",
                "GraphSignature2012": "sec:GraphSignature2012",
                "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
                "accessControl": {
                  "@id": "perm:accessControl",
                  "@type": "@id"
                },
                "writePermission": {
                  "@id": "perm:writePermission",
                  "@type": "@id"
                }
              }
            }
        )),
        "https://w3id.org/security/v1" | "http://w3id.org/security/v1" => Some(metajson!(
            {
              "@context": {
                "id": "@id",
                "type": "@type",
                "dc": "http://purl.org/dc/terms/",
                "sec": "https://w3id.org/security#",
                "xsd": "http://www.w3.org/2001/XMLSchema#",
                "EcdsaKoblitzSignature2016": "sec:EcdsaKoblitzSignature2016",
                "Ed25519Signature2018": "sec:Ed25519Signature2018",
                "EncryptedMessage": "sec:EncryptedMessage",
                "GraphSignature2012": "sec:GraphSignature2012",
                "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
                "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
                "CryptographicKey": "sec:Key",
                "authenticationTag": "sec:authenticationTag",
                "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
                "cipherAlgorithm": "sec:cipherAlgorithm",
                "cipherData": "sec:cipherData",
                "cipherKey": "sec:cipherKey",
                "created": {
                  "@id": "dc:created",
                  "@type": "xsd:dateTime"
                },
                "creator": {
                  "@id": "dc:creator",
                  "@type": "@id"
                },
                "digestAlgorithm": "sec:digestAlgorithm",
                "digestValue": "sec:digestValue",
                "domain": "sec:domain",
                "encryptionKey": "sec:encryptionKey",
                "expiration": {
                  "@id": "sec:expiration",
                  "@type": "xsd:dateTime"
                },
                "expires": {
                  "@id": "sec:expiration",
                  "@type": "xsd:dateTime"
                },
                "initializationVector": "sec:initializationVector",
                "iterationCount": "sec:iterationCount",
                "nonce": "sec:nonce",
                "normalizationAlgorithm": "sec:normalizationAlgorithm",
                "owner": {
                  "@id": "sec:owner",
                  "@type": "@id"
                },
                "password": "sec:password",
                "privateKey": {
                  "@id": "sec:privateKey",
                  "@type": "@id"
                },
                "privateKeyPem": "sec:privateKeyPem",
                "publicKey": {
                  "@id": "sec:publicKey",
                  "@type": "@id"
                },
                "publicKeyBase58": "sec:publicKeyBase58",
                "publicKeyPem": "sec:publicKeyPem",
                "publicKeyWif": "sec:publicKeyWif",
                "publicKeyService": {
                  "@id": "sec:publicKeyService",
                  "@type": "@id"
                },
                "revoked": {
                  "@id": "sec:revoked",
                  "@type": "xsd:dateTime"
                },
                "salt": "sec:salt",
                "signature": "sec:signature",
                "signatureAlgorithm": "sec:signingAlgorithm",
                "signatureValue": "sec:signatureValue"
              }
            }
        )),
        _ => None,
    }
}
