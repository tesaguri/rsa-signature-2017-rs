use std::ffi::OsStr;
use std::fs::File;
use std::io::{stdin, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use clap::builder::{StringValueParser, TypedValueParser};
use json_ld::ReqwestLoader;
use json_syntax::Parse as _;
use rsa_signature_2017::json_ld::loader::PreloadedLoader;
use rsa_signature_2017::Signature;
use sophia_api::dataset::CollectibleDataset;
use sophia_inmem::dataset::LightDataset;
use sophia_iri::Iri;
use sophia_jsonld::loader::ChainLoader;
use sophia_jsonld::vocabulary::ArcIri;
use sophia_jsonld::{JsonLdOptions, JsonLdParser};

use crate::common::{read_rsa_private_key_file, KeyFormat};

#[derive(clap::Args)]
pub struct Args {
    /// URI of the key pair
    #[arg(short, long, value_name = "URI", value_hint = clap::ValueHint::Url)]
    #[arg(value_parser = StringValueParser::new().try_map(Iri::new))]
    creator: Iri<String>,
    /// Private key to sign the documents with
    #[arg(short, long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    key: PathBuf,
    /// The date and time of the signature generation in the ISO 8601 format.
    #[arg(long, value_name = "DATETIME", value_hint = clap::ValueHint::Other)]
    created: Option<String>,
    /// Format of the private key
    #[arg(long, value_name = "FORMAT", default_value_t = Default::default())]
    key_format: KeyFormat,
    #[arg(long)]
    nonce: Option<String>,
    /// Documents to sign
    #[arg(value_hint = clap::ValueHint::FilePath)]
    input: Vec<PathBuf>,
}

pub async fn main(args: Args) -> anyhow::Result<()> {
    let key = read_rsa_private_key_file(args.key_format, &args.key)?;
    let creator = args.creator.as_ref();

    let placeholder_iri = Iri::new_unchecked(Arc::from("urn:x-placeholder"));

    let mut inputs = args.input.iter();
    let mut path = if let Some(input) = inputs.next() {
        input
    } else {
        Path::new("-")
    };

    let mut sign_options = Signature::options();
    sign_options.created(args.created.as_deref()).nonce(
        args.nonce
            .as_ref()
            .map(|nonce| (!nonce.is_empty()).then_some(nonce.as_str())),
    );

    loop {
        let mut json = String::new();
        if path == OsStr::new("-") {
            stdin().lock().read_to_string(&mut json)
        } else {
            let input =
                File::open(path).with_context(|| format!("unable to open input: {:?}", path))?;
            BufReader::new(input).read_to_string(&mut json)
        }
        .with_context(|| format!("unable to read input: {:?}", path))?;

        let path_iri: ArcIri = Iri::new(format!("file://{:?}", path).into())
            .unwrap_or_else(|_| placeholder_iri.clone());
        let json = json_syntax::Value::parse_str(&json, |span| {
            locspan::Location::new(path_iri.clone(), span)
        })
        .with_context(|| format!("unable to parse inout: {:?}", path))?;

        if !json.is_object() {
            anyhow::bail!("{:?}: expected JSON object, got {}", path, json.kind());
        }

        let document = json_ld::RemoteDocument::new(None, None, json);

        let json_ld_options = JsonLdOptions::new()
            .with_default_document_loader::<ChainLoader<PreloadedLoader, ReqwestLoader<ArcIri>>>();
        let quads = JsonLdParser::new_with_options(json_ld_options)
            .parse_json(&document)
            .await;
        let dataset = LightDataset::from_quad_source(quads)?;

        let signature = sign_options
            .sign_rsa_signature_2017(&dataset, &key, creator)
            .with_context(|| format!("unable to sign input: {:?}", path))?;

        let signature_key = locspan::Meta::new(
            "signature".into(),
            locspan::Location::new(placeholder_iri.clone(), Default::default()),
        );
        let signature_json = json_syntax::to_value_with(&signature, || {
            locspan::Location::new(placeholder_iri.clone(), Default::default())
        })
        .unwrap();

        let mut json = document.into_document();
        json.as_object_mut()
            .unwrap()
            .insert(signature_key, signature_json);

        println!("{}", json);

        if let Some(input) = inputs.next() {
            path = input;
        } else {
            break;
        }
    }

    Ok(())
}
