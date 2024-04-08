use core::fmt::{self, Display, Formatter};
use core::str;
use std::fs;
use std::path::Path;

use anyhow::Context as _;
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

#[derive(Clone, Copy, Default, clap::ValueEnum)]
pub enum KeyFormat {
    /// Heuristically determine the key format
    #[default]
    Auto,
    /// PKCS#8 DER format
    Der,
    /// PKCS#8 PEM format
    Pem,
}

impl KeyFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyFormat::Auto => "auto",
            KeyFormat::Der => "der",
            KeyFormat::Pem => "pem",
        }
    }
}

impl Display for KeyFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn read_rsa_private_key_file(
    mut format: KeyFormat,
    path: &Path,
) -> anyhow::Result<RsaPrivateKey> {
    if matches!(format, KeyFormat::Auto) {
        if let Some(ext) = path.extension() {
            if ext == "der" {
                format = KeyFormat::Der;
            } else if ext == "pem" {
                format = KeyFormat::Pem;
            }
        }
    }

    let key =
        match format {
            KeyFormat::Auto => {
                let key = fs::read(path).context("unable to read private key")?;
                RsaPrivateKey::from_pkcs8_der(&key).or_else(|_| {
                    str::from_utf8(&key)
                        .map_err(|_| ())
                        .and_then(|key| RsaPrivateKey::from_pkcs8_pem(key).map_err(|_| ()))
                        .map_err(|()| anyhow::anyhow!("unable to determine private key format"))
                })?
            }
            KeyFormat::Der => RsaPrivateKey::read_pkcs8_der_file(path)
                .context("unable to read private key DER")?,
            KeyFormat::Pem => RsaPrivateKey::read_pkcs8_pem_file(path)
                .context("unable to read private key PEM")?,
        };

    Ok(key)
}
