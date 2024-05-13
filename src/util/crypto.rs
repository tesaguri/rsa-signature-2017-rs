use std::io::{self, Write};

use base64::Engine as _;
use rand_core::{CryptoRng, RngCore};
use sha2::digest::Update;

pub struct DigestWrite<'a, D>(&'a mut D);

#[derive(Debug)]
pub enum NeverRng {}

impl<'a, D: Update> DigestWrite<'a, D> {
    pub fn new(digest: &'a mut D) -> Self {
        Self(digest)
    }
}

impl<'a, D: Update> Write for DigestWrite<'a, D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RngCore for NeverRng {
    fn next_u32(&mut self) -> u32 {
        match *self {}
    }

    fn next_u64(&mut self) -> u64 {
        match *self {}
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {
        match *self {}
    }

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        match *self {}
    }
}

impl CryptoRng for NeverRng {}

pub fn gen_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> String {
    pub const ENCODED_LEN: usize = 20;
    let mut rand = [0_u8; ENCODED_LEN * 3 / 4];
    rng.fill_bytes(&mut rand);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&rand[..])
}
