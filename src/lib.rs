use aead::Aead;
use algorithms::load_aead_keyset;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use error::TinkError;

pub mod aead;
pub mod error;
pub mod signer;
pub mod verifier;

mod algorithms;
mod codegen;

//
// Parsers for different key types
//

pub fn parse_aead_keyset(keyset: &[u8]) -> Result<Box<dyn Aead + Send>, TinkError> {
    load_aead_keyset(keyset)
}

pub fn parse_aead_keyset_base64(key: &str) -> Result<Box<dyn Aead + Send>, TinkError> {
    match STANDARD.decode(key) {
        Ok(data) => parse_aead_keyset(&data),
        Err(_) => Err(TinkError {}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_aes_gcm_key() {
        let result = parse_aead_keyset_base64("<key>");
        
        match result {
            Ok(_) => assert!(false),
            Err(_) => assert!(false, "unable to load AES-GCM key")
        }
    }
}
