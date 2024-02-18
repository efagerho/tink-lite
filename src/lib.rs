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

pub fn parse_aead_keyset(keyset: &[u8]) -> Result<Box<dyn Aead + Send + Sync>, TinkError> {
    load_aead_keyset(keyset)
}

pub fn parse_aead_keyset_base64(key: &str) -> Result<Box<dyn Aead + Send + Sync>, TinkError> {
    match STANDARD.decode(key) {
        Ok(data) => parse_aead_keyset(&data),
        Err(_) => Err(TinkError {}),
    }
}

//
// AEAD encryption/decryption tests
//

#[cfg(test)]
mod tests {
    use super::*;

    //
    // AES-GCM-128 tests
    //

    const aes_gcm_128_new: &str = "CPrP7PkPElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEKM9RUIt0parJeRpubWLRzMYARABGPrP7PkPIAE=";
    const aes_gcm_128_old: &str = "CKKeo+MHElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEPVwEJ2cPgr5iD1SqhhGfjsYARABGKKeo+MHIAE=";
    const aes_gcm_128_old_and_new_old_active: &str = "CKKeo+MHElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEPVwEJ2cPgr5iD1SqhhGfjsYARABGKKeo+MHIAESVApICjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSEhoQoz1FQi3Slqsl5Gm5tYtHMxgBEAEY+s/s+Q8gAQ==";
    const aes_gcm_128_old_and_new_new_active: &str = "CPrP7PkPElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEPVwEJ2cPgr5iD1SqhhGfjsYARABGKKeo+MHIAESVApICjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkSEhoQoz1FQi3Slqsl5Gm5tYtHMxgBEAEY+s/s+Q8gAQ==";

    #[test]
    fn aes_gcm_128_decrypts_encrypted() {
        let keys = [
            aes_gcm_128_old,
            aes_gcm_128_new,
            aes_gcm_128_old_and_new_old_active,
            aes_gcm_128_old_and_new_new_active,
        ];

        for key in keys {
            let key = parse_aead_keyset_base64(key).unwrap();
            let plaintext = "foobarbazz";

            let ciphertext = key.encrypt(plaintext.as_bytes(), "".as_bytes()).unwrap();
            let decrypted = key.decrypt(&ciphertext, "".as_bytes()).unwrap();

            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn aes_gcm_128_encrypts_with_primary() {
        let old_key = parse_aead_keyset_base64(aes_gcm_128_old).unwrap();
        let old_active_key = parse_aead_keyset_base64(aes_gcm_128_old_and_new_old_active).unwrap();
        let new_active_key = parse_aead_keyset_base64(aes_gcm_128_old_and_new_new_active).unwrap();

        let plaintext = "foobarbazz";

        // Old key should be able to decrypt the ciphertext.
        let ciphertext_old_active = old_active_key.encrypt(plaintext.as_bytes(), "".as_bytes()).unwrap();
        let decrypted = old_key.decrypt(&ciphertext_old_active, "".as_bytes()).unwrap();
        assert_eq!(plaintext.as_bytes(), decrypted.as_slice());

        // Old key should not be able to decrypt the ciphertext
        let ciphertext_new_active = new_active_key.encrypt(plaintext.as_bytes(), "".as_bytes()).unwrap();
        let decrypted = old_key.decrypt(&ciphertext_new_active, "".as_bytes());
        assert!(decrypted.is_err());
    }

    #[test]
    fn aes_gcm_128_decrypts_with_nonprimary() {
        let old_key = parse_aead_keyset_base64(aes_gcm_128_old).unwrap();
        let new_active_key = parse_aead_keyset_base64(aes_gcm_128_old_and_new_new_active).unwrap();

        let plaintext = "foobarbazz";

        // Combined keyset should be able to decrypt with nonprimary.
        let ciphertext = old_key.encrypt(plaintext.as_bytes(), "".as_bytes()).unwrap();
        let decrypted = new_active_key.decrypt(&ciphertext, "".as_bytes()).unwrap();
        assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
    }

    //
    // AES-GCM-256 tests
    //
}
