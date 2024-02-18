// The following key types are currently unimplemented:
//
// type.googleapis.com/google.crypto.tink.AesCmacPrfKey
// type.googleapis.com/google.crypto.tink.AesCmacKey
// type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey
// type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey
// type.googleapis.com/google.crypto.tink.AesCtrKey
// type.googleapis.com/google.crypto.tink.AesEaxKey
// type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey
// type.googleapis.com/google.crypto.tink.AesGcmSivKey
// type.googleapis.com/google.crypto.tink.AesSivKey
// type.googleapis.com/google.crypto.tink.ChaCha20Poly1305.
// type.googleapis.com/google.crypto.tink.EcdsaPublicKey
// type.googleapis.com/google.crypto.tink.EcdsaPrivateKey
// type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey
// type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey
// type.googleapis.com/google.crypto.tink.Ed25519PublicKey
// type.googleapis.com/google.crypto.tink.Ed25519PrivateKey
// type.googleapis.com/google.crypto.tink.HmacPrfKey
// type.googleapis.com/google.crypto.tink.HmacKey
// type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey
// type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey
// type.googleapis.com/google.crypto.tink.JwtHmacKey
// type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey
// type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey
// type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey
// type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey
// type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey
// type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey
// type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey
// type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey
// type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey
// type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key

use crate::{
    aead::Aead,
    codegen::{KeyStatusType, Keyset, OutputPrefixType},
    error::TinkError,
};

use self::aead::{AeadKeyset, AEAD_ALGORITHMS};
use prost::Message;

mod aead;

use rand::{thread_rng, Rng};

pub fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    thread_rng().fill(&mut data[..]);
    data
}

//
// Ciphertext prefix handling
//

pub const PREFIX_SIZE: usize = 5;
pub const LEGACY_KEY_START_BYTE: u8 = 0;
pub const TINK_KEY_START_BYTE: u8 = 1;

pub fn gen_output_prefix(prefix: OutputPrefixType, key_id: u32) -> [u8; PREFIX_SIZE] {
    let start_byte = match prefix {
        OutputPrefixType::Legacy => LEGACY_KEY_START_BYTE,
        OutputPrefixType::Tink => TINK_KEY_START_BYTE,
        _ => panic!("Should never have loaded a key with any other prefix type"),
    };

    let mut out = [0_u8; PREFIX_SIZE];
    out[..1].copy_from_slice(&[start_byte]);
    out[1..].copy_from_slice(&key_id.to_be_bytes());
    out
}

pub fn get_key_id_from_prefix(prefix: &[u8]) -> u32 {
    let bytes: [u8; 4] = prefix[1..5].try_into().unwrap();
    u32::from_be_bytes(bytes)
}

pub fn is_supported_prefix(prefix: OutputPrefixType) -> bool {
    match prefix {
        OutputPrefixType::Legacy => true,
        OutputPrefixType::Tink => true,
        _ => false,
    }
}

//
// AEAD loading
//

pub fn load_aead_keyset(keyset: &[u8]) -> Result<Box<dyn Aead + Send + Sync>, TinkError> {
    let mut keys = vec![];
    let mut ids = vec![];

    match Keyset::decode(keyset) {
        Ok(keyset) => {
            for key in keyset.key.iter() {
                // We only load enabled keys
                if key.status == KeyStatusType::UnknownStatus as i32
                    || key.status == KeyStatusType::Disabled as i32
                    || key.status == KeyStatusType::Destroyed as i32
                {
                    continue;
                }

                if !is_supported_prefix(key.output_prefix_type()) {
                    return Err(TinkError {});
                }

                let keydata = if let Some(k) = &key.key_data {
                    k
                } else {
                    // Messages are optional, so a broken key might not have the field.
                    continue;
                };

                let active = key.key_id == keyset.primary_key_id;
                let id = key.key_id;

                // Apply correct loader to the current key.
                match AEAD_ALGORITHMS.get(&keydata.type_url) {
                    None => return Err(TinkError {}),
                    Some(loader) => {
                        let result = loader(key);
                        match result {
                            Ok(key) => {
                                // The active key should always be first
                                if active {
                                    keys.insert(0, key);
                                    ids.insert(0, id);
                                } else {
                                    keys.push(key);
                                    ids.push(id);
                                }
                            }
                            Err(_) => return Err(TinkError {}),
                        };
                    }
                }
            }

            if keys.is_empty() {
                return Err(TinkError {});
            }

            Ok(Box::new(AeadKeyset::new(keys, ids)))
        }
        Err(_) => Err(TinkError {}),
    }
}
