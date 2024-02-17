// Notes:
//
// 1. The OutPutPrefixType is a per key property.

use crate::{aead::Aead, codegen::{key_data::KeyMaterialType, keyset::Key, OutputPrefixType}, error::TinkError};
use phf::{phf_map, Map};

pub static AEAD_ALGORITHMS: Map<&'static str, fn(&Key) -> Result<AeadKey, TinkError>> = phf_map! {
   "type.googleapis.com/google.crypto.tink.AesGcmKey" => load_aes_gcm_key
};

#[derive(Clone)]
pub struct AesGcmKey {
    key: Vec<u8>,
    key_id: u32,
    prefix: OutputPrefixType,
}

#[derive(Clone)]
pub enum AeadKey {
    AesGcm(AesGcmKey),
}

#[derive(Clone)]
pub struct AeadKeyset {
    pub keys: Vec<AeadKey>,
    // We store at index i the ID for keys[i].
    // This is more memory efficient than a hashmap and presumably the number of keys will be small enough
    // that a consecutive scan through a buffer is faster than a hash table lookup. 
    pub ids: Vec<u32>,
    // The active key is always the first key. TODO: remove this
    pub active: usize,
}

impl Aead for AeadKeyset {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        match self.keys[self.active] {
            AeadKey::AesGcm(key) => key.encrypt(plaintext, additional_data)
        }
    }

    fn decypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        // Decode ciphertext to find correct key version
        match self.keys[self.active] {
            AeadKey::AesGcm(key) => key.decypt(ciphertext, additional_data)
        }
    }
}

//
// AES-GCM
//

pub fn load_aes_gcm_key(key: &Key) -> Result<AeadKey, TinkError> {
    let key_data = if let Some(data) = key.key_data {
        data
    } else {
        return Err(TinkError {});
    };

    if key_data.key_material_type != KeyMaterialType::Symmetric as i32 {
        return Err(TinkError {});
    }

    // Step 1: Parse the bytes of the key

    // Needs to do the following:
    // 1. Extract the key material
    // 2. Calculate the key ID based on 
    println!("Got AES-GCM key");
    Ok(AeadKey::AesGcm(AesGcmKey { prefix: key.output_prefix_type}))
}

impl Aead for AesGcmKey {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        Err(TinkError {})
    }

    fn decypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        Err(TinkError {})
    }
}
