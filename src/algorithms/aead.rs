use std::mem::size_of;

use crate::{
    aead::Aead,
    codegen::{key_data::KeyMaterialType, keyset::Key, AesGcmKey, OutputPrefixType},
    error::TinkError,
};
use phf::{phf_map, Map};

use aes_gcm::{aead::Aead as AeadLowLevel, KeyInit};
use aes_gcm::{
    aead::{consts::U12, generic_array::GenericArray, Payload},
    AeadInPlace,
};
use prost::Message;

use super::{gen_output_prefix, get_key_id_and_ciphertext, get_random_bytes, PREFIX_SIZE};

//
// Constants
//

const MAX_TINK_AEAD_PREFIX_LENGTH: usize = 5;

pub static AEAD_ALGORITHMS: Map<&'static str, fn(&Key) -> Result<AeadKey, TinkError>> = phf_map! {
   "type.googleapis.com/google.crypto.tink.AesGcmKey" => load_aes_gcm_key
};

//
// Key loaders
//

pub fn load_aes_gcm_key(key: &Key) -> Result<AeadKey, TinkError> {
    println!("Got AES-GCM key");
    let key_data = if let Some(data) = &key.key_data {
        data
    } else {
        return Err(TinkError {});
    };

    if key_data.key_material_type != KeyMaterialType::Symmetric as i32 {
        return Err(TinkError {});
    }

    // Parse the actual AES key
    let acm_gcm_proto_bytes = key_data.value.as_slice();
    let aes_gcm_key = match AesGcmKey::decode(acm_gcm_proto_bytes) {
        Ok(key) => key,
        Err(_) => return Err(TinkError {}),
    };

    // Only version 0 keys are supported.
    if aes_gcm_key.version != 0 {
        return Err(TinkError {});
    }

    // Calculate key metadata
    let prefix = OutputPrefixType::try_from(key.output_prefix_type).unwrap();
    let key_id = key.key_id;

    match aes_gcm_key.key_value.len() {
        16 => Ok(AeadKey::AesGcm128(AesGcm128Key::new(
            &aes_gcm_key.key_value,
            prefix,
            key_id,
        ))),
        32 => Ok(AeadKey::AesGcm256(AesGcm256Key::new(
            &aes_gcm_key.key_value,
            prefix,
            key_id,
        ))),
        _ => Err(TinkError {}),
    }
}

//
// AEAD Keys
//

#[derive(Clone)]
pub enum AeadKey {
    AesGcm128(AesGcm128Key),
    AesGcm256(AesGcm256Key),
}

#[derive(Clone)]
pub struct AeadKeyset {
    keys: Vec<(u32, AeadKey)>,
}

impl AeadKeyset {
    pub fn new(keys: Vec<(u32, AeadKey)>) -> Self {
        AeadKeyset { keys }
    }
}

impl Aead for AeadKeyset {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        // The first key is always the active one.
        match &self.keys[0].1 {
            AeadKey::AesGcm128(key) => key.encrypt(plaintext, additional_data),
            AeadKey::AesGcm256(key) => key.encrypt(plaintext, additional_data),
        }
    }

    fn decrypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ciphertext.len() < 5 {
            return Err(TinkError {  });
        }

        let (key_id, ciphertext) = get_key_id_and_ciphertext(ciphertext);

        println!("Decrypting using key: {}", key_id);

        for key in self.keys.iter() {
            println!("Trying key: {}", key.0);
            if key.0 != key_id {
                continue;
            }
            return match &key.1 {
                AeadKey::AesGcm128(key) => key.decrypt(ciphertext, additional_data),
                AeadKey::AesGcm256(key) => key.decrypt(ciphertext, additional_data),
            };
        }
        Err(TinkError {})
    }
}

//
// AES-GCM
//

const AES_GCM_IV_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;

const MAX_AES_GCM_PLAINTEXT_SIZE: usize = if size_of::<usize>() == 4 {
    (isize::MAX - 1) as usize - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE
} else {
    (1 << 36) - 32
};

#[derive(Clone)]
pub struct AesGcm128Key {
    key: aes_gcm::Aes128Gcm,
    prefix: OutputPrefixType,
    prefix_bytes: [u8; MAX_TINK_AEAD_PREFIX_LENGTH],
}

impl AesGcm128Key {
    pub fn new(key: &[u8], prefix: OutputPrefixType, key_id: u32) -> Self {
        if key.len() != 16 {
            panic!("Invalid key length in AES-GCM-128 key")
        }

        AesGcm128Key {
            key: aes_gcm::Aes128Gcm::new_from_slice(key).unwrap(),
            prefix: prefix,
            prefix_bytes: gen_output_prefix(prefix, key_id),
        }
    }
}

impl Aead for AesGcm128Key {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        if plaintext.len() > MAX_AES_GCM_PLAINTEXT_SIZE {
            return Err(TinkError {});
        }

        let iv = aes_gcm_iv();
        let payload = Payload {
            msg: plaintext,
            aad: additional_data,
        };

        let ciphertext = match self.key.encrypt(&iv, payload) {
            Ok(res) => res,
            Err(_) => return Err(TinkError {}),
        };

        // TODO: Making unnecessary memory copy here. We could do the following:
        // 1. Calculate the size of the ciphertext prior to calling encrypt.
        // 2. Allocate res with the appropriate capacity
        // 3. Call the unsafe function set_len to update vectors size to avoid touching the memory.
        // 4. Copy the prefix to the beginning.
        // 5. Encrypt with output written directly to the buffer.
        let mut res = Vec::with_capacity(PREFIX_SIZE + iv.len() + ciphertext.len());

        res.extend_from_slice(&self.prefix_bytes);
        res.extend_from_slice(&iv);
        res.extend_from_slice(&ciphertext);

        println!("Encrypted plaintext of size {} generating ciphertext of size {} with raw ciphertext {}", plaintext.len(), res.len(), ciphertext.len());

        Ok(res)
    }

    fn decrypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        if ciphertext.len() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE {
            println!("Ciphertext is too short: {}", ciphertext.len());
            return Err(TinkError {  });
        }

        let iv = GenericArray::from_slice(&ciphertext[..AES_GCM_IV_SIZE]);
        let payload = Payload {
            msg: &ciphertext[AES_GCM_IV_SIZE..],
            aad: additional_data
        };

        match self.key.decrypt(iv, payload) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err(TinkError {  })
        }
    }
}

#[derive(Clone)]
pub struct AesGcm256Key {
    key: aes_gcm::Aes256Gcm,
    prefix: OutputPrefixType,
    prefix_bytes: [u8; MAX_TINK_AEAD_PREFIX_LENGTH],
}

impl AesGcm256Key {
    pub fn new(key: &[u8], prefix: OutputPrefixType, key_id: u32) -> Self {
        if key.len() != 32 {
            panic!("Invalid key length in AES-GCM-256 key")
        }

        AesGcm256Key {
            key: aes_gcm::Aes256Gcm::new_from_slice(key).unwrap(),
            prefix: prefix,
            prefix_bytes: gen_output_prefix(prefix, key_id),
        }
    }
}

impl Aead for AesGcm256Key {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        if plaintext.len() > MAX_AES_GCM_PLAINTEXT_SIZE {
            return Err(TinkError {});
        }

        let iv = aes_gcm_iv();
        let payload = Payload {
            msg: plaintext,
            aad: additional_data,
        };

        let ct = match self.key.encrypt(&iv, payload) {
            Ok(res) => res,
            Err(_) => return Err(TinkError {}),
        };

        // TODO: Making unnecessary memory copy here. We could do the following:
        // 1. Calculate the size of the ciphertext prior to calling encrypt.
        // 2. Allocate res with the appropriate capacity
        // 3. Call the unsafe function set_len to update vectors size to avoid touching the memory.
        // 4. Copy the prefix to the beginning.
        // 5. Encrypt with output written directly to the buffer.
        let mut res = Vec::with_capacity(PREFIX_SIZE + ct.len());

        res.extend_from_slice(&self.prefix_bytes);
        res.extend_from_slice(&ct);

        Ok(res)
    }

    fn decrypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        Err(TinkError {})
    }
}

fn aes_gcm_iv() -> GenericArray<u8, U12> {
    let iv = get_random_bytes(AES_GCM_IV_SIZE);
    *GenericArray::<u8, U12>::from_slice(&iv)
}
