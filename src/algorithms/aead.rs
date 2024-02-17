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

//
// Constants
//

const MAX_TINK_AEAD_PREFIX_LENGTH: usize = 5;

const AES_GCM_IV_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;
const MAX_AES_GCM_PLAINTEXT_SIZE: u64 = (1 << 36) - 32;

pub static AEAD_ALGORITHMS: Map<&'static str, fn(&Key) -> Result<AeadKey, TinkError>> = phf_map! {
   "type.googleapis.com/google.crypto.tink.AesGcmKey" => load_aes_gcm_key
};

//
// Key loaders
//

pub fn load_aes_gcm_key(key: &Key) -> Result<AeadKey, TinkError> {
    println!("Got AES-GCM key");
    let key_data = if let Some(data) = key.key_data {
        data
    } else {
        return Err(TinkError {});
    };

    if key_data.key_material_type != KeyMaterialType::Symmetric as i32 {
        return Err(TinkError {});
    }

    // Parse the actual AES key
    let acm_gcm_proto_bytes = key_data.value;
    let aes_gcm_key = match AesGcmKey::decode(acm_gcm_proto_bytes.as_slice()) {
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
    pub keys: Vec<AeadKey>,
    // We store at index i the ID for keys[i].
    // This is more memory efficient than a hashmap and presumably the number of keys will be small enough
    // that a consecutive scan through a buffer is faster than a hash table lookup.
    pub ids: Vec<u32>,
}

impl Aead for AeadKeyset {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        // The first key is always the active one.
        match &self.keys[0] {
            AeadKey::AesGcm128(key) => key.encrypt(plaintext, additional_data),
            AeadKey::AesGcm256(key) => key.encrypt(plaintext, additional_data),
        }
    }

    fn decypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        // TODO: Parse header to figure out right key version
        match &self.keys[0] {
            AeadKey::AesGcm128(key) => key.decypt(ciphertext, additional_data),
            AeadKey::AesGcm256(key) => key.decypt(ciphertext, additional_data),
        }
    }
}

//
// AES-GCM
//

#[derive(Clone)]
pub struct AesGcm128Key {
    key: aes_gcm::Aes128Gcm,
    key_id: u32,
    prefix: OutputPrefixType,
    prefix_bytes: [u8; MAX_TINK_AEAD_PREFIX_LENGTH],
}

impl AesGcm128Key {
    pub fn new(key: &[u8], prefix: OutputPrefixType, key_id: u32) -> Self {
        if key.len() != 16 {
            panic!("Invalid key length in AES-GCM-128 key")
        }

        // TODO: Calculate the prefix bytes

        AesGcm128Key {
            key: aes_gcm::Aes128Gcm::new_from_slice(key).unwrap(),
            key_id: key_id,
            prefix: prefix,
            prefix_bytes: [0; MAX_TINK_AEAD_PREFIX_LENGTH],
        }
    }
}

impl Aead for AesGcm128Key {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
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
        let mut res = Vec::with_capacity(get_prefix_length(self.prefix) + ct.len());

        let prefix_length = get_prefix_length(self.prefix);
        res.extend_from_slice(&self.prefix_bytes[0..prefix_length]);
        res.extend_from_slice(&ct);

        Ok(res)
    }

    fn decypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        Err(TinkError {})
    }
}

#[derive(Clone)]
pub struct AesGcm256Key {
    key: aes_gcm::Aes256Gcm,
    key_id: u32,
    prefix: OutputPrefixType,
    prefix_bytes: [u8; MAX_TINK_AEAD_PREFIX_LENGTH],
}

impl AesGcm256Key {
    pub fn new(key: &[u8], prefix: OutputPrefixType, key_id: u32) -> Self {
        if key.len() != 32 {
            panic!("Invalid key length in AES-GCM-256 key")
        }

        // TODO: Calculate the prefix bytes

        AesGcm256Key {
            key: aes_gcm::Aes256Gcm::new_from_slice(key).unwrap(),
            key_id: key_id,
            prefix: prefix,
            prefix_bytes: [0; MAX_TINK_AEAD_PREFIX_LENGTH],
        }
    }
}

impl Aead for AesGcm256Key {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
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
        let mut res = Vec::with_capacity(get_prefix_length(self.prefix) + ct.len());

        let prefix_length = get_prefix_length(self.prefix);
        res.extend_from_slice(&self.prefix_bytes[0..prefix_length]);
        res.extend_from_slice(&ct);

        Ok(res)
    }

    fn decypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError> {
        Err(TinkError {})
    }
}

fn aes_gcm_iv() -> GenericArray<u8, U12> {
    // TODO: INSECURE FIX
    let iv = [0; AES_GCM_IV_SIZE];
    *GenericArray::<u8, U12>::from_slice(&iv)
}

fn get_prefix_length(prefix: OutputPrefixType) -> usize {
    match prefix {
        OutputPrefixType::Raw => 0,
        OutputPrefixType::UnknownPrefix => {
            panic!("Logic error, should not happen");
        }
        OutputPrefixType::Crunchy => 5,
        OutputPrefixType::Legacy => 5,
        OutputPrefixType::Tink => 5,
    }
}
