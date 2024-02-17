use crate::error::TinkError;

pub trait Aead: AeadBoxClone {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError>;

    fn decypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, TinkError>;
}

pub trait AeadBoxClone {
    fn box_clone(&self) -> Box<dyn Aead + Send>;
}

impl<T> AeadBoxClone for T
where
    T: 'static + Aead + Clone + Send,
{
    fn box_clone(&self) -> Box<dyn Aead + Send> {
        Box::new(self.clone())
    }
}
