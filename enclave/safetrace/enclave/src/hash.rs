use tiny_keccak::Keccak;
use types::Hash256;


/// Takes a list of variables and concat them together with lengths in between.
/// What this does is appends the length of the messages before each message and makes one big slice from all of them.
/// e.g.: `S(H(len(a)+a, len(b)+b...))`
/// # Examples
/// ```
/// use hash;
/// let msg = b"sign";
/// let msg2 = b"this";
/// let ready = hash::prepare_hash_multiple(&[msg, msg2]);
/// ```
pub fn prepare_hash_multiple<B: AsRef<[u8]>>(messages: &[B]) -> std::vec::Vec<u8> {
    use std::{vec::Vec, mem};
    let mut res = Vec::with_capacity(messages.len() * mem::size_of::<usize>());
    for msg in messages {
        let msg = msg.as_ref();
        let len = msg.len().to_be_bytes();
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
    }
    res
}

// Hash a byte array into keccak256.
pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}

pub trait Sha256<T> {
    fn sha256(&self) -> T where T: Sized;
}

impl Keccak256<Hash256> for [u8] {
    fn keccak256(&self) -> Hash256 {
        let mut keccak = Keccak::new_keccak256();
        let mut result = Hash256::default();
        keccak.update(self);
        keccak.finalize(result.as_mut());
        result
    }
}

impl Sha256<Hash256> for [u8] {
    fn sha256(&self) -> Hash256 {
        use sha2::{Digest};
        let mut hasher = sha2::Sha256::new();
        hasher.input(&self);
        let mut result = Hash256::default();
        result.copy_from_slice(&hasher.result());
        result
    }
}