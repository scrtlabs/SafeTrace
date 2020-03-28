//! # Hash Module
//! This module provides a struct meant for containing Hashes (Kecack256 or Sha256).

use core::ops::{Deref, DerefMut};
use rustc_hex::{FromHex, FromHexError};
use arrayvec::ArrayVec;
use crate::serde::{Serialize, Deserialize};

/// This struct is basically a wrapper over `[u8; 32]`, and is meant to be returned from whatever hashing functions we use.
/// `#[repr(C)]` is a Rust feature which makes the struct be aligned just like C structs.
/// See [`Repr(C)`][https://doc.rust-lang.org/nomicon/other-reprs.html]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
#[serde(crate = "crate::serde")]
#[repr(C)]
pub struct Hash256([u8; 32]);


impl Hash256 {
    /// This method exposes rust's built in [`copy_from_slice`][https://doc.rust-lang.org/std/primitive.slice.html#method.copy_from_slice]
    /// Copies the elements from `src` into `self`.
    ///
    /// The length of `src` must be the same as `self`.
    ///
    /// # Panics
    ///
    /// This function will panic if the two slices have different lengths.
    ///
    /// This might not be needed since we implement `Deref` and `DerefMut` for the inner array.
   pub fn copy_from_slice(&mut self, src: &[u8]) {
        self.0.copy_from_slice(src)
    }

    /// This function converts a hex string into `Hash256` type.
    /// the hex must not contain `0x` (as is usually the case in hexs in rust)
    /// if the hex length isn't 64 (which will be converted into the 32 bytes) it will return an error.
    pub fn from_hex(hex: &str) -> Result<Self, FromHexError> {
        if hex.len() != 64 {
            return Err(FromHexError::InvalidHexLength);
        }
        let hex_vec: ArrayVec<[u8; 32]> = hex.from_hex()?;
        let mut result = Self::default();
        result.copy_from_slice(&hex_vec);
        Ok(result)
    }

    /// Checks if the struct contains only zeroes or not.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8;32]
    }
}


impl From<[u8; 32]> for Hash256 {
    fn from(arr: [u8; 32]) -> Self {
        Hash256(arr)
    }
}

impl Into<[u8; 32]> for Hash256 {
    fn into(self) -> [u8; 32] {
        self.0
    }
}

impl Deref for Hash256 {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl DerefMut for Hash256 {
    fn deref_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Hash256 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use super::Hash256;
    #[test]
    fn test_hex_succeed() {
        let a = "0101010101010101010101010101010101010101010101010101010101010101";
        Hash256::from_hex(&a).unwrap();
    }

    #[should_panic]
    #[test]
    fn test_hex_long() {
        let a = "02020202020202020202020202020202020202020202020202020202020202020202024444020202020202";
        Hash256::from_hex(&a).unwrap();
    }
}