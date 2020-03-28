use core::ops::{Deref, DerefMut};
use rustc_hex::{FromHex, FromHexError};
use arrayvec::ArrayVec;


pub type SymmetricKey = [u8; 32];
pub type StateKey = SymmetricKey;
pub type DhKey = SymmetricKey;
pub type PubKey = [u8; 64];


#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EnclaveReturn {
    Success,
    TaskFailure,
    KeysError,
    EncryptionError,
    SigningError,
    PermissionError,
    SgxError,
    StateError,
    OcallError,
    OcallDBError,
    MessagingError,
    Other,
//    Uninitialized,
}

impl Default for EnclaveReturn {
    fn default() -> EnclaveReturn { EnclaveReturn::Success }
}

impl ::std::fmt::Display for EnclaveReturn {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        use self::EnclaveReturn::*;
        let p = match *self {
            Success => "EnclaveReturn: Success",
            TaskFailure => "EnclaveReturn: Task failure",
            KeysError => "EnclaveReturn: KeysError",
            EncryptionError => "EnclaveReturn: EncryptionError",
            SigningError => "EnclaveReturn: SigningError",
            PermissionError => "EnclaveReturn: PermissionError",
            SgxError => "EnclaveReturn: SgxError",
            StateError => "EnclaveReturn: StateError",
            OcallError => "EnclaveReturn: OcallError",
            OcallDBError => "EnclaveReturn: OcallDBError",
            MessagingError => "EnclaveReturn: MessagingError",
            Other => "EnclaveReturn: Other",
        };
        write!(f, "{}", p)
    }
}

pub trait ResultToEnclaveReturn {
    fn into_enclave_return(self) -> EnclaveReturn;
}

impl<T: ResultToEnclaveReturn> From<Result<(), T>> for EnclaveReturn {
    fn from(res: Result<(), T>) -> Self {
        match res {
            Ok(()) => EnclaveReturn::Success,
            Err(e) => ResultToEnclaveReturn::into_enclave_return(e),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
#[repr(C)]
pub struct Hash256([u8; 32]);


impl Hash256 {
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        self.0.copy_from_slice(src)
    }

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

impl AsMut<[u8]> for Hash256 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}