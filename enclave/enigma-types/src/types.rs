//! # Types module
//! This module should provide low level types, enums and structures that are required on both sides of the SGX.
//! All enums and structures should have `#[repr(C)]` on them so they would be aligned just like in C
//! See [`Repr(C)`][https://doc.rust-lang.org/nomicon/other-reprs.html]
//!
//! Any new type here that should pass through the edl should be added into the [`build.rs]` file,
//! so it will put it into the auto generated C header.
//!
//! Note: Please use the right types even if they're only aliases right now,
//! this helps both for readability and if in the future we decide to change the alias.

use core::{fmt, mem, ptr, default::Default};

pub use crate::hash::Hash256;
/// The size of the symmetric 256 bit key we use for encryption (in bytes).
pub const SYMMETRIC_KEY_SIZE: usize = 256 / 8;
/// symmetric key we use for encryption.
pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];
/// StateKey is the key used for state encryption.
pub type StateKey = SymmetricKey;
/// DHKey is the key that results from the ECDH [`enigma_crypto::KeyPair::derive_key`](../replace_me)
pub type DhKey = SymmetricKey;
/// ContractAddress is the address of contracts in the Enigma Network.
pub type ContractAddress = Hash256;
/// PubKey is a public key that is used for ECDSA signing.
pub type PubKey = [u8; 64];


/// This enum is used to return from an ecall/ocall to represent if the operation was a success and if not then what was the error.
/// The goal is to not reveal anything sensitive
/// `#[repr(C)]` is a Rust feature which makes the struct be aligned just like C structs.
/// See [`Repr(C)`][https://doc.rust-lang.org/nomicon/other-reprs.html]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EnclaveReturn {
    /// Success, the function returned without any failure.
    Success,
    /// TaskFailure, the task(Deploy/Compute) has failed
    TaskFailure,
    /// KeysError, There's a key missing or failed to derive a key.
    KeysError,
    /// Failure in Encryption, couldn't decrypt the variable / failed to encrypt the results.
    EncryptionError,
    // TODO: I'm not sure this error is used anywhere.
    /// SigningError, for some reason it failed on signing the results.
    SigningError,
    // TODO: Also don't think this is needed.
    /// RecoveringError, Something failed in recovering the public key.
    RecoveringError,
    ///PermissionError, Received a permission error from an ocall, (i.e. opening the signing keys file or something like that)
    PermissionError,
    /// SgxError, Error that came from the SGX specific stuff (i.e DRAND, Sealing etc.)
    SgxError,
    /// StateError, an Error in the State. (i.e. failed applying delta, failed deserializing it etc.)
    StateError,
    /// OcallError, an error from an ocall.
    OcallError,
    /// OcallDBError, an error from the Database in the untrusted part, couldn't get/save something.
    OcallDBError,
    /// MessagingError, a message that received couldn't be processed (i.e. KM Message, User Key Exchange etc.)
    MessagingError,
    /// WorkerAuthError, Failed to authenticate the worker, this is specific to the KM node.
    WorkerAuthError,
    // TODO: should consider merging with a different error.
    /// Missing StateKeys in the KM node.
    KeyProvisionError,
    /// Something went really wrong.
    Other
}


/// This struct is basically some sort of a boolean that says if an operation was a success or a failure.
#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum ResultStatus {
    /// Ok = Success = 1.
    Ok = 1,
    /// Failure = Error = 0.
    Failure = 0,
}


/// This struct is what returned from a Deploy/Compute ecall, it contains all the needed data.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecuteResult {
    /// A pointer to the output of the execution using [`ocall_save_to_memory`](../replace_me) (on the untrusted stack)
    pub output: *const u8,
    /// A pointer to the resulting delta using [`ocall_save_to_memory`](../replace_me) (on the untrusted stack)
    pub delta_ptr: *const u8,
    /// The delta index number.
    pub delta_index: u32,
    /// A pointer to the Ethereum payload using [`ocall_save_to_memory`](../replace_me) (on the untrusted stack)
    pub ethereum_payload_ptr: *const u8,
    /// The ethereum address that the payload belongs to.
    pub ethereum_address: [u8; 20],
    /// A signature by the enclave on all of the results.
    pub signature: [u8; 65],
    /// The gas used by the execution.
    pub used_gas: u64,
}

/// This struct is a wrapper to a raw pointer.
/// when you pass a pointer through the SGX bridge(EDL) the SGX Edger8r will copy the data that it's pointing to
/// using `memalloc` and `memset` to the other side of the bridge, then it changes the pointer to point to the new data.
///
/// So this struct is needed if you want to pass a pointer from one side to the other while the pointer still points to the right locaiton.
///
/// Say you want to give the enclave a DB on the untrusted, so that the enclave can then pass that pointer to an ocall.
/// This will let you do it without the Edger8r messing with the pointer.
///
/// And I tried to add a mutability bool to make it a little more safe by giving you a pointer based on the original mutability.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawPointer {
    ptr: *const u8,
    _mut: bool
}

impl RawPointer {
    /// Creates a new RawPointer wrapper.
    /// it will auto cast the reference into a raw pointer.
    pub unsafe fn new<T>(reference: &T) -> Self {
        RawPointer { ptr: reference as *const T as *const u8, _mut: false }
    }

    /// Creates a new mutable RawPointer wrapper.
    /// This is needed if when you unwrap this you want a mutable pointer.
    pub unsafe fn new_mut<T>(reference: &mut T) -> Self {
        RawPointer { ptr: reference as *mut T as *const u8, _mut: true }
    }

    /// This will return the underlying const raw pointer.
    pub fn get_ptr<T>(&self) -> *const T {
        self.ptr as *const T
    }

    /// this will return a Result and if the RawPointer was created with `new_mut`
    /// it Will return `Ok` with the underlying mut raw pointer.
    /// if the struct was created with just `new` it will return `Err`.
    pub fn get_mut_ptr<T>(&self) -> Result<*mut T, &'static str> {
        if !self._mut {
            Err("This DoublePointer is not mutable")
        } else {
            Ok(self.ptr as *mut T)
        }
    }

    /// This will unsafely cast the underlying pointer back into a reference.
    pub unsafe fn get_ref<T>(&self) ->  &T {
        &*(self.ptr as *const T)
    }

    /// This will unsafely cast the underlying pointer back into a mut pointer.
    /// it will return a result and have the same rules as [`get_mut_ptr`]
    ///
    /// [`get_mut_ptr`]: #method.get_mut_ptr
    pub unsafe fn get_mut_ref<T>(&self) -> Result<&mut T, &'static str> {
        if !self._mut {
            Err("This DoublePointer is not mutable")
        } else {
            Ok(&mut *(self.ptr as *mut T) )
        }
    }


}

impl From<bool> for ResultStatus {
    fn from(i: bool) -> Self {
        if i {
            ResultStatus::Ok
        } else {
            ResultStatus::Failure
        }
    }
}

impl Default for ExecuteResult {
    fn default() -> ExecuteResult {
        ExecuteResult {
            output: ptr::null(),
            delta_ptr: ptr::null(),
            ethereum_payload_ptr: ptr::null(),
            .. unsafe { mem::zeroed() }
        }
    }
}

impl fmt::Debug for ExecuteResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_trait_builder = f.debug_struct("ExecuteResult");
        debug_trait_builder.field("output", &(self.output));
        debug_trait_builder.field("delta_ptr", &(self.delta_ptr));
        debug_trait_builder.field("delta_index", &(self.delta_index));
        debug_trait_builder.field("ethereum_payload_ptr", &(self.ethereum_payload_ptr));
        debug_trait_builder.field("ethereum_address", &(self.ethereum_address));
        debug_trait_builder.field("signature", &(&self.signature[..]));
        debug_trait_builder.field("used_gas", &(self.used_gas));
        debug_trait_builder.finish()
    }
}

impl Default for EnclaveReturn {
    fn default() -> EnclaveReturn { EnclaveReturn::Success }
}

impl fmt::Display for EnclaveReturn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::EnclaveReturn::*;
        let p = match *self {
            Success => "EnclaveReturn: Success",
            TaskFailure => "EnclaveReturn: Task failure",
            KeysError => "EnclaveReturn: KeysError",
            EncryptionError => "EnclaveReturn: EncryptionError",
            SigningError => "EnclaveReturn: SigningError",
            RecoveringError => "EnclaveReturn: RecoveringError",
            PermissionError => "EnclaveReturn: PermissionError",
            SgxError => "EnclaveReturn: SgxError",
            StateError => "EnclaveReturn: StateError",
            OcallError => "EnclaveReturn: OcallError",
            OcallDBError => "EnclaveReturn: OcallDBError",
            MessagingError => "EnclaveReturn: MessagingError",
            WorkerAuthError => "EnclaveReturn: WorkerAuthError",
            KeyProvisionError => "EnclaveReturn: KeyProvisionError",
            Other => "EnclaveReturn: Other",
        };
        write!(f, "{}", p)
    }
}


/// This trait will convert a Result into EnclaveReturn.
///
/// I used this because there's a problem.
/// we want to convert  [`enigma_tools_t::common::errors::EnclaveError`](../replace_me) into [`EnclaveReturn`] to return it back through the EDL.
/// *but* in this module we can't impl [`From`](core::convert::From) from `EnclaveError` to `EnclaveReturn` because this crate is `std` pure
/// so it doesn't have access to `enigma_tools_t`.
/// And we can't implement this as `Into<EncalveReturn> for Result<(), EnclaveError>` in `enigma_tools_t`
/// because in rust you can't implement an imported trait(`From`/`Into`) on a type you imported (`Result`).
///
/// So my solution was to declare a new trait, and to implement [`core::convert::From`] on whatever implements my trait through generics.
/// that way all we need is to implement `ResultToEnclaveReturn` on `EnclaveError` and it will auto generate a `From` impl for it.
///
/// And if the Result is `Ok` it will return `EnclaveReturn::Success` and if `Err` it will convert using this trait.
pub trait ResultToEnclaveReturn {
    /// Should return a EnclaveReturn while consuming self.
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
