#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unused_extern_crates, missing_docs, warnings)]
//! # Enigma Types
//! This library is meant to supply all the types that are specific to our protocol. <br>
//! Inside of this library I abstracted the std as `localstd` so that you can use it without knowing if it's `sgx_tstd` or regular std.
//! *But* Unlike other crates this isn't just abstracting 2 different std's,
//! but this crate is expected to work even without std at all(except some parts maybe).
//!
//! in the `build.rs` I use `cbindgen` to auto generate `enigma-types.h` header so it can be included into the edl.
//! that way we can pass rust structs through the SGX bridge(which is C)
//!
//! This crate is Rust 2018 Edition,
//! meaning there's no `extern crate` and `use` statements need to start with `crate`/`self`/`super`.


pub mod traits;
mod types;
mod hash;

#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;

#[cfg(not(feature = "sgx"))]
use serde_std as serde;

use crate::traits::SliceCPtr;
pub use crate::types::*;

/// This is a bit safer wrapper of [`core::ptr::copy_nonoverlapping`]
/// it checks that the src len is at least as big as `count` otherwise it will panic.
/// *and* it uses [`SliceCPtr`](crate::traits::SliceCPtr) trait to pass a C compatible pointer.
pub unsafe fn write_ptr<T>(src: &[T], dst: *mut T, count: usize) {
    if src.len() > count {
        unimplemented!()
    }
    core::ptr::copy_nonoverlapping(src.as_c_ptr(), dst, src.len());
}
