// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "safetraceenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_trts;
extern crate sgx_tseal;
#[macro_use]
extern crate lazy_static;

// extern crate sgx_serialize;
// #[macro_use]
// extern crate sgx_serialize_derive;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::{slice};
//use std::{path::PathBuf, str};


extern crate serde;
extern crate serde_json;
extern crate secp256k1;
extern crate tiny_keccak;
extern crate sha2;
extern crate rustc_hex;
extern crate arrayvec;

#[macro_use]
mod macros;
mod errors_t;
mod data;
mod keys_t;
mod storage;
mod types;
mod hash;
mod traits;

use keys_t::{ecall_get_user_key_internal, KeyPair};
use data::ecall_add_personal_data_internal;
use storage::*;
use types::EnclaveReturn;
use errors_t::EnclaveError;
use traits::SliceCPtr;

lazy_static! {
    pub(crate) static ref SIGNING_KEY: KeyPair = get_sealed_keys_wrapper();
}

extern "C" {
    fn ocall_save_to_memory(ptr: *mut u64, data_ptr: *const u8, data_len: usize) -> sgx_status_t;
}


// TODO: Replace u64 with *const u8, and pass it via the ocall using *const *const u8
pub fn save_to_untrusted_memory(data: &[u8]) -> Result<u64, EnclaveError> {
    let mut ptr = 0u64;
    match unsafe { ocall_save_to_memory(&mut ptr as *mut u64, data.as_c_ptr(), data.len()) } {
        sgx_status_t::SGX_SUCCESS => Ok(ptr),
        e => Err(e.into()),
    }
}

fn get_sealed_keys_wrapper() -> KeyPair {
    // // Get Home path via Ocall
    // let mut path_buf = get_home_path().unwrap();
    // // add the filename to the path: `keypair.sealed`
    // path_buf.push("keypair.sealed");
    // let sealed_path = path_buf.to_str().unwrap();

    // TODO: Decide what to do if failed to obtain keys.
    match get_sealed_keys("keypair.sealed") {
        Ok(key) => key,
        Err(err) => panic!("Failed obtaining keys: {:?}", err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ecall_get_user_key(sig: &mut [u8; 65], user_pubkey: &[u8; 64], serialized_ptr: *mut u64) -> EnclaveReturn  {
    println!("Get User Key called inside enclave");
    let msg = match ecall_get_user_key_internal(sig, user_pubkey) {
        Ok(msg) => msg,
        Err(e) => return e.into(),
    };
    *serialized_ptr = match save_to_untrusted_memory(&msg[..]) {
        Ok(ptr) => ptr,
        Err(e) => return e.into(),
    };
    EnclaveReturn::Success
}

#[no_mangle]
pub extern "C" fn ecall_add_personal_data(data_string: *const u8, data_len: usize) -> sgx_status_t {
    ecall_add_personal_data_internal(data_string, data_len);
    sgx_status_t::SGX_SUCCESS
}