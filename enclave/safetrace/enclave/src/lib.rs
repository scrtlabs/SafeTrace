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
#![no_std]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate enigma_runtime_t;
#[macro_use]
extern crate enigma_tools_t;
extern crate enigma_crypto;
extern crate enigma_tools_m;
extern crate enigma_types;

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

extern crate sgx_rand;
// extern crate sgx_trts;
extern crate sgx_tseal;
#[macro_use]
extern crate lazy_static;

extern crate serde;
// #[macro_use]
extern crate serde_json;

// extern crate sgx_serialize;
// #[macro_use]
// extern crate sgx_serialize_derive;

use std::{slice};

// extern crate serde;
// extern crate secp256k1;
// extern crate tiny_keccak;
// extern crate sha2;
// extern crate rustc_hex;
// extern crate arrayvec;
// extern crate ring;

// #[macro_use]
// mod macros;
// mod errors_t;
mod data;
mod keys_t;
// // mod storage;
// mod types;
// mod hash;
// mod traits;

use sgx_types::*;
use keys_t::{ecall_get_user_key_internal};
use data::ecall_add_personal_data_internal;
// use storage::*;
use enigma_types::{PubKey, DhKey, EnclaveReturn};
use enigma_tools_t::{
    common::errors_t::{EnclaveError},
    storage_t,
    quote_t,
};
use enigma_tools_m::utils::EthereumAddress;

use enigma_tools_m::utils::{LockExpectMutex};
use enigma_crypto::{asymmetric, CryptoError};



// use traits::SliceCPtr;

use enigma_tools_t::{esgx::ocalls_t};

lazy_static! {
    pub(crate) static ref SIGNING_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper();
}

#[no_mangle]
pub extern "C" fn ecall_get_registration_quote(target_info: &sgx_target_info_t, real_report: &mut sgx_report_t) -> sgx_status_t {
    quote_t::create_report_with_data(&target_info, real_report, &SIGNING_KEY.get_pubkey().address())
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_address(pubkey: &mut [u8; 20]) { pubkey.copy_from_slice(&SIGNING_KEY.get_pubkey().address()); }


fn get_sealed_keys_wrapper() -> asymmetric::KeyPair {
    // // Get Home path via Ocall
    // let mut path_buf = get_home_path().unwrap();
    // // add the filename to the path: `keypair.sealed`
    // path_buf.push("keypair.sealed");
    // let sealed_path = path_buf.to_str().unwrap();

    // TODO: Decide what to do if failed to obtain keys.
    match storage_t::get_sealed_keys("keypair.sealed") {
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
    *serialized_ptr = match ocalls_t::save_to_untrusted_memory(&msg[..]) {
        Ok(ptr) => ptr,
        Err(e) => return e.into(),
    };
    EnclaveReturn::Success
}

fn get_io_key(user_key: &PubKey) -> Result<DhKey, EnclaveError> {
    let io_key = keys_t::DH_KEYS
        .lock_expect("User DH Key")
        .remove(&user_key[..])
        .ok_or(CryptoError::MissingKeyError { key_type: "DH Key" })?;
    Ok(io_key)
}

#[no_mangle]
pub unsafe extern "C" fn ecall_add_personal_data(
    encryptedUserId: *const u8,
    encryptedUserId_len: usize,
    encryptedData: *const u8,
    encryptedData_len: usize,
    userPubKey: &[u8; 64]) -> EnclaveReturn {

    let encryptedUserId = slice::from_raw_parts(encryptedUserId, encryptedUserId_len);
    let encryptedData = slice::from_raw_parts(encryptedData, encryptedData_len);

    let io_key;
    match get_io_key(userPubKey) {
        Ok(v) => io_key = v,
        Err(e) => return e.into(),
    }

    let result = ecall_add_personal_data_internal(encryptedUserId, encryptedData, userPubKey, &io_key);
    EnclaveReturn::Success
}