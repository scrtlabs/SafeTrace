// use serde::{Serialize, Deserialize};
// use std::{slice};
// use std::string::String;
use enigma_tools_t::common::errors_t::{EnclaveError,  EnclaveError::*, FailedTaskError::*, EnclaveSystemError::*};
use enigma_crypto::{symmetric::decrypt};
use enigma_types::{DhKey, PubKey, EnclaveReturn};
use std::string::String;
use std::string::ToString;
use std::vec::Vec;
use std::str;
use serde_json::{Value, json};
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};


use sgx_tseal::{SgxSealedData};
use sgx_types::marker::ContiguousMemory;
use std::untrusted::fs::File;
use std::io::{Read, Write, self};
use sgx_types::{sgx_status_t, sgx_sealed_data_t};

pub enum Error {
    SliceError,
    UnsealError(sgx_status_t),
    SerializeError,
    Other
}

// TODO: Do proper mapping, using a generic for now
impl From<Error> for EnclaveError {
    fn from(other: Error) -> EnclaveError {
        EnclaveError::SystemError(MessagingError{ err: "Error unsealing data".to_string() })
    }
}

pub const SEAL_LOG_SIZE: usize = 4096;

// Structs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeolocationTime {
    lat: f32,
    lng: f32,
    startTS: i32,
    endTS: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserLocations {
  pub locations: Vec<GeolocationTime>,
  pub user_id: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct UserLocationsArray {
    key: u32,
    rand: [u8; 16],
    vec: Vec<UserLocations>
}

pub fn decrypt_userid(userid: &[u8], key: &DhKey) -> Result<Vec<u8>, EnclaveError> {
    if userid.is_empty(){
        Err(FailedTaskError(InputError { message: "encryptedUserId is empty".to_string()}))
    } else {
        Ok(decrypt(userid, key)?)
    }
}

pub fn decrypt_data(data: &[u8], key: &DhKey) -> Result<Vec<u8>, EnclaveError> {
    if data.is_empty(){
        Err(FailedTaskError(InputError { message: "encryptedData is empty".to_string()}))
    } else {
        Ok(decrypt(data, key)?)
    }
}

pub fn create_sealeddata_for_serializable(data: &UserLocations, sealed_log_out: &mut [u8; SEAL_LOG_SIZE]) -> enigma_types::EnclaveReturn {

    let encoded_vec = serde_json::to_vec(&data).unwrap();
    let encoded_slice = encoded_vec.as_slice();
    // println!("Length of encoded slice: {}", encoded_slice.len());
    // println!("Encoded slice: {:?}", encoded_slice);

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data(&aad, encoded_slice);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => { return EnclaveReturn::SgxError; },
    };

    let sealed_log = sealed_log_out.as_mut_ptr();

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, SEAL_LOG_SIZE as u32);
    if opt.is_none() {
        return EnclaveReturn::SgxError;
    }

    EnclaveReturn::Success
}

pub fn recover_sealeddata_for_serializable(sealed_log: * mut u8, sealed_log_size: u32) -> Result<UserLocations, Error> {

    let sealed_data = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size).ok_or(Error::SliceError)?;
    let unsealed_data = sealed_data.unseal_data().map_err(|err| Error::UnsealError(err))?;
    let encoded_slice = unsealed_data.get_decrypt_txt();

    // println!("Length of encoded slice: {}", encoded_slice.len());
    // println!("Encoded slice: {:?}", encoded_slice);
    let data: UserLocations = serde_json::from_slice(encoded_slice).unwrap();

    Ok(data)
}


fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<[T]>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}


// Save sealed data to disk
pub fn save_sealed_data(path: &str, sealed_data: &[u8]) {
    let opt = File::create(path);
    if opt.is_ok() {
        debug_println!("Created file => {} ", path);
        let mut file = opt.unwrap();
        let result = file.write_all(&sealed_data);
        if result.is_ok() {
            debug_println!("success writting to file! ");
        } else {
            debug_println!("error writting to file! ");
        }
    }
}

// Load sealed data from disk
pub fn load_sealed_data(path: &str, sealed_data: &mut [u8]) {
    let opt = File::open(path);
    if opt.is_ok() {
        debug_println!("Created file => {} ", path);
        let mut file = opt.unwrap();
        let result = file.read(sealed_data);
        if result.is_ok() {
            debug_println!("success writting to file! ");
        } else {
            debug_println!("error writting to file! ");
        }
    }
}

pub fn add_personal_data_internal(
    encryptedUserId: &[u8],
    encryptedData: &[u8],
    userPubKey: &PubKey,
    dhKey: &DhKey)  -> Result<(), EnclaveError> {

    println!("Add personal data inside the enclave");

    // Decrypt inputs using dhKey
    let decrypted_userid = decrypt_userid(encryptedUserId, dhKey)?;
    let decrypted_data = decrypt_data(encryptedData, dhKey)?;

    // TODO: Should not panic, propagate error instead
    let userid = match str::from_utf8(&decrypted_userid) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    }; 

    // Deserialize decrypted input data into expected format
    let mut inputData: Vec<GeolocationTime> = serde_json::from_slice(&decrypted_data).unwrap();

    // Construct user data
    let userData = UserLocations {
        user_id: userid.to_string(),
        locations: inputData,
    };

    // Seal the data and store it on disk
    let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
    create_sealeddata_for_serializable(&userData, &mut sealed_log_in);
    let p = String::from("data.sealed");
    save_sealed_data(&p, &sealed_log_in);


    // Retrieve sealed data
    let p = String::from("data.sealed");
    let mut sealed_log_out: [u8; SEAL_LOG_SIZE] = [0; SEAL_LOG_SIZE];
    load_sealed_data(&p, &mut sealed_log_out);

    let sealed_log = sealed_log_out.as_mut_ptr();
    let data = recover_sealeddata_for_serializable(sealed_log, SEAL_LOG_SIZE as u32)?;
    println!("{:?}", data);

    Ok(())
}

pub fn find_match_internal(
    encryptedUserId: &[u8],
    userPubKey: &PubKey,
    dhKey: &DhKey)  -> Result<Vec<u8>, EnclaveError> {

    // Decrypt inputs using dhKey
    let decrypted_userid = decrypt_userid(encryptedUserId, dhKey)?;

    // TODO: Should not panic, propagate error instead
    let userid = match str::from_utf8(&decrypted_userid) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    // Retrieve sealed data
    let p = String::from("data.sealed");
    let mut sealed_log_out: [u8; SEAL_LOG_SIZE] = [0; SEAL_LOG_SIZE];
    load_sealed_data(&p, &mut sealed_log_out);

    let sealed_log = sealed_log_out.as_mut_ptr();
    let data = recover_sealeddata_for_serializable(sealed_log, SEAL_LOG_SIZE as u32)?;
    println!("{:?}", data.locations);

    let mut results = data.iter().filter(|item| item.user_id != userid).filter(|item| item.lat > 0 ).collect();

    let mut buf = Vec::new();
    //let val = serde_json::to_value(data.locations).map_err(|_| Error::SerializeError)?;
    let val = json!([]);
    val.serialize(&mut Serializer::new(&mut buf)).map_err(|_| Error::SerializeError)?;

    Ok(buf)
}