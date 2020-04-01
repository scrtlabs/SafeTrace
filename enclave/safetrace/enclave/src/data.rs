use enigma_tools_t::common::errors_t::{EnclaveError,  EnclaveError::*, FailedTaskError::*, EnclaveSystemError::*};
use enigma_crypto::{symmetric::decrypt, symmetric::encrypt};
use enigma_types::{DhKey, PubKey, EnclaveReturn};
use std::{
    string::{String,ToString},
    vec::Vec,
    str,
    collections::HashMap
};

use serde_json::{Value, json};
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};

use sgx_tseal::{SgxSealedData};
use sgx_types::marker::ContiguousMemory;
use std::untrusted::fs::File;
use std::io::{Read, Write, self};
use sgx_types::{sgx_status_t, sgx_sealed_data_t};

pub const DATAFILE: &str = "data.sealed";
pub const TOVERLAP: i32 = 300;             // 5min * 60s minimum overlap
pub const DISTANCE: f64 = 10.0;            // in meters
pub const EARTH_RADIUS: f64 = 6371000.0;   // in meters
pub const SEAL_LOG_SIZE: usize = 4096; // Maximum data can seal in bytes -> match 


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

// Structs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeolocationTime {
    lat: f64,
    lng: f64,
    startTS: i32,
    endTS: i32,
    testResult: bool
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

//pub fn create_sealeddata_for_serializable(data: &UserLocations, sealed_log_out: &mut [u8; SEAL_LOG_SIZE]) -> enigma_types::EnclaveReturn {
pub fn create_sealeddata_for_serializable(data: HashMap<String, Vec<GeolocationTime>>, sealed_log_out: &mut [u8; SEAL_LOG_SIZE]) -> enigma_types::EnclaveReturn {

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

pub fn recover_sealeddata_for_serializable(sealed_log: * mut u8, sealed_log_size: u32) -> Result<HashMap<String, Vec<GeolocationTime>>, Error> {

    let sealed_data = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size).ok_or(Error::SliceError)?;
    let unsealed_data = sealed_data.unseal_data().map_err(|err| Error::UnsealError(err))?;
    let encoded_slice = unsealed_data.get_decrypt_txt();

    // println!("Length of encoded slice: {}", encoded_slice.len());
    // println!("Encoded slice: {:?}", encoded_slice);
    
    let data: HashMap<String, Vec<GeolocationTime>> = serde_json::from_slice(encoded_slice).unwrap();

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
pub fn load_sealed_data(path: &str, sealed_data: &mut [u8]) -> Result<(), String> {
    let mut file = match File::open(path) {
        Err(why) => return Err("Error opening the file".to_string()),
        Ok(file) => file,
    };
    debug_println!("Created file => {} ", path);
        
    let result = file.read(sealed_data);
    if result.is_ok() {
        debug_println!("success reading from file! ");
    } else {
        debug_println!("error reading from file! ");
    }
    Ok(())

}

pub fn unseal_data_wrapper() -> Result<HashMap<String, Vec<GeolocationTime>>, Error> {
    let p = DATAFILE;
    let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
    match load_sealed_data(&p, &mut sealed_log_out) {
        Ok(_) => {
            let sealed_log = sealed_log_out.as_mut_ptr();
            let mut data = recover_sealeddata_for_serializable(sealed_log, SEAL_LOG_SIZE as u32)?;
            Ok(data)
        },
        Err(err) => {
            let mut data = HashMap::new();
            Ok(data)
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

    let mut data = unseal_data_wrapper()?;
    //let mut data = HashMap::new();

    data.insert(userid.to_string(), inputData);

    // Seal the data and store it on disk
    let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
    create_sealeddata_for_serializable(data, &mut sealed_log_in);

    let p = DATAFILE;
    save_sealed_data(&p, &sealed_log_in);

    let mut newdata = unseal_data_wrapper()?;
    println!("This is what we got");
    println!("{:?}", newdata);

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

    let data = unseal_data_wrapper()?;

    let mut results = Vec::new();

    // This is the algorithm to find overlaps in time and space, defined in time by TOVERLAP (in seconds)
    // and in space by DISTANCE (in meters)
    // We iterate over all values in the set, excluding the user we are looking for matches. 
    // For all of them, we iterate over all locations and compare them with all locations from the user
    for (key, val) in data.iter() {
        if key != &userid {
            for d in data[userid].clone() {
                for e in val.iter() {
                    if e.testResult {
                        // It's easier to find overlaps in time because it's a direct comparison of integers
                        // so handle this first:
                        // Both time intervals have to be larger than the minumum time overlap TOVERLAP
                        // and both start times + TOVERLAP have to be smaller than the other end times
                        if d.endTS - d.startTS > TOVERLAP &&
                           e.endTS - e.startTS > TOVERLAP &&
                           d.startTS + TOVERLAP < e.endTS && e.startTS + TOVERLAP < d.endTS {
                            // We start comparing distance between latitudes. Each degree of lat is aprox
                            // 111 kms (range varies between 110.567 km at the equator to 111.699 km at the poles)
                            // The distance between two locations will be equal or larger than the distance between 
                            // their latitudes (or the distance between lats will be smaller than the distance * cos(45))
                            // Source:
                            // https://stackoverflow.com/questions/5031268/algorithm-to-find-all-latitude-longitude-locations-within-a-certain-distance-fro
                            if (e.lat - d.lat).abs() * 111000.0 <  DISTANCE * 0.71 {
                                // then we can run a more computationally expensive and precise comparison
                                if (e.lat.sin()*d.lat.sin()+e.lat.cos()*d.lat.cos()*(e.lng-d.lng).cos()).acos() * EARTH_RADIUS < DISTANCE {
                                    results.push(d.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let serialized_results = serde_json::to_string(&results).map_err(|err| Error::SerializeError)?;
    let array_u8_results = serialized_results.as_bytes();
    let encrypted_output = encrypt(array_u8_results, dhKey)?;

    Ok(encrypted_output)
}