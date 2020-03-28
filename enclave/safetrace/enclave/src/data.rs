use serde::{Serialize, Deserialize};
// use std::{slice};
use std::string::String;
use errors_t::EnclaveError;
use types::{PubKey, DhKey};


// Structs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeolocationTime {
    lat: i32,
    lng: i32,
    startTS: i32,
    endTS: i32
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Request {
    encryptedUserId: String,
    encryptedData: String,
    userPubKey: String
}

pub fn ecall_add_personal_data_internal(
    encryptedUserId: &[u8],
    encryptedData: &[u8],
    userPubKey: &PubKey,
    dhKey: &DhKey)  -> Result<(), EnclaveError> {


    println!("Add personal data inside the enclave");

    println!("{:?}", dhKey);
    println!("Received UserPub Key Again: {:?}", userPubKey.to_vec());


    // // let str_slice = unsafe { slice::from_raw_parts(data_json, some_len) };

    // // Input sanitised in EngimaJS to object type
    // let mut request: Request = serde_json::from_slice(str_slice).unwrap();

    // println!("EncryptedUserId: {:?}", request.encryptedUserId);

    // let inputkey = request.userPubKey;



    // Read from the state
    // let mut data = Self::get_data();
    // Append
    // data.append(&mut array);
    // Write back to the state
    // write_state!(DATASET => data);

    // Ocall to normal world for output
    //println!("Received Data: {:?}", &request);

    Ok(())
}