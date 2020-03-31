use crate::SIGNING_KEY;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_m::utils::LockExpectMutex;
use enigma_crypto::asymmetric::KeyPair;
use enigma_tools_m::primitives::km_primitives::UserMessage;
use enigma_types::{DhKey, PubKey};
use std::collections::HashMap;
use std::{sync::SgxMutex, vec::Vec};

lazy_static! { pub static ref DH_KEYS: SgxMutex<HashMap<Vec<u8>, DhKey>> = SgxMutex::new(HashMap::new()); }

pub(crate) unsafe fn ecall_get_user_key_internal(sig: &mut [u8; 65], user_pubkey: &PubKey) -> Result<Vec<u8>, EnclaveError> {
    let keys = KeyPair::new()?;
    let req = UserMessage::new(keys.get_pubkey());
    *sig = SIGNING_KEY.sign(&req.to_sign())?;
    let msg = req.into_message()?;
    let enc_key = keys.derive_key(&user_pubkey)?;
    DH_KEYS.lock_expect("DH Keys").insert(user_pubkey.to_vec(), enc_key);
    Ok(msg)
}
