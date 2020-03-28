use crate::SIGNING_KEY;
use types::{PubKey, DhKey, SymmetricKey};
use std::collections::HashMap;
use std::{sync::SgxMutex as Mutex, sync::SgxMutexGuard as MutexGuard, vec::Vec};
use serde::{Deserialize, Serialize};
use secp256k1::{PublicKey, SecretKey, SharedSecret};
use errors_t::{CryptoError, EnclaveError, ToolsError::MessagingError};
use hash::{Keccak256, prepare_hash_multiple};

//use ring::aead::{self, Nonce, Aad};
//use std::{borrow::ToOwned};


#[derive(Debug)]
pub struct KeyPair {
    pubkey: PublicKey,
    privkey: SecretKey,
}

impl KeyPair {
    /// This will generate a fresh pair of Public and Private keys.
    /// it will use the available randomness from [crate::rand]

    pub fn new() -> Result<KeyPair, CryptoError> {
        use sgx_trts::trts::rsgx_read_rand;
        // This loop is important to make sure that the resulting public key isn't a point in infinity(at the curve).
        // So if the Resulting public key is bad we need to generate a new random private key and try again until it succeeds.
	    loop {
	        let mut me = [0u8; 32];
			rsgx_read_rand(&mut me);
	        if let Ok(privkey) = SecretKey::parse(&me) {
	            let pubkey = PublicKey::from_secret_key(&privkey);
	            return Ok(KeyPair { privkey, pubkey });
	        }
	    }
    }

    pub fn from_slice(privkey: &[u8; 32]) -> Result<KeyPair, CryptoError> {
        let privkey = SecretKey::parse(&privkey)
            .map_err(|e| CryptoError::KeyError { key_type: "Private Key", err: Some(e) })?;
        let pubkey = PublicKey::from_secret_key(&privkey);

        Ok(KeyPair { privkey, pubkey })
    }

    /// This function does an ECDH(point multiplication) between one's private key and the other one's public key.
    ///
    pub fn derive_key(&self, _pubarr: &PubKey) -> Result<DhKey, CryptoError> {
        let mut pubarr: [u8; 65] = [0; 65];
        pubarr[0] = 4;
        pubarr[1..].copy_from_slice(&_pubarr[..]);

        let pubkey = PublicKey::parse(&pubarr)
            .map_err(|e| CryptoError::KeyError { key_type: "Private Key", err: Some(e) })?;

        let shared = SharedSecret::new(&pubkey, &self.privkey)
            .map_err(|_| CryptoError::DerivingKeyError { self_key: self.get_pubkey(), other_key: *_pubarr })?;

        let mut result = [0u8; 32];
        result.copy_from_slice(shared.as_ref());
        Ok(result)
    }

    fn pubkey_object_to_pubkey(key: &PublicKey) -> PubKey {
        let mut sliced_pubkey: [u8; 64] = [0; 64];
        sliced_pubkey.clone_from_slice(&key.serialize()[1..65]);
        sliced_pubkey
    }

    pub fn get_privkey(&self) -> [u8; 32] { self.privkey.serialize() }

    /// Get the Public Key and slice the first byte
    /// The first byte represents if the key is compressed or not.
    /// Because we use uncompressed Keys That start with `0x04` we can slice it out.
    ///
    /// We should move to compressed keys in the future, this will save 31 bytes on each pubkey.
    ///
    /// See More:
    ///     `https://tools.ietf.org/html/rfc5480#section-2.2`
    ///     `https://docs.rs/libsecp256k1/0.1.13/src/secp256k1/lib.rs.html#146`
    pub fn get_pubkey(&self) -> PubKey {
        KeyPair::pubkey_object_to_pubkey(&self.pubkey)
    }

    /// Sign a message using the Private Key.
    /// # Examples
    /// Simple Message signing:
    /// ```
    /// use enigma_crypto::KeyPair;
    /// let keys = KeyPair::new().unwrap();
    /// let msg = b"Sign this";
    /// let sig = keys.sign(msg);
    /// ```
    ///
    /// The function returns a 65 bytes slice that contains:
    /// 1. 32 Bytes, ECDSA `r` variable.
    /// 2. 32 Bytes ECDSA `s` variable.
    /// 3. 1 Bytes ECDSA `v` variable aligned to the right for Ethereum compatibility
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 65], CryptoError> {
        let hashed_msg = message.keccak256();
        let message_to_sign = secp256k1::Message::parse(&hashed_msg);

        let (sig, recovery) = secp256k1::sign(&message_to_sign, &self.privkey)
            .map_err(|_| CryptoError::SigningError { hashed_msg: *hashed_msg })?;

        let v: u8 = recovery.into();
        let mut returnvalue = [0u8; 65];
        returnvalue[..64].copy_from_slice(&sig.serialize());
        returnvalue[64] = v + 27;
        Ok(returnvalue)
    }

}


/// A struct to represent the UserMessage for the key exchange.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct UserMessage {
    pub(crate) pubkey: Vec<u8>,
}

impl UserMessage {
    // The reason for the prefix is that I(@elichai) don't feel comfortable signing a plain public key.
    // Because ECDSA signature contains multiplication of curve points, so I'm not sure if signing on a valid curve point has any side effect.
    const PREFIX: &'static [u8; 19] = b"Enigma User Message";

    /// Generate a new UserMessage struct with the provided public key.
    pub fn new(pubkey: PubKey) -> Self {
        let pubkey = pubkey.to_vec();
        Self { pubkey }
    }

    /// This should serialize the struct for it to be signed, using [`enigma_crypto::hash::prepare_hash_multiple()`]
    /// it will add a prefix to the data, `b"Enigma User Message"`.
    pub fn to_sign(&self) -> Vec<u8> {
        let to_sign = [&Self::PREFIX[..], &self.pubkey];
        prepare_hash_multiple(&to_sign)
    }

    /// This will serialize the Message using MessagePack.
    pub fn into_message(self) -> Result<Vec<u8>, EnclaveError> {
        //let mut buf = Vec::new();
        //let val = serde_json::to_value(self).map_err(|_| MessagingError { err: "Couldn't convert UserMesssage to Value" })?;
        //val.serialize(&mut Serializer::new(&mut buf)).map_err(|_| MessagingError { err: "Couldn't serialize UserMesssage" })?;;
        let val = serde_json::to_vec(&self).map_err(|_| MessagingError { err: "Couldn't convert UserMesssage to Value" })?;
        Ok(val)
    }

    // /// This will deserialize the Message using MessagePack.
    // pub fn from_message(msg: &[u8]) -> Result<Self, ToolsError> {
    //     let mut des = Deserializer::new(&msg[..]);
    //     let res: serde_json::Value = Deserialize::deserialize(&mut des)
    //         .map_err(|_| MessagingError { err: "Couldn't Deserialize UserMesssage"})?;;
    //     let msg: Self = serde_json::from_value(res)
    //         .map_err(|_| MessagingError { err: "Couldn't convert Value to UserMesssage"})?;
    //     Ok(msg)
    // }

    // /// Will return the DH public key from the message.
    // pub fn get_pubkey(&self) -> PubKey {
    //     let mut pubkey = [0u8; 64];
    //     pubkey.copy_from_slice(&self.pubkey[..]);
    //     pubkey
    // }
}


// const IV_SIZE: usize = 96/8;
// static AES_MODE: &aead::Algorithm = &aead::AES_256_GCM;
// type IV = [u8; IV_SIZE];

// pub fn decrypt(cipheriv: &[u8], key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
//     if cipheriv.len() < IV_SIZE {
//         return Err(CryptoError::ImproperEncryption);
//     }
//     let aes_decrypt = aead::OpeningKey::new(&AES_MODE, key)
//         .map_err(|_| CryptoError::KeyError { key_type: "Decryption", err: None })?;

//     let (ciphertext, iv) = cipheriv.split_at(cipheriv.len()-12);
//     let nonce = aead::Nonce::try_assume_unique_for_key(&iv).unwrap(); // This Cannot fail because split_at promises that iv.len()==12
//     let mut ciphertext = ciphertext.to_owned();
//     let decrypted_data = aead::open_in_place(&aes_decrypt, nonce, Aad::empty(), 0, &mut ciphertext);
//     let decrypted_data = decrypted_data.map_err(|_| CryptoError::DecryptionError)?;

//     Ok(decrypted_data.to_vec())
// }


/// A trait that is basically a shortcut for `mutex.lock().expect(format!("{} mutex is posion", name))`
/// you instead call `mutex.lock_expect(name)` and it will act the same.
pub trait LockExpectMutex<T> {
    /// See trait documentation. a shortcut for `lock()` and `expect()`
    fn lock_expect(&self, name: &str) -> MutexGuard<T>;
}

impl<T> LockExpectMutex<T> for Mutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T> { self.lock().unwrap_or_else(|_| panic!("{} mutex is poison", name)) }
}

lazy_static! { pub static ref DH_KEYS: Mutex<HashMap<Vec<u8>, DhKey>> = Mutex::new(HashMap::new()); }

pub(crate) unsafe fn ecall_get_user_key_internal(sig: &mut [u8; 65], user_pubkey: &PubKey) -> Result<Vec<u8>, EnclaveError> {
    let keys = KeyPair::new()?;
    let req = UserMessage::new(keys.get_pubkey());
    *sig = SIGNING_KEY.sign(&req.to_sign())?;
    let msg = req.into_message()?;
    let enc_key = keys.derive_key(&user_pubkey)?;
    DH_KEYS.lock_expect("DH Keys").insert(user_pubkey.to_vec(), enc_key);
    Ok(msg)
}
