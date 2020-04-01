use crate::networking::messages::*;
use sgx_types::sgx_enclave_id_t;
use futures::{Future, Stream};
use std::sync::Arc;
use tokio_zmq::prelude::*;
use tokio_zmq::{Error, Multipart, Rep};


pub struct IpcListener {
    _context: Arc<zmq::Context>,
    rep_future: Box<dyn Future<Item = Rep, Error = Error>>,
}

impl IpcListener {
    pub fn new(conn_str: &str) -> Self {
        let _context = Arc::new(zmq::Context::new());
        let rep_future = Rep::builder(_context.clone()).bind(conn_str).build();
        println!("Binded to socket: {}", conn_str);
        IpcListener { _context, rep_future }
    }

    pub fn run<F>(self, f: F) -> impl Future<Item = (), Error = Error>
    where F: FnMut(Multipart) -> Multipart {
        self.rep_future.and_then(|rep| {
            let (sink, stream) = rep.sink_stream(25).split();
            stream.map(f).forward(sink).map(|(_stream, _sink)| ())
        })
    }
}

pub fn handle_message(request: Multipart, spid: &str, eid: sgx_enclave_id_t, retries: u32) -> Multipart {
    let mut responses = Multipart::new();
    for msg in request {
        let msg: IpcMessageRequest = msg.into();
        let id = msg.id.clone();
        let response_msg = match msg.request {
            IpcRequest::GetEnclaveReport => handling::get_enclave_report(eid, spid, retries),
            IpcRequest::NewTaskEncryptionKey { userPubKey } => handling::new_task_encryption_key(&userPubKey, eid),
            IpcRequest::AddPersonalData { input } => handling::add_personal_data(input, eid),
            IpcRequest::FindMatch { input } => handling::find_match(input, eid),
        };
        let msg = IpcMessageResponse::from_response(response_msg.unwrap_or_error(), id);
        responses.push_back(msg.into());
    }
    responses
}


pub(self) mod handling {
    use crate::networking::messages::*;
    use crate::keys_u;
    use crate::esgx::equote;
    use failure::Error;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};
    use hex::{FromHex, ToHex};
    use std::str;
    use rmp_serde::Deserializer;
    use serde::Deserialize;
    use serde_json::Value;
    use enigma_tools_u::{
        esgx::equote as equote_tools,
        attestation_service::{service::AttestationService, constants::ATTESTATION_SERVICE_URL},
    };
    use enigma_types::{EnclaveReturn};


    extern {
        fn ecall_add_personal_data(
            eid: sgx_enclave_id_t,
            ret: *mut sgx_status_t,
            encryptedUserId: *const u8,
            encryptedUserId_len: usize,
            encryptedData: *const u8,
            encryptedData_len: usize,
            userPubKey: &[u8; 64]) -> sgx_status_t;
    }

    extern {
        fn ecall_find_match(
                eid: sgx_enclave_id_t,
                ret: *mut sgx_status_t,
                encryptedUserId: *const u8,
                encryptedUserId_len: usize,
                userPubKey: &[u8; 64],
                serialized_ptr: *mut u64
            ) -> sgx_status_t;
    }

    type ResponseResult = Result<IpcResponse, Error>;

    #[derive(Serialize, Deserialize)]
    struct PubkeyResult {
        pubkey: Vec<u8>
    }

    //#[logfn(TRACE)]
    pub fn get_enclave_report(eid: sgx_enclave_id_t, spid: &str, retries: u32) -> ResponseResult {

        let signing_key = equote::get_register_signing_address(eid)?;

        let enc_quote = equote_tools::retry_quote(eid, spid, 18)?;
        println!("{:?}", enc_quote);


        // *Important* `option_env!()` runs on *Compile* time.
        // This means that if you want Simulation mode you need to run `export SGX_MODE=SW` Before compiling.
        let (signature, report_hex) = if option_env!("SGX_MODE").unwrap_or_default() == "SW" { // Simulation Mode
            let report =  enc_quote.as_bytes().to_hex();
            let sig = String::new();
            (sig, report)
        } else { // Hardware Mode
            let service: AttestationService = AttestationService::new_with_retries(ATTESTATION_SERVICE_URL, retries);
            let response = service.get_report(enc_quote)?;
            let report = response.result.report_string.as_bytes().to_hex();
            let sig = response.result.signature;
            (sig, report)
        };

        let result = IpcResults::EnclaveReport { signing_key: signing_key.to_hex(), report: report_hex, signature };

        Ok(IpcResponse::GetEnclaveReport { result })
    }

    // TODO
    //#[logfn(TRACE)]
    pub fn new_task_encryption_key(_user_pubkey: &str, eid: sgx_enclave_id_t) -> ResponseResult {
        let mut user_pubkey = [0u8; 64];
        user_pubkey.clone_from_slice(&_user_pubkey.from_hex().unwrap());

        let (msg, sig) = keys_u::get_user_key(eid, &user_pubkey)?;

        let mut des = Deserializer::new(&msg[..]);
        let res: Value = Deserialize::deserialize(&mut des).unwrap();
        let pubkey = serde_json::from_value::<Vec<u8>>(res["pubkey"].clone())?;

        let result = IpcResults::DHKey {taskPubKey: pubkey.to_hex(), sig: sig.to_hex() };

        Ok(IpcResponse::NewTaskEncryptionKey { result })
    }

    // TODO
    //#[logfn(DEBUG)]
    pub fn add_personal_data(input: IpcInputData, eid: sgx_enclave_id_t) -> ResponseResult {

        let mut ret = sgx_status_t::SGX_SUCCESS;
        let encrypted_userid = input.encrypted_userid.from_hex()?;
        let encrypted_data = input.encrypted_data.from_hex()?;
        let mut user_pub_key = [0u8; 64];
        user_pub_key.clone_from_slice(&input.user_pub_key.from_hex()?);

        unsafe { ecall_add_personal_data(eid,
                                         &mut ret as *mut sgx_status_t,
                                         encrypted_userid.as_ptr() as * const u8,
                                         encrypted_userid.len(),
                                         encrypted_data.as_ptr() as * const u8,
                                         encrypted_data.len(),
                                         &user_pub_key) };

        let result = IpcResults::AddPersonalData { status: Status::Passed };
        Ok(IpcResponse::AddPersonalData { result })
    }

    // TODO
    //#[logfn(DEBUG)]
    pub fn find_match( input: IpcInputMatch, eid: sgx_enclave_id_t) -> ResponseResult {

        let mut ret = sgx_status_t::SGX_SUCCESS;
        let mut serialized_ptr = 0u64;
        let encrypted_userid = input.encrypted_userid.from_hex()?;
        let mut user_pub_key = [0u8; 64];
        user_pub_key.clone_from_slice(&input.user_pub_key.from_hex()?);

        let status = unsafe { 
            ecall_find_match(
                eid,
                &mut ret as *mut sgx_status_t,
                encrypted_userid.as_ptr() as * const u8,
                encrypted_userid.len(),
                &user_pub_key,
                &mut serialized_ptr as *mut u64
            )
        };

        let box_ptr = serialized_ptr as *mut Box<[u8]>;
        let part = unsafe { Box::from_raw(box_ptr) };

        let mut des = Deserializer::new(&part[..]);
        let res: Value = Deserialize::deserialize(&mut des).unwrap();

        println!("HERE");
        println!("{:?}", res);
        let matches = serde_json::from_value::<Vec<GeolocationTime>>(res)?;

        //let output = res.as_array().unwrap().clone();

        // // TODO: Should not panic, propagate error instead
        // let output_json = match String::from_utf8(output) {
        //     Ok(v) => v,
        //     Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        // };

        //println!("{}", output_json);

        let result = IpcResults::FindMatch { status: Status::Passed, matches: matches};
        Ok(IpcResponse::FindMatch { result })
    }


}
