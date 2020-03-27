use crate::networking::messages::*;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
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
    use failure::Error;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};
    use hex::{FromHex, ToHex};
    use std::str;
    use serde::Deserialize;
    use serde_json::Value;

    extern {
    fn ecall_add_personal_data(eid: sgx_enclave_id_t, ret: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;
    }

    type ResponseResult = Result<IpcResponse, Error>;

    #[derive(Serialize, Deserialize)]
    struct PubkeyResult {
        pubkey: Vec<u8>
    }

    pub fn get_enclave_report(eid: sgx_enclave_id_t, spid: &str, retries: u32) -> ResponseResult {
        let result = IpcResults::EnclaveReport { spid: spid.to_string() };
        Ok(IpcResponse::GetEnclaveReport { result })
    }

    // TODO
    //#[logfn(TRACE)]
    pub fn new_task_encryption_key(_user_pubkey: &str, eid: sgx_enclave_id_t) -> ResponseResult {
        let mut user_pubkey = [0u8; 64];
        user_pubkey.clone_from_slice(&_user_pubkey.from_hex().unwrap());

        let (msg, sig) = keys_u::get_user_key(eid, &user_pubkey)?;

        // Enigma-core implementation used MessagePack, but rmp-serde is not available
        // so replaced MessagePack serialization with plain JSON serialization
        //let mut des = Deserializer::new(&msg[..]);
        //let res: Value = Deserialize::deserialize(&mut des).unwrap();
        //let pubkey = serde_json::from_value::<Vec<u8>>(res["pubkey"].clone())?;
        //let pubkey = serde_json::from_slice::<Vec<u8>>(&msg)?;
        let res = match str::from_utf8(&msg) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };

        let pubkey: PubkeyResult = serde_json::from_str(res)?;

        let result = IpcResults::DHKey {taskPubKey: pubkey.pubkey.to_hex(), sig: sig.to_hex() };

        Ok(IpcResponse::NewTaskEncryptionKey { result })
    }

    // TODO
    //#[logfn(DEBUG)]
    pub fn add_personal_data( input: IpcInput, eid: sgx_enclave_id_t) -> ResponseResult {
        let mut ret = sgx_status_t::SGX_SUCCESS;
        let data = serde_json::to_string(&input).unwrap();

        unsafe { ecall_add_personal_data(eid, &mut ret as *mut sgx_status_t, data.as_ptr() as * const u8, data.len()) };

        let result = IpcResults::AddPersonalData { status: Status::Passed };
        Ok(IpcResponse::AddPersonalData { result })
    }

    // TODO
    //#[logfn(DEBUG)]
    pub fn find_match( input: IpcInput, eid: sgx_enclave_id_t) -> ResponseResult {
        let result = IpcResults::FindMatch { status: Status::Passed };
        Ok(IpcResponse::FindMatch { result })
    }


}
