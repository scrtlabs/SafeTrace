use serde_json;
use serde_repr::{Serialize_repr, Deserialize_repr};
use zmq::Message;


// These attributes enable the status to be casted as an i8 object as well
#[derive(Serialize_repr, Deserialize_repr, Clone, Debug)]
#[repr(i8)]
pub enum Status {
    Failed = -1,
    Passed = 0,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeolocationTime {
    lat: f32,
    lng: f32,
    startTS: i32,
    endTS: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessageRequest {
    pub id: String,
    #[serde(flatten)]
    pub request: IpcRequest
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessageResponse {
    pub id: String,
    #[serde(flatten)]
    pub response: IpcResponse
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetEnclaveReport { #[serde(flatten)] result: IpcResults },
    NewTaskEncryptionKey { #[serde(flatten)] result: IpcResults },
    AddPersonalData { #[serde(flatten)] result: IpcResults },
    FindMatch { #[serde(flatten)] result: IpcResults },
    Error { msg: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", rename = "result")]
pub enum IpcResults {
    Errors(Vec<IpcStatusResult>),
    #[serde(rename = "result")]
    Request { request: String, sig: String },
    #[serde(rename = "result")]
    EnclaveReport { #[serde(rename = "signingKey")] signing_key: String, report: String, signature: String },
    #[serde(rename = "result")]
    DHKey { taskPubKey: String, sig: String },
    AddPersonalData { status: Status },
    FindMatch { status: Status, #[serde(skip_serializing_if = "String::is_empty")] encryptedOutput: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcRequest {
    GetEnclaveReport,
    NewTaskEncryptionKey { userPubKey: String },
    AddPersonalData { input: IpcInputData },
    FindMatch { input: IpcInputMatch },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcInputData {
    #[serde(rename = "encryptedUserId")] pub encrypted_userid: String,
    #[serde(rename = "encryptedData")] pub encrypted_data: String,
    #[serde(rename = "userPubKey")] pub user_pub_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcInputMatch {
    #[serde(rename = "encryptedUserId")] pub encrypted_userid: String,
    #[serde(rename = "userPubKey")] pub user_pub_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcStatusResult {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<i64>,
    pub status: Status,
}

impl IpcMessageResponse {
    pub fn from_response(response: IpcResponse, id: String) -> Self {
        Self { id, response }
    }
}

impl IpcMessageRequest {
    pub fn from_request(request: IpcRequest, id: String) -> Self {
        Self { id, request }
    }
}

impl From<Message> for IpcMessageRequest {
    fn from(msg: Message) -> Self {
        let msg_str = msg.as_str().unwrap();
        let req: Self = serde_json::from_str(msg_str).expect(msg_str);
        req
    }
}

impl Into<Message> for IpcMessageResponse {
    fn into(self) -> Message {
        let msg = serde_json::to_vec(&self).unwrap();
        Message::from(&msg)
    }
}

pub(crate) trait UnwrapError<T> {
    fn unwrap_or_error(self) -> T;
}

impl<E: std::fmt::Display> UnwrapError<IpcResponse> for Result<IpcResponse, E> {
    fn unwrap_or_error(self) -> IpcResponse {
        match self {
            Ok(m) => m,
            Err(e) => {
                error!("Unwrapped Message failed: {}", e);
                IpcResponse::Error {msg: format!("{}", e)}
            }
        }
    }
}