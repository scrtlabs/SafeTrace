use crate::common_u::errors::EnclaveFailError;
use failure::Error;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use crate::enigma_types::types::{EnclaveReturn};

extern {
    pub fn ecall_get_user_key(
        eid: sgx_enclave_id_t,
        retval: *mut EnclaveReturn,
        sig: *mut [u8; 65usize],
        pubkey: *mut [u8; 64usize],
        serialized_ptr: *mut u64,
    ) -> sgx_status_t;
}


pub fn get_user_key(eid: sgx_enclave_id_t, user_pubkey: &[u8; 64]) -> Result<(Box<[u8]>, [u8; 65]), Error> {
    let mut sig = [0u8; 65];
    let mut ret = EnclaveReturn::Success;
    let mut serialized_ptr = 0u64;

    let status = unsafe {
        ecall_get_user_key(eid, &mut ret as *mut EnclaveReturn, &mut sig, user_pubkey.as_ptr() as _, &mut serialized_ptr as *mut u64)
    };
    if ret != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError { err: ret, status }.into());
    }
    let box_ptr = serialized_ptr as *mut Box<[u8]>;
    let part = unsafe { Box::from_raw(box_ptr) };
    Ok((*part, sig))
}
