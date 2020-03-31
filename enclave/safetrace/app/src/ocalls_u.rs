use sgx_types::{sgx_enclave_id_t, sgx_status_t, sgx_target_info_t, sgx_report_t};

//use crate::esgx::general;

// #[no_mangle]
// pub unsafe extern "C" fn ocall_save_to_memory(data_ptr: *const u8, data_len: usize) -> u64 {
//     let data = slice::from_raw_parts(data_ptr, data_len).to_vec();
//     let ptr = Box::into_raw(Box::new(data.into_boxed_slice())) as *const u8;
//     ptr as u64
// }

#[no_mangle]
extern "C" {
    pub fn ecall_get_registration_quote(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        target_info: *const sgx_target_info_t,
        report: *mut sgx_report_t,
    ) -> sgx_status_t;
}

#[no_mangle]
extern "C" {
    pub fn ecall_get_signing_address(eid: sgx_enclave_id_t, arr: *mut [u8; 20usize]) -> sgx_status_t;
}