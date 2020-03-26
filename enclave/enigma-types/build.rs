// client/build.rs

use cbindgen::Language;
use std::{env, path::PathBuf};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = target_dir().join(format!("{}.h", package_name)).display().to_string();

    cbindgen::Builder::new()
        .with_no_includes()
        .with_sys_include("stdbool.h")
        .with_language(Language::C)
        .include_item("EnclaveReturn")
        .include_item("ResultStatus")
        .include_item("ExecuteResult")
        .include_item("Hash256")
        .include_item("StateKey")
        .include_item("ContractAddress")
        .include_item("MsgID")
        .include_item("PubKey")
        .include_item("RawPointer")
        .with_crate(&crate_dir)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&output_file);
}

/// Find the location of the `target/` directory. Note that this may be
/// overridden by `cmake`, so we also need to check the `CARGO_TARGET_DIR`
/// variable.
fn target_dir() -> PathBuf {
    let mut target = PathBuf::from(env::var("OUT_DIR").unwrap());
    target.pop();
    target.pop();
    target.pop();
    target.pop();
    target.pop();

    target
}