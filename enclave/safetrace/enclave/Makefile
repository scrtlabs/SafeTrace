# Because build-dependencies and regular dependencies are mixed together it's not possible to import
# bindgen into the enclave's build.rs (https://github.com/rust-lang/cargo/issues/2589)
# The solution is to install the bindgen CLI in the docker and use it manually in the Makefile.

SGX_SDK ?= /opt/sgxsdk

Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
# Rust_Target_Path := $(CURDIR)/../../incubator-teaclave-sgx-sdk/xargo

BINDGEN_OUTPUT_FILE := src/auto_ffi.rs
BINDGEN_RAW_LINES := "\#![allow(dead_code)] use enigma_types::*; use sgx_types::*;"
BINDGEN_CLANG_FLAGS := -I$(SGX_SDK)/include -I$(HOME)/sgx/edl
BINDGEN_FLAGS := --default-enum-style=rust --rust-target=nightly \
	--no-recursive-whitelist --use-array-pointers-in-arguments \
	--whitelist-function ocall_.*  --raw-line $(BINDGEN_RAW_LINES)


all: bindgen $(Rust_Enclave_Name)

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
ifeq ($(XARGO_SGX), 1)
	RUST_TARGET_PATH=$(shell pwd) xargo build --target x86_64-unknown-linux-sgx $(CARGO_FLAGS)
	cp ./target/x86_64-unknown-linux-sgx/$(Rust_target_dir)/libsafetraceenclave.a ../lib/libenclave.a
else
	cargo build $(CARGO_FLAGS)
	cp ./target/$(Rust_target_dir)/libsafetraceenclave.a ../lib/libenclave.a
endif


.PHONY: bindgen
bindgen: Enclave_t.h
	cargo build -p enigma-types $(CARGO_FLAGS) # Meant to make sure `enigma-types.h` already exists and can be included.
	bindgen Enclave_t.h $(BINDGEN_FLAGS) -- $(BINDGEN_CLANG_FLAGS) > $(BINDGEN_OUTPUT_FILE)
	rustfmt  $(BINDGEN_OUTPUT_FILE)
