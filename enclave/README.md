# Enclave for COVID-19 Self-reporting

This folder contains the code that runs inside the enclave using Intel Secure Guard Extensions (SGX). It builds on [Apache's Teaclave](https://github.com/apache/incubator-teaclave), and more specifically its [Rust SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk) which is included as part of this repo as a submodule (branch = `v1.1.1-testing`).

## Requirements

* SGX-capable computer host with SGX enabled in the BIOS
* Ubuntu Bionic (18.04) or newer
* [Rust](https://www.rust-lang.org/tools/install)

## Installation

1. Clone this repository, if you haven't already:

    * Using HTTPS:

    ```bash
    git clone https://github.com/enigmampc/covid-self-reporting.git
    ```

    * Using SSH:

	```bash
	git clone git@github.com:enigmampc/covid-self-reporting.git
	```

2. Install the SGX driver and SDK, as per these [instructions](https://github.com/enigmampc/EnigmaBlockchain/blob/master/docs/dev/setup-sgx.md).


3. Move into the `enclave/safetrace` subfolder:

    ```bash
    cd enclave/safetrac
    ```

4. Compile the code:

    ```bash
    make
    ```

5. Run the enclave code:

    ```bash
    cd bin
    ./safetrace-app
    ```

## ToDo

* Sign code and deploy
