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

2. Move into this `enclave` subfolder:

    ```bash
    cd enclave
    ```

3. Initialize the gitsubmodule:

    ```bash
    cd incubator-teaclave-sgx-sdk
    git submodule init
    git submodule update
    ```

4. Install the SGX driver and SDK, as per these [instructions](https://github.com/enigmampc/EnigmaBlockchain/blob/master/docs/dev/setup-sgx.md).

5. A sample code is temporarily included in this repo as a starting point. You can try it out:

    ```bash
    cd hello-rust
    make
    cd bin
    ./app
    ```

    *Note: This code is very particular, and you need to run `./app` from inside the `bin` folder. If you try to run it from anywhere else (e.g. its parent folder, as in `./bin/app`), you will get the following error, because it expects another file in the same folder from where the command is run:* 

    ```bash
    [-] Init Enclave Failed SGX_ERROR_ENCLAVE_FILE_ACCESS!`*
    ```

    Which should print something similar to this:

    ```bash
    [+] Init Enclave Successful 2!
    This is a normal world string passed into Enclave!
    This is a in-Enclave Rust string!
    gd: 1 0 0 1 
    static: 1 eremove: 0 dyn: 0
    EDMM: 0, feature: 9007268796301311
    supported sgx
    [+] say_something success...
    ```

## ToDo

* Use the `hello-rust` folder and scaffolding for the COVID-19 code
* Write the actual Rust code for the application
* Implement Remote Attestation to provide proof of code running in legitimate enclave
* Implement data sealing and unsealing choosing the right configuration so that data is uniquely assigned to this enclave
* Sign code and deploy
