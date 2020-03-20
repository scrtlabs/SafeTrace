# Enclave for COVID-19 Self-reporting

This folder contains the code that runs inside the enclave using Intel Secure Guard Extensions (SGX). It builds on [Apache's Teaclave](https://github.com/apache/incubator-teaclave), and more specifically its [Rust SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk) which is included as part of this repo as a submodule (branch = `v1.1.1-testing`).

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
