# JSON-RPC API Server for COVID-19 Self-Reporting

This folder contains the code that provides a public-facing API that frontend applications can consume to interact with the SGX enclave.

# API endpoints

## getEnclaveReport

Requests the Remote Attestation report from the enclave that proves that the enclave is legitimate, runs in production mode, and runs the code that is supposed to run.

**Parameters**

None

**Returns**
 
`report` (String) - Base64-encoded Remote-Attestation report
`signingKey` (String) - The public signing key of the enclave
`signature` (String) - Signature of the report

## newTaskEncryptionKey

Requests a public encryption from the enclave that will be used to encrypt/decrypt data for the next user request.

**Parameters**

* `userPubKey` (String) - 64-byte public key for Diffie-Hellman

**Returns**

* `enclavePubKey` (String) - 64-byte public key for Diffie-Hellman
* `signature` (String) - Signature of `enclavePubKey`

## addPersonalData

Submits new personal data from the user (identified by its `userId`) providing an array of `lat`, `lng` and `timestamps`.

**Parameters**

* `encryptedUserId` (String) - encrypted `userId`
* `encryptedData` (String) - encrypted data, see the [Data Specification section](#data-specification) for details.
* `userPubKey` - (String) - 64-byte public key for Diffie-Hellman

**Returns**

* `status` (Integer) - `0` if the operation was successful, other values otherwise

    **Successsful Operation**

    ```json
    {
	  "jsonrpc": "2.0",
	  "id": 1,
	  "result": {
	  	"id": "dd5ee176c4",
	  	"type": "AddPersonalData",
	  	"addPersonalData": {
	  	  "status": 0
	  	}
	  }
	}
	```

	**Failed Operation**

    ```json
    {
	  "jsonrpc": "2.0",
	  "id": 1,
	  "result": {
	  	"id": "3254abe86c",
	  	"type": "AddPersonalData",
	  	"addPersonalData": {
	  	  "status": -1
	  	}
	  }
	}
	```


## findMatch

Queries whether there is a match both in location and time between the user (identified by its `userId`) and anyone in the dataset who has tested `positive`

**Parameters**

* `encryptedUserId` (String) - encrypted `userId`

**Returns**

* `status` (Integer) - `0` if the operation was successful, other values otherwise
* `matches` (Array) - if a match was found, this field will be populated with an array of `lat`, `lng` and `timestamp` where a match was found. If no match was found, this will return an empty array. This field comes encrypted, and needs to be decrypted to obtain the array.

    **Successsful Operation**
    
    ```json
    { 
        "id": "4078a17e30",
        "type": "FindMatch",
        "findMatch":
        {
	    "status": 0,
            "encryptedOutput": "25b2ec3c7b1ed1fdd0bf2fcc517b12af815fb1b161f3949f5fe0cb60c17e"
	}
    }
    ```

    **Failed Operation**
    
    ```json
    { 
        "id": "da7d3d68ff",
        "type": "FindMatch",
        "findMatch":
        {
	    "status": -1,
	}
    }
    ````

# Data Specification

The geolocation + datetime data is to be provided in an array in JSON format as follows:

```json
[
	{
		"lat": 40.757339,
		"lng": -73.985992,
		"startTS": 1583064000,
		"endTS": 1583067600,
		"testResult": false,
	},
	{
		"lat": 40.793840,
		"lng": -73.956900,
		"startTS": 1583150400,
		"endTS": 1583154000,
		"testResult": true,
	},
	
]
```
In the example above, the first datapoint is for Times Square in New York City on March 1st, 2020 from 12pm to 1pm, whereas the second data point is somewhere in Central Park the following day March 2nd, 2020 from 12pm to 1pm. This user did not test positive for Coronavirus the first day, but he tested positive the following day.


# Installation

## Requirements

The code in this folder assumes that it will be run on the same server that runs the code in the [enclave](../enclave) folder, which requires SGX (see that folder for additional information). Otherwise adjust the `ENCLAVE_URI` in [index.js](index.js) accordingly.

## Setup

1. Clone this repository, if you haven't already:

    * Using HTTPS:

    ```bash
    git clone https://github.com/enigmampc/covid-self-reporting.git
    ```

    * Using SSH:

	```bash
	git clone git@github.com:enigmampc/covid-self-reporting.git
	```

2. Move into this `api-server` subfolder:

	```bash
	cd api-server
	```

3. Install package dependencies:

	```bash
	yarn install
	```

## Development

For development or debugging purposes, this server can be run directly with:

```bash
./index.js
```

## Production

To put this server in production, one can use [pm2](https://pm2.keymetrics.io/docs/usage/startup/):

```bash
npx pm2 startup
```

Then, simply copy/paste the line PM2 command gives you above and the startup script will be configured for your OS. 

In Ubuntu, you can start the system service as:

```bash
sudo systemctl start pm2-${USER}
```
