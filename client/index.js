const axios = require('axios');
const forge = require('node-forge');
const EthCrypto = require('eth-crypto');
const jaysonBrowserClient = require('jayson/lib/client/browser');
const enigma = require('enigma-js/lib/enigma-js.node');
const web3utils = require('web3-utils');


const JSON_RPC_Server='http://localhost:8080';

const callServer = function(request, callback) {
  let config = {
    headers: {
      'Content-Type': 'application/json',
      'credentials': 'include',
    },
  };
  axios.post(JSON_RPC_Server, JSON.parse(request), config).then((response) => {
    if ('error' in response.data) {
      callback(response.data.error, null);
    } else {
      let text = JSON.stringify(response.data.result);
      callback(null, text);
    }
  }).catch(function(err) {
    callback({code: -32000, message: err.message}, null);
  });
};

const client = jaysonBrowserClient(callServer, {});

function getClientKeys(seed='') {
  if (seed === '') {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 9; i++) {
      seed += characters.charAt(Math.floor(Math.random() * characters.length));
    }
  }
  let random = forge.random.createInstance();

  random.seedFileSync = function(needed) {
    return forge.util.fillString(seed, needed);
  };
  const privateKey = forge.util.bytesToHex(random.getBytes(32));
  const publicKey = EthCrypto.publicKeyByPrivateKey(privateKey)

  return {privateKey, publicKey};
}

async function add_data(userId, data){

  let {publicKey, privateKey} = getClientKeys();

  console.log(publicKey)

  try {
    const getWorkerEncryptionKeyResult = await new Promise((resolve, reject) => {
      client.request('newTaskEncryptionKey', {userPubKey: publicKey},
          (err, response) => {
            if (err) {
              reject(err);
              return;
            }
            resolve(response);
          });
      });

    const {result, id} = getWorkerEncryptionKeyResult;
    const {taskPubKey, sig} = result;
    // ToDo: verify signature

    // Generate derived key from worker's encryption key and user's private key
    const derivedKey = enigma.utils.getDerivedKey(taskPubKey, privateKey);
    // Encrypt function and ABI-encoded args
    const encryptedUserId = enigma.utils.encryptMessage(derivedKey, userId);
    const encryptedData = enigma.utils.encryptMessage(derivedKey, data);
    const msg = web3utils.soliditySha3(
      {t: 'bytes', v: encryptedUserId},
      {t: 'bytes', v: encryptedData},
    );

    // const a = getClientKeys();

    // console.log(a.publicKey);

    const addPersonalDataResult = await new Promise((resolve, reject) => {
      client.request('addPersonalData', {
        encryptedUserId: encryptedUserId, 
        encryptedData: encryptedData,
        userPubKey: publicKey},
          (err, response) => {
            if (err) {
              reject(err);
              return;
            }
            resolve(response);
          });
      });

    const {addPersonalData} = addPersonalDataResult;

    if(addPersonalData.status == 0) {
      console.log('Personal data added successfully to the enclave.');
    } else {
      console.log('Something went wrong. Time to debug...')
    }
    

  } catch(err) {
      console.log(err);
      // Or Throw an error
  }

}

let myData = [
  {
    "lat": 40.757339,
    "lng": -73.985992,
    "startTS": 1583064000,
    "endTS": 1583067600
  },
  {
    "lat": 40.793840,
    "lng": -73.956900,
    "startTS": 1583150400,
    "endTS": 1583154000
  },
]

add_data('myUserId', JSON.stringify(myData))
