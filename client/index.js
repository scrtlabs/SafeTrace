const axios = require('axios');
const forge = require('node-forge');
const EthCrypto = require('eth-crypto');
const jaysonBrowserClient = require('jayson/lib/client/browser');
const enigma = require('enigma-js/lib/enigma-js.node');
const web3utils = require('web3-utils');
const data = require('./data.js');


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

async function getEncryptionKey(publicKey) {
  const getEncryptionKeyResult = await new Promise((resolve, reject) => {
    client.request('newTaskEncryptionKey', {userPubKey: publicKey},
        (err, response) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(response);
        });
    });

  const {result, id} = getEncryptionKeyResult;
  const {taskPubKey, sig} = result;
  // ToDo: verify signature
  return taskPubKey;
}

function encrypt(taskPubKey, privateKey, variable){
    // Generate derived key from enclave public encryption key and user's private key
    const derivedKey = enigma.utils.getDerivedKey(taskPubKey, privateKey);
    // Encrypt function and ABI-encoded args
    return enigma.utils.encryptMessage(derivedKey, variable);
}


async function addData(userId, data){

  let {publicKey, privateKey} = getClientKeys();

  try {
    let taskPubKey = await getEncryptionKey(publicKey);
    let encryptedUserId = encrypt(taskPubKey, privateKey, userId);
    let encryptedData = encrypt(taskPubKey, privateKey, data);

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
    // Or throw an error
  }
}

async function findMatch(userId){

  let {publicKey, privateKey} = getClientKeys();

  try {
    let taskPubKey = await getEncryptionKey(publicKey);
    let encryptedUserId = encrypt(taskPubKey, privateKey, userId);

    const findMatchResult = await new Promise((resolve, reject) => {
      client.request('findMatch', {
        encryptedUserId: encryptedUserId, 
        userPubKey: publicKey},
          (err, response) => {
            if (err) {
              reject(err);
              return;
            }
            resolve(response);
          });
      });

    if(findMatchResult.findMatch.status == 0) {
      console.log('Find Match operation successful');
      if(findMatchResult.findMatch.matches.length){
        console.log('Find matches:');
        console.log(findMatchResult.findMatch.matches);
      } else {
        console.log('No matches');
      }
    } else {
      console.log('Something went wrong. Time to debug...')
    }
  } catch(err) {
    console.log(err);
    // Or throw an error
  }
}


addData('user1', JSON.stringify(data.DataUser1));
addData('user2', JSON.stringify(data.DataUser2));

findMatch('user1');
