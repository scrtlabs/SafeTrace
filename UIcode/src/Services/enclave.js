import axios from "axios";
import forge from "node-forge";
import EthCrypto from "eth-crypto";
import jaysonBrowserClient from "jayson/lib/client/browser";
import { utils } from "enigma-js";

const JSON_RPC_Server = process.env.REACT_APP_ENCLAVE_URL;

const callServer = function (request, callback) {
  let config = {
    headers: {
      "Content-Type": "application/json",
      credentials: "include",
    },
  };
  axios
    .post(JSON_RPC_Server, JSON.parse(request), config)
    .then((response) => {
      if ("error" in response.data) {
        callback(response.data.error, null);
      } else {
        let text = JSON.stringify(response.data.result);
        callback(null, text);
      }
    })
    .catch(function (err) {
      callback({ code: -32000, message: err.message }, null);
    });
};

const client = jaysonBrowserClient(callServer, {});

function getClientKeys(seed = "") {
  if (seed === "") {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < 9; i++) {
      seed += characters.charAt(Math.floor(Math.random() * characters.length));
    }
  }
  let random = forge.random.createInstance();

  random.seedFileSync = function (needed) {
    return forge.util.fillString(seed, needed);
  };
  const privateKey = forge.util.bytesToHex(random.getBytes(32));
  const publicKey = EthCrypto.publicKeyByPrivateKey(privateKey);

  return { privateKey, publicKey };
}

export async function getEncryptionKey(publicKey) {
  const getEncryptionKeyResult = await new Promise((resolve, reject) => {
    client.request(
      "newTaskEncryptionKey",
      { userPubKey: publicKey },
      (err, response) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(response);
      }
    );
  });
  const { result } = await getEncryptionKeyResult;
  const { taskPubKey } = result;
  // ToDo: verify signature
  return taskPubKey;
}

function encrypt(taskPubKey, privateKey, variable) {
  // Generate derived key from enclave public encryption key and user's private key
  const derivedKey = utils.getDerivedKey(taskPubKey, privateKey);
  // Encrypt function and ABI-encoded args
  return utils.encryptMessage(derivedKey, variable);
}

function decrypt(taskPubKey, privateKey, enc_variable) {
  // Generate derived key from enclave public encryption key and user's private key
  const derivedKey = utils.getDerivedKey(taskPubKey, privateKey);
  // Decrypt function and ABI-encoded args
  let outputHex = utils.decryptMessage(derivedKey, enc_variable);
  let outputStr = utils.hexToAscii(outputHex);
  return JSON.parse(outputStr);
}

async function addPersonalData(encryptedUserId, encryptedData, publicKey) {
  const getEncryptionKeyResult = await new Promise((resolve, reject) => {
    client.request(
      "addPersonalData",
      {
        encryptedUserId: encryptedUserId,
        encryptedData: encryptedData,
        userPubKey: publicKey,
      },
      (err, response) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(response);
      }
    );
  });
  const { result } = await getEncryptionKeyResult;
  return result;
}

async function findMatchCall(encryptedUserId, publicKey) {
  const findMatchResult = await new Promise((resolve, reject) => {
    client.request(
      "findMatch",
      {
        encryptedUserId: encryptedUserId,
        userPubKey: publicKey,
      },
      (err, response) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(response);
      }
    );
  });
  
  return findMatchResult;
}

export async function addData(userId, data) {
  console.log('addData parameters: ', userId, data);
  
  let { publicKey, privateKey } = getClientKeys();
  let taskPubKey = await getEncryptionKey(publicKey);
  let encryptedUserId = await encrypt(taskPubKey, privateKey, userId);
  let encryptedData = await encrypt(taskPubKey, privateKey, data);
  let addDataResult = await addPersonalData(
    encryptedUserId,
    encryptedData,
    publicKey
  );
  return addDataResult;
}

export async function findMatch(userId) {
  console.log('findMatch_userid', userId);
  let { publicKey, privateKey } = getClientKeys();

  try {
    let taskPubKey = await getEncryptionKey(publicKey);
    let encryptedUserId = encrypt(taskPubKey, privateKey, userId);

    let findMatchResult = await findMatchCall(encryptedUserId, publicKey);
    console.log('findMarchResult',findMatchResult);
    if (findMatchResult.findMatch.status === 0) {
      return decrypt(
        taskPubKey,
        privateKey,
        findMatchResult.findMatch.encryptedOutput
      );
    }else{
      console.log('Error in findMatch. Time to debug...');
    }
  } catch (err) {
    throw err;
  }
}
