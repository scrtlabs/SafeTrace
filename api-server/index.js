#!/usr/bin/env node

'use strict';

const zmq = require("zeromq");
const cors = require('cors');
const jayson = require("jayson");
const crypto = require('crypto');
const connect = require('connect');
const bodyParser = require('body-parser');

const app = connect();
const socket = zmq.socket('req');
const ENCLAVE_URI = 'tcp://localhost:5552';
const _INVALID_PARAM = -32602;

var c = [];

function generateId() {
  return crypto.randomBytes(5).toString('hex');
}

socket.connect(ENCLAVE_URI);

socket.on('message', msg => {
  console.log('Message received');
  msg = JSON.parse(msg);
  console.log(msg);
  c[msg.id](null, msg);
})

const server = jayson.server({
  /**
   * Get Remote Attestation report
   */
  getEnclaveReport: async function(args, callback) {
    const id = generateId()
    c[id] = callback;
    try {
      await socket.send(JSON.stringify({id : id, type : 'GetEnclaveReport'}))
    } catch (err) {
      callback(err);
    }
  },
  /**
   * Get Encryption Key to encrypt inputs to enclave
   * and decrypt outputs from enclave
   */
  newTaskEncryptionKey: async function(args, callback) {
    const id = generateId()
    c[id] = callback;
    if(args.userPubKey && args.userPubKey.length == 128) {
      try {
        await socket.send(JSON.stringify({
          id : id, 
          type : 'NewTaskEncryptionKey', 
          userPubKey: args.userPubKey
        }));
      } catch (err) {
        callback(err);
      }
    } else {
      return callback({
        code: _INVALID_PARAM,
        message: "Invalid params"
      });
    }
  },
  /**
   * Submits user data (location+datetime) to the enclave
   */
  addPersonalData: async function(args, callback) {
    const id = generateId()
    c[id] = callback;
    if(args.encryptedUserId && args.encryptedData && args.userPubKey) {
      try {
        await socket.send(JSON.stringify({
          id : id, 
          type : 'addPersonalData', 
          input: {
            encryptedUserId: args.encryptedUserId,
            encryptedData: args.encryptedData,
            userPubKey: args.userPubKey
          }
        }));
      } catch (err) {
        callback(err);
      }
    } else {
      return callback({
        code: _INVALID_PARAM,
        message: "Invalid params"
      });
    }
  },
  /**
   * Requests if there has been a location+datetime match for the user
   */
  findMatch: async function(args, callback) {
    const id = generateId()
    c[id] = callback;
    if(args.encryptedUserId && args.userPubKey) {
      try {
        await socket.send(JSON.stringify({
          id : id, 
          type : 'findMatch', 
          input: {
            encryptedUserId: args.encryptedUserId,
            userPubKey: args.userPubKey
          }
        }));
      } catch (err) {
        callback(err);
      }
    } else {
      return callback({
        code: _INVALID_PARAM,
        message: "Invalid params"
      });
    }
  },
});

app.use(cors({methods: ['POST']}));
app.use(bodyParser.json({ limit: "20mb" }));
app.use(bodyParser.urlencoded({ limit: "20mb", extended: true}));
app.use(server.middleware());
app.listen(8080);