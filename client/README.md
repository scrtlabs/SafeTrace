# Client interface to SafeTrace

This folder contains sample Javascript code to interface with the enclave via a JSON RPC Server. At the time of this writing
there is a live instance of the enclave + JSON RPC Server that you can interact with at https://safetrace.enigma.co.

If you visit https://safetrace.enigma.co with your browser, you'll get a `405 Error: Method not allowed` because it does not
accept GET requests like the ones that regular browsers make. Instead, you have to POST properly formatted JSON-RPC requests:

The client code in this folder is meant to be used as a reference and adapted for your own client. It has not been packaged
as a library yet, but you should be able to copy/paste the relevant functions into your code. You can run:

```bash
node index.js
```

to see an example of working code that submits data for two users into the enclave, and later queries for a match between the
two datasets, returning one match.

Below are included example requests and responses for each endpoint using [curl](https://curl.haxx.se/) from the command line.

## getEnclaveReport

* Request

```bash
$ curl -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id":1, "method":"getEnclaveReport", "params": {}}' https://safetrace.enigma.co
```

* Response
```bash
{
  "jsonrpc":"2.0",
  "id":1,
  "result": {
    "id":"ed88a0a1f7",
    "type":"GetEnclaveReport",
    "result": {
      "signingKey":"5b4a6ba4809d94f3b0cccbaf43e17dea5d3bdba8",
      "report":"7b226964223a22353239313235363835323730343032363337353238343539303132303
      9363930353931343134222c2274696d657374616d70223a22323032302d30342d30315431343a3236
      3a30322e343737353631222c2276657273696f6e223a332c22697376456e636c61766551756f74655
      37461747573223a2247524f55505f4f55545f4f465f44415445222c22706c6174666f726d496e666f
      426c6f62223a223135303230303635303430303037303030303044304430323034303130313033303
      030303030303030303030303030303030304130303030304230303030303030323030303030303030
      303030303041433742453139303731323337303543343031394435363630433744443835313733313
      737304138343538414441344332433445354441334545363230463932433139424538383639434441
      353237374141333537353737363232304246323544303332313631383038443146463738334238393
      14532394434303238383344393534222c22697376456e636c61766551756f7465426f6479223a2241
      674141414d634b414141494141634141414141414c417a58394f38484d715067453635696d5167575
      331314d722f377379626b4251555851493072707947694167372f42502f2f41414141414141414141
      414141414141414141414141414141414141414141414141414141414141414141414141414141414
      14141414141427741414141414141414148414141414141414141466d644f7251736445764a434665
      624b7232454536637638444d5a314d64492b4b6f7858517a4956385a4941414141414141414141414
      1414141414141414141414141414141414141414141414141414141414141434431786e6e6665724b
      4648443275765971545864444138695a32326b434435787737683338434d664f6e674141414141414
      141414141414141414141414141414141414141414141414141414141414141414141414141414141
      414141414141414141414141414141414141414141414141414141414141414141414141414141414
      141414141414141414141414141414141414141414141414141414141414141414141414141414141
      414141414141414141414141414141414141414141414141414141414141414141414141414141414
      141414141414141414141414141414141414141414141414141414141414141414141414141414141
      4141414262536d756b674a32553837444d79363944345833715854766271414141414141414141414
      141414141414141414141414141414141414141414141414141414141414141414141414141414141
      4141414141414141227d",
      "signature":"981fc554b5a92149c0b5cfc07ae8c82cdfa213b1405ee867f2dce49ff77f219c8419
      3fe67363255cf371a4404b5f62cf85f06361fec00327409e302973a1043d17b76b0ef0b32f95974d4
      e612702c1d618f3035a37fa56883a2bb0ee485e8c3b7f85d1305be58490c393de178cdb2a91006b26
      6c3225ec3b244c2373bbc2c5e206d372d754142527e5c75893ebb2384d3f3844ca63d91367833cce8
      031b6f8f8666f9e93bf5897fc9248839e51cff80f0c455ea217a51befbe4942ea077bc4cf29e87693
      3d170778285fa043fd91fb9391b340a607d47a6a0fbee9c5d7ee1818b4899e41020b3de91e5b1b33f
      abc36449b35f22a403635b6ab9e429cdc542654"
    }
  }
}
```

## newTaskEncryptionKey

* Request

```bash
curl -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1, "method": "newTaskEncryptionKey","params": { "userPubKey":"cc955077ff7aeb67e544bb0dfad0a5ac1d3117f4115c528d38da9c2337cb033ec08f1d12a580d2ccfed02144e70d961c72e28e92ef48b9056c08137918c5ab2d"}}' https://safetrace.enigma.co
```

* Response

```json
{
  "jsonrpc":"2.0",
  "id":1,
  "result": {
    "id":"5708a053c9",
    "type":"NewTaskEncryptionKey",
    "result": {
      "taskPubKey":"1a75beafbc32c5a4ba881dcca795fb0f87b4b473e5689592db942366b763d52466922a7
      103a6975be699cf6f3b499294f5dd92cbe5a2e15470dd03bc971c770d",
      "sig":"1994e259d3befd9fab06c6b9f00c4f892bb6c6d54f6449ccd0b42df79ceeb7ae057aa85b3fe2d0
      70c21775a5cac60274bf1ac8e3c0e104872601a136c978deeb1b"
    }
  }
}
```

## addPersonalData

* Request

```bash
curl -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id":1, "method":"addPersonalData", "params": {"encryptedUserId":"15806c56ed8fb37a9a45c8c3efa227a98a406c5787bf3ff90f0c89fde8ad3d6fdd", "encryptedData": "85d6f1e75cd29d761e291f9c8fd3e8dc5ac289df327960a39938a0934bcaee41f7b17c61ec450b7a8fc01474e9495d12d6d07754d01217c88774b678c03032e3085155ba65f9cf9617de36a538c30c6664e05c3f07f812a3cf10b23ca90fc765912f82bfddd864ba4d4f7e6ab41c11f6d43006b2aee150ddef72215f2baeadd1957fdeac9d2f582e779e79cabc604a3ba50f9c870952239ee4a2437d54952f891090a677b3c38972a2982a739bd43c911c14f67c80cd53b34001285a5091c4525f1d68cef4d89ebb805181a3a11d8c52e57ba4e802e7", "userPubKey": "cc955077ff7aeb67e544bb0dfad0a5ac1d3117f4115c528d38da9c2337cb033ec08f1d12a580d2ccfed02144e70d961c72e28e92ef48b9056c08137918c5ab2d"}}' https://safetrace.enigma.co
```

*NOTE: The parameters `encryptedUserId` and `encryptedData` are encrypted with an ephemeral Diffie-Hellman key, so you need
to run the method `newTaskEncryptionKey` everytime to be able to derive that key, and use it to encrypt these parameters. This also means that the encrypted values will change every time.*

* Response

```json
{
  "jsonrpc":"2.0",
  "id":1,
  "result": {
    "id":"eb2f102370",
    "type":"AddPersonalData",
    "addPersonalData": {
      "status":0
    }
  }
}
```

## findMatch

* Request

```bash
curl -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "id":1, "method":"findMatch", "params": {"encryptedUserId":"15806c56ed8fb37a9a45c8c3efa227a98a406c5787bf3ff90f0c89fde8ad3d6fdd", "userPubKey": "cc955077ff7aeb67e544bb0dfad0a5ac1d3117f4115c528d38da9c2337cb033ec08f1d12a580d2ccfed02144e70d961c72e28e92ef48b9056c08137918c5ab2d"}}' https://safetrace.enigma.co
```

* Response

```json
{ 
  "jsonrpc":"2.0",
  "id":1,
  "result": {
    "id": "d23d723a6a",
    "type": "FindMatch",
    "findMatch": { 
      "status": 0,
      "encryptedOutput": "45c90f568a5bb096fc39ae8429c3e05cd29f40c30c0f89e8c0395cf431f5c2934d
      232cff4eb3c27b18e9704790e65b0bdecdcd02d6e8b5b668991d3e53b804c23b24c7f5d9e5d1a2c322036a
      3068991ddc0ebd7a56ddd1b90a7d857c790844f5233b22aad906bea938c77d24882b1043d2e84b2c8d959d
      d0"
    } 
  }
}
```

*NOTE: Analogously to the previous method, the input and output from this method are encrypted, which you can encrypt and
decrypt with the key derived through Diffie-Hellman. Again, the command and output included here are for reference 
purposes, but you will not be able to reproduce verbatim. Instead, you have to run `newTaskEncryptionKey` and use that
for encryption and decryption.*

