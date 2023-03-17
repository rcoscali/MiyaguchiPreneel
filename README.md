# MiyaguchiPreneel
JS Implementation for MiyaguchiPreneel compression function

## Install

```
npm i miyaguchipreneel
```

## Usage

```
const MP = require("miyaguchipreneel");
...
var mp = new MP();
var bufferMsg = Buffer.from("A message to get hash on with AES-ECB !");
var bufferIv0 = Buffer.from("00000000000000000000000000000000", "hex");
const bufferHash = mp.comp(bufferIv0, bufferMsg).toString("hex");

// Expected hash is 'e4bcb82e0e776ea16f67857e13ea954f'
console.log("AES-ECB Hash of message is: '" + mp.comp(bufferIv0, bufferMsg).toString('hex') + "'");
```
