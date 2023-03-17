# MiyaguchiPreneel
JS Implementation for MiyaguchiPreneel compression function.
The MiyaguchiPreneel compression function is a one way cryptographic function built from a symmetric cryptographic algorythm. At present day, this compression function is secure and a cryptanalysis providing collisions is not known.

## Install

```
npm i miyaguchipreneel
```

## Usage

Basic usage is through the following code.

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

However, the constructor accept the following arguments:

```
    function MiyaguchiPreneel(enc, key, padding, hbits); 
```

 * `enc` :
   Parameter for providing the symmetric crypto algorythm used for generating the MiyaguchiPreneel compressor

 * `key` :
   Parameter for providing the Key Derivation Function used for pre-processing the key used at the symmetric crypto algo used.

 * `padding` :
   Parameter for providing the padding function used when a block size to cipher is lower to the block size required by the symmetric crypto algo.

 * `hbits` :
   The size in bits of a crypto block used by the symmetric crypto algo.

The following code (coming from tests) provides an example of some specific usage of this implementation.

The first is an instanciation of MP with the ident as a encryption function.
```
	    var mp = new MP((k, v) => {return(v);});
```

The second id an instanciation of MP with the revert function as KDF.
```
	    var mp = new MP(
		undefined,
		(k) =>
		{
		    var newk = Buffer.alloc(k.length, 0);
		    for (var i = 0; i < k.length; i++)
			newk[i] = k[k.length -1 -i];
		    return(newk);
		}
	    );
```

I'll let you, as an exercise, write instanciation for using PKCS#1 v1.5 padding and another one for PKCS#1 OAEP.
```
           Have Fun !!
```

I'll describe the rest of the API in further doc changes.