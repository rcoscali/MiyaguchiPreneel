#!/usr/bin/env node

var aesjs = require('aes-js');

const MP = require('./MiyaguchiPreneel.js');
const BufferXor = require('node-aes-cmac/lib/buffer-tools.js').xor;

var bufferIv = Buffer.from('00000000000000000000000000000000', 'hex');
const KeyUpdateEncCte = Buffer.from('010153484500800000000000000000b0', 'hex');

var options = {returnAsBuffer: true};

var mp = new MP();

function KDF(k)
{
    //console.log("*** KDF");
    var kb, key;
    if (k instanceof Buffer)
	kb = Buffer.from(k);
    else
	kb = Buffer.from(k, 'hex');
    key = Buffer.concat([kb, KeyUpdateEncCte]);
    var dk = mp.comp(bufferIv, key);
    //console.log("*** Derived KEY = " + dk.toString('hex'));
    return(dk);
}

function decrypt_M2(msg, key)
{
    //console.log("*** decrypt_M2");
    //console.log("str msg = " + msg.toString('hex'));
    //console.log("str key = " + key.toString('hex'));
    var dk = KDF(key);
    //console.log("*** KDF = " + dk.toString('hex'));
    var aesCbc = new aesjs.ModeOfOperation.cbc(aesjs.utils.hex.toBytes(dk.toString('hex')), aesjs.utils.hex.toBytes(bufferIv.toString('hex')));
    var m2Str = aesCbc.decrypt(aesjs.utils.hex.toBytes(msg.toString('hex')));
    var bufM2 = Buffer.from(m2Str);
    //console.log("*** decrypted M2 = " + bufM2.toString('hex'));
    return(bufM2);
}

test('SHE_decrypt: KDF', () =>
    {
	var mp = new MP();
	var bufferKey = Buffer.from('0153f7000099ed9f320451aa8a7d9707', 'hex');
	expect(KDF(bufferKey).toString('hex')).toBe('0937e1e1690a81c388dd50ac10965b2f');
    }
);

test('SHE_decrypt: decrypt_M2', () =>
    {
	var mp = new MP();
	var bufferM2 = Buffer.from('000000000000000000000000000000413e38f7c374d4a3f39547b556893861d251195ce2f6f3f989d6460408bda42c33ecc5c11b04af0c85f0f857b6b235a2bd', 'hex');
	var bufferKey = Buffer.from('0153f7000099ed9f320451aa8a7d9707', 'hex');
	var decM2 = decrypt_M2(bufferM2, bufferKey).subarray(16,48);
	expect(decM2.toString('hex')).toBe('0000001100000000000000000000004110357f020289ad8f512662ba988f1111');
	var cid = decM2.subarray(0, 4).toString('hex').substring(0, 7);
	expect(cid).toBe('0000001');
	var fid = ((decM2[3] & 0x0F) << 1) + ((decM2[4] >> 7) & 0x01);
	expect(fid).toBe(2);
	var key = decM2.subarray(16);
	expect(key.toString('hex')).toBe('10357f020289ad8f512662ba988f1111');
    }
);

/*
 * -*- mode: JavaScript; coding: utf-8-unix -*-
 */
