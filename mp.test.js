#!/usr/bin/env node

(function(root) {
    "use strict";

    /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
    /*global document, window, escape, unescape, module, require, Uint32Array */

    var aesjs = require('aes-js');

    const MP = require('./MiyaguchiPreneel.js');
    const BufferXor = require('node-aes-cmac/lib/buffer-tools.js').xor;

    var options = {returnAsBuffer: true};

    test('MiyaguchiPreneel instanciation: properties', () =>
	{
	    var mp = new MP();
	    expect(mp.hlen).toBe(128);
	    expect(mp.getHLen()).toBe(128);
	    expect(mp.blksz).toBe(16);
	    expect(mp.getBlkSz()).toBe(16);
	}
    );

    test('MiyaguchiPreneel instanciation: enc_func method', () =>
	{
	    var mp = new MP();
	    var bufferKey = Buffer.from('53f7000099ed9f320001008004de5f1e', 'hex');
	    var bufferMsg = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    expect(mp.enc_func).toBeInstanceOf(Function);
	    expect(mp.enc_func(bufferKey, bufferKey).toString('hex')).toBe('a918f5eded3ce5cbde2e47596a2f9f62');
	    expect(mp.enc_func(bufferMsg, bufferKey).toString('hex')).toBe('04bcb5fdb682ebf64fd89a467299460d');
	}
    );

    test('MiyaguchiPreneel instanciation: custom enc_func method', () =>
	{
	    var mp = new MP((k, v) => {return(v);});
	    var bufferKey = Buffer.from('53f7000099ed9f320001008004de5f1e', 'hex');
	    var bufferMsg = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    expect(mp.enc_func).toBeInstanceOf(Function);
	    expect(mp.enc_func(bufferKey, bufferKey).toString('hex')).toBe('53f7000099ed9f320001008004de5f1e');
	    expect(mp.enc_func(bufferKey, bufferMsg).toString('hex')).toBe('3cc30001008004de5f1eacc0403d0000');
	}
    );

    test('MiyaguchiPreneel instanciation: key_func method', () =>
	{
	    var mp = new MP();
	    var bufferKey = Buffer.from('53f7000099ed9f320001008004de5f1e', 'hex');
	    var bufferMsg = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    expect(mp.key_func).toBeInstanceOf(Function);
	    expect(mp.key_func(bufferKey).toString('hex')).toBe('53f7000099ed9f320001008004de5f1e');
	    expect(mp.key_func(bufferMsg).toString('hex')).toBe('3cc30001008004de5f1eacc0403d0000');
	}
    );

    test('MiyaguchiPreneel instanciation: custom key_func method', () =>
	{
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
	    var bufferKey = Buffer.from('53f7000099ed9f320001008004de5f1e', 'hex');
	    var bufferMsg = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    expect(mp.key_func).toBeInstanceOf(Function);
	    expect(mp.key_func(bufferKey).toString('hex')).toBe('1e5fde0480000100329fed990000f753');
	    expect(mp.key_func(bufferMsg).toString('hex')).toBe('00003d40c0ac1e5fde0480000100c33c');
	}
    );

    test('MiyaguchiPreneel instanciation: pad_func method', () =>
	{
	    var mp = new MP();
	    var bufferPad = Buffer.from('015f7000099ed92051aa8a7d', 'hex');
	    var bufferMsg = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    expect(mp.pad_func).toBeInstanceOf(Function);
	    expect(mp.pad_func(Buffer.from('123'), 5).toString('hex')).toBe('3132330000');
	    expect(mp.pad_func(Buffer.from('abcd', 'hex'), 5).toString('hex')).toBe('abcd000000');
	    expect(mp.pad_func(bufferPad, 16).toString('hex')).toBe('015f7000099ed92051aa8a7d00000000');
	    expect(mp.pad_func(bufferMsg, 32).toString('hex')).toBe('3cc30001008004de5f1eacc0403d000000000000000000000000000000000000');
	}
    );

    test('MiyaguchiPreneel instanciation: custom pad_func method', () =>
	{
	    var mp = new MP(
		undefined,
		undefined,
		(v, l) =>
		{
		    var paddedBuffer = Buffer.alloc(l, 255);
		    v.copy(paddedBuffer);
		    return(paddedBuffer);
		}
	    );
	    var bufferPad = Buffer.from('0153f7000099ed9f320451aa8a7d', 'hex');
	    var bufferMsg = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    expect(mp.pad_func).toBeInstanceOf(Function);
	    expect(mp.pad_func(Buffer.from('123'), 5).toString('hex')).toBe('313233ffff');
	    expect(mp.pad_func(Buffer.from('abcd', 'hex'), 5).toString('hex')).toBe('abcdffffff');
	    expect(mp.pad_func(bufferPad, 16).toString('hex')).toBe('0153f7000099ed9f320451aa8a7dffff');
	    expect(mp.pad_func(bufferMsg, 32).toString('hex')).toBe('3cc30001008004de5f1eacc0403d0000ffffffffffffffffffffffffffffffff');
	}
    );

    test('MiyaguchiPreneel instanciation: bxor method', () =>
	{
	    var mp = new MP();
	    var bufferMsgA = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    var bufferMsgB = Buffer.from('0153f7000099ed9f320451aa8a7dffff','hex');
	    var bufferMsgC = Buffer.from('11111111111111111111111111111111','hex');
	    var bufferMsgD = Buffer.from('ffffffffffffffffffffffffffffffff','hex');
	    var bufferMsgE = Buffer.from('ffffffffffffffffffffffffffffffff','hex');
	    var bufferMsgF = Buffer.from('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex');
	    var bufferMsgG = Buffer.from('ffffffffffffffffccccccccccccccc0','hex');
	    var bufferMsgH = Buffer.from('1bbbbbbbbbbbbbbbeeeeeeeeeeeeeeef','hex');
	    expect(mp.bxor).toBeInstanceOf(Function);
	    expect(mp.bxor()).toBeUndefined();
	    expect(mp.bxor(bufferMsgA).toString('hex')).toBe('3cc30001008004de5f1eacc0403d0000');
	    expect(mp.bxor(undefined, bufferMsgA).toString('hex')).toBe('3cc30001008004de5f1eacc0403d0000');
	    expect(mp.bxor(bufferMsgA, bufferMsgB).toString('hex')).toBe('3d90f7010019e9416d1afd6aca40ffff');
	    expect(mp.bxor(bufferMsgC, bufferMsgD).toString('hex')).toBe('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');
	    expect(mp.bxor(bufferMsgE, bufferMsgF).toString('hex')).toBe('44444444444444444444444444444444');
	    expect(mp.bxor(bufferMsgG, bufferMsgH).toString('hex')).toBe('e444444444444444222222222222222f');
	}
    );

    test('MiyaguchiPreneel instanciation: comp_step method', () =>
	{
	    var mp = new MP();
	    var bufferMsg0 = Buffer.from('00000000000000000000000000000000','hex');
	    var bufferMsg1 = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    var bufferKey0 = Buffer.from('00000000000000000000000000000000','hex');
	    var bufferKey1 = Buffer.from('0153f7000099ed9f320451aa8a7dffff','hex');
	    expect(mp.comp_step).toBeInstanceOf(Function);
	    expect(mp.comp_step(undefined, undefined, bufferKey0, bufferMsg0).toString('hex')).toBe('66e94bd4ef8a2c3b884cfa59ca342b2e');
	    expect(mp.comp_step((k, v) => {return(v);}, undefined, bufferKey0, bufferMsg0).toString('hex')).toBe('00000000000000000000000000000000');
	    expect(mp.comp_step(
		undefined,
 		(k) =>
		{
		    var newk = Buffer.alloc(k.length, 0);
		    for (var i = 0; i < k.length; i++)
			newk[i] = k[k.length -1 -i];
		    return(newk);
		},
		bufferKey0,
		bufferMsg0).toString('hex')).toBe('66e94bd4ef8a2c3b884cfa59ca342b2e');
	    expect(mp.comp_step(undefined, undefined, bufferKey1, bufferMsg1).toString('hex')).toBe('852c33b900b8f43b28ad2be35b093624');
	    expect(mp.comp_step((k, v) => {return(v);}, undefined, bufferKey1, bufferMsg1).toString('hex')).toBe('0153f7000099ed9f320451aa8a7dffff');
	    expect(mp.comp_step(
		undefined,
		(k) =>
		{
		    var newk = Buffer.alloc(k.length, 0);
		    for (var i = 0; i < k.length; i++)
			newk[i] = k[k.length -1 -i];
		    return(newk);
		},
		bufferKey1,
		bufferMsg1).toString('hex')).toBe('ad9eb3a35b39fade6415394499efa3db');
	}
    );

    test('MiyaguchiPreneel instanciation: comp_step method', () =>
	{
	    var mp = new MP();
	    var bufferMsg0 = Buffer.from('00000000000000000000000000000000','hex');
	    var bufferMsg1 = Buffer.from('3cc30001008004de5f1eacc0403d0000','hex');
	    var bufferMsg2 = Buffer.from('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000','hex');
	    var bufferMsg3 = Buffer.from('3cc30153f7000099ed9f3204510153f7000099e3cc30001008004de5f1eacc0403d0000d9f320451aa8a7dffffaa8a7dffff0001008004de5f1e0153f7000099ed9f320451aa8a7dffffacc0403d0000','hex');
	    var bufferIv0 = Buffer.from('00000000000000000000000000000000','hex');
	    var bufferIv1 = Buffer.from('0153f7000099ed9f320451aa8a7dffff','hex');
	    expect(mp.comp).toBeInstanceOf(Function);
	    expect(mp.comp(bufferIv0, bufferMsg0).toString('hex')).toBe('66e94bd4ef8a2c3b884cfa59ca342b2e');
	    expect(mp.comp(bufferIv0, bufferMsg1).toString('hex')).toBe('7e438a1ac7dbac47fa1add7186fcbbe3');
	    expect(mp.comp(bufferIv0, bufferMsg2).toString('hex')).toBe('9638cbac04a474ea4ac9602cb15a1955');
	    expect(mp.comp(bufferIv0, bufferMsg3).toString('hex')).toBe('bdbb40593258d7f1b2a9d65e63e3c0d1');
	    expect(mp.comp(bufferIv1, bufferMsg0).toString('hex')).toBe('3354b8bd25f8d4c2ba35fecb54c71480');
	    expect(mp.comp(bufferIv1, bufferMsg1).toString('hex')).toBe('852c33b900b8f43b28ad2be35b093624');
	    expect(mp.comp(bufferIv1, bufferMsg2).toString('hex')).toBe('e7ce5a48177d0098b5ac73d8a2b50248');
	    expect(mp.comp(bufferIv1, bufferMsg3).toString('hex')).toBe('eb4b4c7468e98578889f787f72fda4c3');
	}
    );
})(this);

/*
 * vim: et:ts=4:sw=4:sts=4
 * -*- mode: JavaScript; coding: utf-8-unix; tab-width: 4 -*-
 */
