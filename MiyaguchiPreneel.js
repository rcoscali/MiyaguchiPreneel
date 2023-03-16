#!/usr/bin/env node
/** @fileOverview Javascript cryptography implementation 
 * for MiyaguchiPreneel Compression function.
 *
 *
 */

(function(root) {
    "use strict";

    /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
    /*global document, window, escape, unescape, module, require, Uint32Array */
    
    var aesjs = require('aes-js');
    var options = {returnAsBuffer: true};
    

    MiyaguchiPreneel.prototype.aes_enc = (k, v) =>
    {
	var bufK = aesjs.utils.hex.toBytes(k.toString('hex'));
	var bufV = aesjs.utils.hex.toBytes(v.toString('hex'));
	var aesEcb = new aesjs.ModeOfOperation.ecb(bufK);
	var bufEnc = Buffer.from(aesEcb.encrypt(bufV));
	return(bufEnc);
    }
    
    MiyaguchiPreneel.prototype.ident = (k) =>
    {
	return(k);
    }
    
    MiyaguchiPreneel.prototype.pad_zero = (v, l) =>
    {
	var paddedBuffer = Buffer.alloc(l, 0);
	v.copy(paddedBuffer);
	return(paddedBuffer);
    }
    
    function MiyaguchiPreneel(enc, key, padding, hbits)
    {
	MiyaguchiPreneel.prototype.enc_func = enc == undefined ? this.aes_enc : enc;
	this.enc_func = MiyaguchiPreneel.prototype.enc_func;
	MiyaguchiPreneel.prototype.key_func = key == undefined ? this.ident : key;
	this.key_func = key == undefined ? this.ident : key;
	MiyaguchiPreneel.prototype.pad_func = padding == undefined ? this.pad_zero : padding;
	this.pad_func = padding == undefined ? this.pad_zero : padding;
	MiyaguchiPreneel.prototype.hlen = (hbits == undefined ? 128 : hbits);
	this.hlen = MiyaguchiPreneel.prototype.hlen;
	MiyaguchiPreneel.prototype.blksz = Math.floor(this.hlen/8);
	this.blksz = MiyaguchiPreneel.prototype.blksz;
	return(this);
    }
    
    MiyaguchiPreneel.prototype.getHLen = function()
    {
	return(MiyaguchiPreneel.prototype.hlen);
    }
    
    MiyaguchiPreneel.prototype.getBlkSz = function()
    {
	return(MiyaguchiPreneel.prototype.blksz);
    }
    
    MiyaguchiPreneel.prototype.bxor = function(a, b)
    {
	if (a === undefined && b === undefined)
	    return(undefined);
	if (a === undefined && b instanceof Buffer)
	    return(b);
	if (a instanceof Buffer && b === undefined)
	    return(a);
	var out = new Buffer.alloc(Math.min(a.length, b.length), 0);
	for (var ix = 0; ix < out.length; ix++)
	    out[ix] = a[ix] ^ b[ix];
	return(out);
    }
    
    MiyaguchiPreneel.prototype.comp_step = function(e, g, h_pre, x_cur)
    {    
	e = (e == undefined ? this.enc_func : e);
	g = (g == undefined ? this.key_func : g);
	var hKey = g(h_pre);
	var hEnc = e(hKey, x_cur);
	var h_cur = this.bxor(this.bxor(hEnc, x_cur), h_pre);
	return(h_cur);
    }
    
    MiyaguchiPreneel.prototype.comp = function(iv, msg)
    {
	var out_cur;
	var data_length = msg.length;
	var nblk = Math.floor((data_length + this.getBlkSz() -1) / this.getBlkSz());
	if (iv instanceof Buffer)
	    out_cur = Buffer.from(iv)
	else if (typeof iv === 'string')
	    out_cur = Buffer.from(iv, 'hex');
        else
            out_cur = Buffer.from('00000000000000000000000000000000', 'hex');
	for (var i = 0; i < nblk; i++)
	{
	    var out_pre = Buffer.from(out_cur);
	    var dblk = msg.subarray(i*this.getBlkSz(),
				    (i+1)*this.getBlkSz() > data_length ? data_length : (i+1)*this.getBlkSz());
	    var x_cur;
	    if (dblk.length < this.getBlkSz())
		x_cur = this.pad_func(dblk, this.getBlkSz());
	    else
		x_cur = Buffer.from(dblk);
	    out_cur = this.comp_step(this.enc_func, this.key_func, out_pre, x_cur);
	}
	return(out_cur);
    }
    
    // NodeJS
    if (typeof exports !== 'undefined')
    {
	exports.MiyaguchiPreneel = MiyaguchiPreneel;
	exports.getBlkSz = MiyaguchiPreneel.prototype.getBlkSz;
	exports.getHLen = MiyaguchiPreneel.prototype.getHLen;
	exports.comp_step = MiyaguchiPreneel.prototype.comp_step;
	exports.comp = MiyaguchiPreneel.prototype.comp;
	module.exports = MiyaguchiPreneel;
    }
    // RequireJS/AMD
    // http://www.requirejs.org/docs/api.html
    // https://github.com/amdjs/amdjs-api/wiki/AMD
    else if (typeof(define) === 'function' && define.amd)
    {
	define([], function() { return MiyaguchiPreneel; });
    }
    // Web Browsers
    else
    {
	
	root.MiyaguchiPreneel = MiyaguchiPreneel;
    }
})(this);

/*
 * vim: et:ts=4:sw=4:sts=4
 * -*- mode: JavaScript; coding: utf-8-unix; tab-width: 4 -*-
 */
