'use strict'
const crypto = require('crypto');
const EdDSA = require('elliptic').eddsa;
const BN = require('bn.js');

const ed = new EdDSA('ed25519');
const sk = 'c0c416d2d3116a1011021042af360403bfdc911d99eb62f408d1833fa6e12888';

const main = async _ => {
    try {
        
        const pub = KeyGeneration(sk);
        console.log('public key:\t\t\t', pub.toString('hex'));

        const key = ed.keyFromSecret(sk.toString('hex'));
        const pk = Buffer.from(key.pubBytes());
        console.log('library public key: ', pk.toString('hex'));
        
        (Buffer.compare(pub,pk)==0)? console.log('keyGenerator is correct') : console.log('keyGenerator error');

    } catch (error) {
        console.log(error);
    }
}

const KeyGeneration = (secretKey) =>{
    /** 
         *  rfc8032 - EDDSA ED25519 
         *  generation key
         */
        // STEP 1
        // 32 byte secret key
        const b = Buffer.from(secretKey, 'hex');
        // h = H(b)
        const h = crypto.createHash('sha512').update(b).digest();
        // use only first 32 byte
        // h -> hl = [0,31] 
        const hl = h.slice(0,32);
        // STEP 2
        // These transformations guarantee that the private key will always 
        //belong to the same subgroup of EC points on the curve 
        const s = transformByte(hl);
        const sBig=new BN(s,'hex');
        // STEP 3
        // G or B, depends by definition, is the Base Point, the Generator
        // A = s[G]
        const A = ed.g.mul(sBig);
        // STEP 4 
        //encoding point
        const ABuff = Buffer.from(ed.encodePoint(A));
        return ABuff;
}

// prune the buffer
const transformByte = (h) => {
    // copy h 
    const h1 =h.toString('hex');
    // convert 1fr byte in bin
    const byteFr = hexToBin(h[0], 10);
    // 1fr = [0,4] + 000
    const newFr = byteFr.substring(0, 5) + '000';
    // convert last byte in bin
    const byteLs = hexToBin(h[31], 10);
    // last = 01 + last[2,7]
    const newLs = '01' + byteLs.substring(2, 8);
    // add modification to the buffer
    const s = BinToHex(newFr).concat(h1.substring(2,h1.length-2), BinToHex(newLs));
    // interpreter s as LE
    const sBuff = Buffer.from(s,'hex');
    const sRev = sBuff.reverse();
    return sRev.toString('hex');
}
// byte espresso in base_ val num (hex=16 e int=10)
// return string
const hexToBin = (hex, base) => {
    try {
        //if (typeof base != 'number' || base>36 || base < 2) throw new Error ('invalid base');
        const temp = new BN(hex, base);
        const value = temp.toString(2);
        // pad obtain 8 bit
        return value.padStart(8, '0');
    } catch (error) {
        console.log(error);
    }
}

const BinToHex = (bin, base=16) => {
    try {
        const temp = new BN(bin,2);
        const value = temp.toString(16);

        return value;
    } catch (error) {
        console.log(error);
    }
}


main();