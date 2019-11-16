'use strict';
//const nacl = require('./lib-copyNacl');
const nacl = require('tweetnacl');

// generate key without seed
// const {publicKey, secretKey}= nacl.sign.keyPair();

// generate key with seed
// const {publicKey, secretKey}= nacl.sign.keyPair.fromSeed(seed);

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}
// decimal nuber to bin
function dec2bin(dec) {
    return (dec >>> 0).toString(2);
}
function bin2dec(bin) {
    return parseInt(bin, 2);
}

const string2byte = (stringa) => {
    if (stringa.length < 8) {
        const zeros = 8 - stringa.length;
        const temp = new Array(zeros).fill(0);
        const res = temp.join('') + stringa;
        return res;
    } else {
        return stringa;
    }
}
// modifies byte like rfc... 1 byte: value 1 || 32 byte: value 2  
const modByte = (byte, value) => {
    if (value == 1) {
        return byte.slice(0, 5) + "000";
    } else if (value == 2) {
        return "01" + byte.slice(2, 8);
    } else {
        throw new Error('invalid modify');
    }

}

const transformPkey = async (secretKey) => {
    // SHA-512
    const h = nacl.hash(secretKey);
    // select the lower 32 byte
    const lowH = h.slice(32, 64);
    // take first byte
    const Fbyte = string2byte(dec2bin(lowH[0]));
    // take last byte
    const Lbyte = string2byte(dec2bin(lowH[31]));

    const s = lowH.slice(0, 32);
    console.log(s.length);
    console.log("before modify", s);
    s[0] = bin2dec(modByte(Fbyte, 1));
    s[31] = bin2dec(modByte(Lbyte, 2));
    console.log("after modify", s);
    return s;
}

function convert(Uint8Arr) {
    var length = Uint8Arr.length;

    let buffer = Buffer.from(Uint8Arr);
    var result = buffer.readUIntLE(0, length);

    return result;
}

const LENGTH = 32;

const main = async () => {
    try {
        const seed = nacl.randomBytes(32);
         const {publicKey, secretKey}= nacl.sign.keyPair.fromSeed(seed);
        console.log("priv", secretKey);
         console.log("pub", publicKey);
        const pair = nacl.box.keyPair();
        console.log("priv:", buf2hex(pair.secretKey));
        console.log("pub:", buf2hex(pair.publicKey));

        const message = "deadbeef";
        const m = Buffer.from(message);
        const m2 = new Uint8Array (m);
        // console.log("m", m); 
        // console.log("m2", m2); 
        // step1
        const h = nacl.hash(pair.secretKey);
        const prefix = h.slice(32,h.length);
         
        const merge = new Uint8Array(prefix.length + m2.length);
        merge.set(prefix);
        merge.set(m2, prefix.length);
        const r = nacl.hash(merge);
        //console.log(r);
        console.log("r size:", r.length);
        const R = nacl.scalarMult.base(r);
        console.log("R", R);
        // step 2
        //PH is and indetity function
        
        //const secretKey = pair.secretKey;
        // step 2 di rfc
        // const s = await transformPkey(secretKey);
        // step 3 
        


    } catch (error) {
        console.log(error);
    }


}
main();