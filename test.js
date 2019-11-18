const crypto = require('crypto');
const BN = require('bn.js');
const EdDSA = require('elliptic').eddsa;
const utils = require('elliptic/lib/elliptic/utils');


var ed = new EdDSA('ed25519');
// const G = ed.curve.g ;
// const p = ed.curve.p;
// const a = ed.curve.a;
// const d = ed.curve.d;

const sk = '01406c2d0869484943e4ba4b3c1d69e497f06074485a3aec2fe8c9907a41cf2b';
const pk = '7e6b5cea40b9d7da8bedddccd80f74cb53c30113c3331248444cffc7eb2d844c';
const message = 'deadbeef';


function buf2hex(buffer) { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

//const testhash =(prefix, message) => {
    
//const testhash = () =>{    
const hashFun = (params) => {   
const hash = crypto.createHash('sha512');
    params.forEach(element => {
        hash.update(element);
    });
    const output = hash.digest();
    console.log("hash output:", output);
    
        return utils.intFromLE(output).umod(ed.curve.n);
  };


// step 1 H(seed)-->  32 byte|| 32 byte
// .digest return a buffer
// const h = crypto.createHash('sha512').update(sk).digest();


//  const hL = h.slice(0, 32);
//  const prefix = h.slice(32, h.length);
//  console.log(prefix);
// // step2 H(prefix || M)
// const bufferMsg = Buffer.from(message, 'ascii');
// //console.log(new Uint16Array(bufferMsg));
// const bufferA = Buffer.concat([prefix, bufferMsg], prefix.length + bufferMsg.length);

// const r = crypto.createHash('sha512').update(bufferA).digest()
// console.log(r);

// // interpreting the buffer in little endian 
// const r_number = new BN (r,'le');
// console.log("r_number", r_number);

// step1: create key
// const key = ed.keyFromSecret(sk);

// //const test_p = Buffer.from (key.messagePrefix()).toString('hex');
// const test_p = new Uint8Array(key.messagePrefix()); 
// console.log("test",test_p);
// const test_m = Buffer.from(message, 'ascii');//.toString('hex');
// console.log("msg", test_m);

// const r_test2 = testhash(new Array (test_p, test_m));
// console.log("rest_2",r_test2);




//console.log("r_test", r_test);
// correct r <BN: c2121f877e155f9992a673040859890bd4d6fa76e81a6d33032e48f5f268a42>




