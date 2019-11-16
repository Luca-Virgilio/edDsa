const EdDSA = require('elliptic').eddsa;
const crypto = require('crypto');

var ec = new EdDSA('ed25519');


const base64ToHex = (base64) =>{
    const buffer = Buffer.from(base64, 'base64');
    return buffer.toString('hex');
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

const hash = crypto.createHash('sha512');

/*  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

//const seed = crypto.randomBytes(32);
//console.log("seed", seed.toString('hex'));
const nacl_sk = '01406c2d0869484943e4ba4b3c1d69e497f06074485a3aec2fe8c9907a41cf2b';
const seed = new Buffer (nacl_sk, 'hex');
// console.log(typeof(seed));
// console.log(seed);
const key = ec.keyFromSecret(seed);

const sk = key.getSecret();
const pk = key.getPublic();



console.log("sk:",sk.toString('hex'));
//console.log(typeof(pk));
console.log("pk:",buf2hex(pk));

const message = 'deadbeef';
const msgHash = Buffer.from('deadbeef', 'ascii');

const signature = key.sign(msgHash);
console.log("signature: ", signature.toHex());
// console.log(buf2hex(signature._Rencoded));
// console.log(buf2hex(signature._Sencoded));




/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
// const msg2 = Buffer.from('deadbeef', 'ascii');
 
// const pub = Buffer.from("fmtc6kC519qL7d3M2A90y1PDARPDMxJIREz/x+sthEw=", "base64").toString(`hex`);
// console.log("pub", pub);
// const key2 = ec.keyFromPublic(pub, 'hex');
// const sig2 = Buffer.from("dHMj4w36b7zvaXwdRicVGcaF9H2LsKB8skS0EuQ9wX02SQfkk5L9wRVMniqrpcSpo57FprzNTSZnxsIW5NqACQ==", "base64").toString('hex');
// console.log("sig2:", sig2);
// console.log(key2.verify(msg2, sig2));
