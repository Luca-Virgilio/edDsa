const sign_edDSA = require('./myedDSA').sign_edDSA;
const verify_edDSA = require('./myedDSA').verify_edDSA;
const EdDSA = require('elliptic').eddsa;
const crypto = require('crypto');

const ec = new EdDSA('ed25519');

const sk = '01406c2d0869484943e4ba4b3c1d69e497f06074485a3aec2fe8c9907a41cf2b';
const pk = '7e6b5cea40b9d7da8bedddccd80f74cb53c30113c3331248444cffc7eb2d844c';
const message = 'deadbeef';



const sign = sign_edDSA(message, sk);
console.log("signature", sign.toHex());

if (verify_edDSA(message, sign.toHex(), pk)){
    console.log('signature si verified');
} else {
    console.log('signature not valid');
}

/*************************  verify sign with elliptc  ********************************** */ 
console.log('........................... elliptic library .....................................')
const key = ec.keyFromPublic(pk);
const msg = Buffer.from(message, 'ascii');

if (key.verify(msg, sign)){
    console.log('signature si verified');
} else {
    console.log('signature not valid');
}



