const signer = require('nacl-signature');
const nacl = require('tweetnacl');
// .box use secret key with 32 byte || .sign use secret key with 64 byte 
const hexToBase64 = (hex)=>{
 const buffer = Buffer.from(hex,'hex');
 return buffer.toString('base64');
}

const base64ToHex = (base64) =>{
    const buffer = Buffer.from(base64, 'base64');
    return buffer.toString('hex');
}
// base64 encoded secret key
 const secretKey = 'AUBsLQhpSElD5LpLPB1p5JfwYHRIWjrsL+jJkHpBzyt+a1zqQLnX2ovt3czYD3TLU8MBE8MzEkhETP/H6y2ETA==';
// base64 encoded public key
 const publicKey = 'fmtc6kC519qL7d3M2A90y1PDARPDMxJIREz/x+sthEw=';
// const sk = 'sk in hex 01406c2d0869484943e4ba4b3c1d69e497f06074485a3aec2fe8c9907a41cf2b7e6b5cea40b9d7da8bedddccd80f74cb53c30113c3331248444cffc7eb2d844c'
// const pk = '7e6b5cea40b9d7da8bedddccd80f74cb53c30113c3331248444cffc7eb2d844c'

// const secretKey  = hexToBase64(sk);
// const publicKey = hexToBase64(pk);
console.log("sk in hex", base64ToHex(secretKey));
console.log("pk in hex", base64ToHex(publicKey));

// base64 encoded message signature
const message = "deadbeef";

const signature = signer.sign(message, secretKey);
console.log(typeof(signature));
console.log("signature:", signature);
console.log("signature in hex:", base64ToHex(signature));


// verifying a message, given its signature and the sender public key
if (signer.verify(message, signature, publicKey)){
    console.log('Signature is valid');
} else {
    console.log("not valid");
}

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
console.log("altra prova ....................");

const sk = Buffer.from('01406c2d0869484943e4ba4b3c1d69e497f06074485a3aec2fe8c9907a41cf2b7e6b5cea40b9d7da8bedddccd80f74cb53c30113c3331248444cffc7eb2d844c','hex').toString('base64');
const pk = Buffer.from('7e6b5cea40b9d7da8bedddccd80f74cb53c30113c3331248444cffc7eb2d844c','hex').toString('base64');

const sig3 = signer.sign(message, sk);
console.log(typeof(sig3));
console.log("sig3:", sig3);
const sig2 = Buffer.from('747323e30dfa6fbcef697c1d46271519c685f47d8bb0a07cb244b412e43dc17d364907e49392fdc1154c9e2aaba5c4a9a39ec5a6bccd4d2667c6c216e4da8009','hex').toString('base64');
console.log("sig2",sig2);

if (signer.verify(message, sig2, publicKey)){
    console.log('Signature is valid');
} else {
    console.log("not valid");
}
