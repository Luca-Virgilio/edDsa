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


//console.log(pk_point);
// console.log(ed.curve);

// console.log(a);
// console.log(d.toString());
// console.log(p.toString());

//const point= ed.decodePoint(pk);

//  console.log(point);
// const newpk = ed.encodePoint(point);
// console.log(buf2hex(newpk));


// edDSA sign

// step 1 H(seed)-->  32 byte|| 32 byte
// .digest return a buffer
const h = crypto.createHash('sha512').update(sk).digest();

const hL = h.slice(0, 32);
const prefix = h.slice(32, h.length);

// step2 H(prefix || M)
const bufferMsg = Buffer.from(message, 'ascii');
//console.log(new Uint16Array(bufferMsg));
const bufferA = Buffer.concat([prefix, bufferMsg], prefix.length + bufferMsg.length);

const r = crypto.createHash('sha512').update(bufferA).digest()
// console.log(r);

// // interpreting the buffer in little endian 
// const r_number = new BN (r,'le');
// console.log("r_number", r_number);

//console.log("r_test", r_test);
// correct r <BN: c2121f877e155f9992a673040859890bd4d6fa76e81a6d33032e48f5f268a42>



// const R_point = ed.g.mul(r_number);
// const R = ed.encodePoint(R_point);


// const a = new BN('a',16);
// const b = new BN (7,10);
// a.iadd(b);
// console.log(a.toString());

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

// Buffer.from is necessary ?!?!?!?!?

const sign_edDSA = (message, sk) => {
    // step1: create key
    const key = ed.keyFromSecret(sk);

    // step2: H(prefix || M)
    const bufferMsg = Buffer.from(message, 'ascii');
    const msg = utils.parseBytes(bufferMsg);
    const r_test = ed.hashInt(key.messagePrefix(), msg);

    // step3:  R= [r]G 
    const R = ed.g.mul(r_test);
    // convert point to value
    var Rencoded = ed.encodePoint(R);

    // step4: k = H(R || A || m)
    const s_ = ed.hashInt(Rencoded, key.pubBytes(), msg);
    // step5:  S = (r + s*k) mod L
    const S = r_test.add(s_.mul(key.priv())).umod(ed.curve.n);

    return ed.makeSignature({ R: R, S: S, Rencode: Rencoded });

}

const verify_edDSA = (message, sign, pk) => {

    // step 1: obtain R, A, M
    const bMsg = Buffer.from(message, 'ascii');
    const msg = utils.parseBytes(bMsg);

    const sig = ed.makeSignature(sign);
    const key = ed.keyFromPublic(pk);

    const R_value = sig.Rencoded();
    const A_value = key.pubBytes();
    //step 2: H(R || A || M)
    const k = ed.hashInt(R_value, A_value, msg);
    // step 3: SG = R + k[A]
    const SG = ed.g.mul(sig.S());
    const R_plus_kA = sig.R().add(key.pub().mul(k));

    return R_plus_kA.eq(SG);

}


module.exports = {
    sign_edDSA,
    verify_edDSA
}




