'use strict';
const crypto = require('crypto');
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

const sha256BILE = message => {
    try {
        const hashBuffer = crypto.createHash('sha512').update(message).digest();
        const hashBI = utils.intFromLE(hashBuffer).umod(ed.curve.n);
        return hashBI;
    } catch(error) {
        console.log(error);
    }
}

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

// Buffer.from is necessary ?!?!?!?!?

const sign_edDSA = (msg, sk) => {
    try {
    // step1: create key
    const key = ed.keyFromSecret(sk.toString('hex'));

    // step2: H(prefix || M)
    const prefix = Buffer.from(key.messagePrefix());
    const r = sha256BILE(Buffer.concat([prefix, msg]));
    // step3:  R= [r]G 
    const R = ed.g.mul(r);
    // convert point to value
    const Rencode = ed.encodePoint(R);

    // step4: k = H(R || A || m)
    //const s_ = ed.hashInt(Rencoded, key.pubBytes(), msg);
    //const pub = new Uint8Array(key.pubBytes());
    const pub = key.getPublic();
    const A = Buffer.from(key.getPublic());
    const k = sha256BILE(Buffer.concat([Buffer.from(Rencode), A, msg]));

    // step5:  S = (r + s*sk) mod L
    const S = r.add(k.mul(key.priv())).umod(ed.curve.n);

    const res = ed.makeSignature({ R, S, Rencode });
    return res;
    } catch(error) {
        console.log(error);
    }
}

const verify_edDSA = (msg, sign, pk) => {
    try {
    // step 1: obtain R, A, M

    const sig = ed.makeSignature(sign);
    const key = ed.keyFromPublic(pk.toString('hex'));

    const R = sig.Rencoded();
    const A = key.pubBytes();
    //step 2: H(R || A || M)
    //const k = ed.hashInt(R_value, A_value, msg);
    const k = sha256BILE(Buffer.concat([Buffer.from(R), Buffer.from(A), msg]));
    // step 3: SG = R + k[A]
    const SG = ed.g.mul(sig.S());
    const R_plus_kA = sig.R().add(key.pub().mul(k));

    return R_plus_kA.eq(SG);
    } catch(error) {
        console.log(error);
    }
}


module.exports = {
    sign_edDSA,
    verify_edDSA
}




