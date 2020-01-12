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

        (Buffer.compare(pub, pk) == 0) ? console.log('keyGenerator is correct') : console.log('keyGenerator error');

    } catch (error) {
        console.log(error);
    }
}

const KeyGeneration = (secretKey) => {
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
    const hl = h.slice(0, 32);
    // STEP 2
    // These transformations guarantee that the private key will always 
    //belong to the same subgroup of EC points on the curve 
    const s = transformByte(hl);
    const sBig = new BN(s, 'hex');
    // STEP 3
    // G or B, depends by definition, is the Base Point, the Generator
    // A = s[G]
    const A = ed.g.mul(sBig);
    // STEP 4 
    //encoding point
    const ABuff = Buffer.from(ed.encodePoint(A));
    return ABuff;
}

const testMultiply = () => {
    const s = "676e33f9fb9149bc9b9c311981d6799c6cc3397d8bf75777a808643ddcae8168";
    const G = {
        x: "15112221349535400772501151409588531511454012693041857206046113283949847762202",
        y: "46316835694926478169428394003475163141307993866256225615783033603165251855960"
    }

    const A = {
        'x': "14370984746645013685236688114213849896403646545913472908271180401779787238528",
        'y': "41162972829759158181737301444831101697378794022886415695497094000588414640157"
    }

    console.log('prova', new BN('676e33f9fb9149bc9b9c311981d6799c6cc3397d8bf75777a808643ddcae8168','hex').toString(10));
    const test = "1"
    const res = multi(s, G);
    console.log('Ax: ', res.x.toString(10));
    console.log('Ay: ', res.y.toString(10));
    // console.log(res.x.eq(new BN(G.x)));
    // console.log(res.y.eq(new BN(G.y)));
    console.log(res.x.eq(new BN(A.x)));
    console.log(res.y.eq(new BN(A.y)));


}

const multi = (scalar, Point) => {
    const base = new BN(2);
    const val = new BN(19)
    const max = new BN(255)
    const p = base.pow(max).sub(val);

    const P = {
        'x': new BN(Point.x, 10),
        'y': new BN(Point.y, 10),
        'z': new BN(1),
    }
    P['t'] = (P.x.mul(P.y)).mod(p);
    // double and add method
    const k = hexToBin(scalar);
    let res = {
        'x':new BN(0),
        'y':new BN(1),
        'z':new BN(1),
        't':new BN(0)
    }
    // const { x, y, z, t } = P;
    // let res = { x, y, z, t };

    for (let i = 0; i < k.length; i = i + 1) {
        // always apply doubling
        res = additionPoint(res, res);
        if (k[i] == '1') {
            // add base point
            res = additionPoint(res, P);
        }
    }
    return {'x':res.x,'y':res.y};

    // return {'x':res.x.div(res.z),'y':res.y.div(res.z)};
}

const additionPoint2 = (p1, p2) => {
    const base = new BN(2);
    const val = new BN(19)
    const max = new BN(255)
    const p = base.pow(max).sub(val);


    const d1 = new BN(-121665);
    const d2 = new BN(121666);
    const d = (d1.mul(d2.invm(p))).umod(p);
    //  37095705934669439343138083508754565189542113879843219016388785533085940283555

    
    const x1 = p1['x'];
    const y1 = p1['y'];
    const z1 = p1['z'];
    const t1 = p1['t'];
    const x2 = p2['x'];
    const y2 = p2['y'];
    const z2 = p2['z'];
    const t2 = p2['t'];

    const A = ((y1.sub(x1)).mul(y2.sub(x2))).mod(p);
    const B =  ((y1.add(x1)).mul(y2.add(x2))).mod(p);
    const C = (((t1.mul(new BN(2))).mul(d)).mul(t2)).mod(p);
    const D = ((z1.mul(new BN(2))).mul(z2)).mod(p);
    const E = B.sub(A);
    const F = D.sub(C);
    const G = D.add(C);
    const H = B.add(A);
    const x3 = E.mul(F);
    const y3 = G.mul(H);
    const t3 = E.mul(H);
    const z3 = F.mul(G);

    return { 'x': x3, 'y': y3, 'z':z3, 't':t3 };
}


const additionPoint = (p1, p2) => {
    const base = new BN(2);
    const val = new BN(19)
    const max = new BN(255)
    const p = base.pow(max).sub(val);
    const a = new BN(1);

    const d1 = new BN(-121665);
    const d2 = new BN(121666);
    const d = (d1.mul(d2.invm(p))).umod(p);

    const x1 = p1['x'];
    const y1 = p1['y'];
    const x2 = p2['x'];
    const y2 = p2['y'];

    const parz = (((d.mul(x1)).mul(x2)).mul(y1)).mul(y2);

    const A = ((x1.mul(y2)).add(y1.mul(x2))).mod(p);
    const B = (new BN(1).add(parz)).invm(p);
    const C = ((y1.mul(y2)).add(x1.mul(x2))).mod(p);
    const E = (new BN(1).sub(parz)).invm(p);
    const x3 = (A.mul(B)).mod(p);
    const y3 = (C.mul(E)).mod(p);
    // const x3 = (((x1.mul(y2)).add(y1.mul(x2)).mod(p)).mul((new BN(1).add(parz)).invm(p))).mod(p);
    // const y3 = (((y1.mul(y2)).sub(a.mul(x1.mul(x2))).mod(p)).mul((new BN(1).sub(parz)).invm(p))).mod(p);

    return { 'x': x3, 'y': y3 };
}

// prune the buffer
const transformByte = (h) => {
    // copy h 
    const h1 = h.toString('hex');
    // convert 1fr byte in bin
    const byteFr = hexToBin(h[0], 10, 8);
    // 1fr = [0,4] + 000
    const newFr = byteFr.substring(0, 5) + '000';
    // convert last byte in bin
    const byteLs = hexToBin(h[31], 10, 8);
    // last = 01 + last[2,7]
    const newLs = '01' + byteLs.substring(2, 8);
    // add modification to the buffer
    const s = BinToHex(newFr).concat(h1.substring(2, h1.length - 2), BinToHex(newLs));
    // interpreter s as LE
    const sBuff = Buffer.from(s, 'hex');
    const sRev = sBuff.reverse();
    return sRev.toString('hex');
}
// byte espresso in base_ val num (hex=16 e int=10)
// return string
const hexToBin = (hex, base, pad) => {
    try {
        //if (typeof base != 'number' || base>36 || base < 2) throw new Error ('invalid base');
        const temp = new BN(hex, base);
        const value = temp.toString(2);
        // pad obtain 8 bit
        if (pad) return value.padStart(pad, '0');
        else return value;
    } catch (error) {
        console.log(error);
    }
}

const BinToHex = (bin, base = 16) => {
    try {
        const temp = new BN(bin, 2);
        const value = temp.toString(16);

        return value;
    } catch (error) {
        console.log(error);
    }
}
 main();
//testMultiply();