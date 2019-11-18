const { sign_edDSA, verify_edDSA } = require('./myedDSA');

const sk = Buffer.from('01406c2d0869484943e4ba4b3c1d69e497f06074485a3aec2fe8c9907a41cf2b', 'hex');
const pk = Buffer.from('7e6b5cea40b9d7da8bedddccd80f74cb53c30113c3331248444cffc7eb2d844c', 'hex');
const msg = Buffer.from('deadbeef', 'ascii');

const signature = sign_edDSA(msg, sk);
console.log("signature:", signature.toHex());
verify_edDSA(msg, signature.toHex(), pk) ? console.log('signature verified!') : console.log('signature not valid');
//shoudlBe: "747323E30DFA6FBCEF697C1D46271519C685F47D8BB0A07CB244B412E43DC17D364907E49392FDC1154C9E2AABA5C4A9A39EC5A6BCCD4D2667C6C216E4DA8009";