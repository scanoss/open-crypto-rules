const crypto = require('crypto');
const { createVerify, verify } = require('crypto');

// Curve held in a variable, exported constructor with new, assigned sink.
// TEST-RULE: javascript.crypto.ecdsa.verify-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.Verify.update
function verifyP256(data, signature) {
    const curve = 'prime256v1';
    const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
    const verifier = new crypto.Verify('sha256');
    verifier.update(data);
    return verifier.verify(publicKey, signature, 'hex');
}

// Inline literal, destructured import, fully chained sink.
// TEST-RULE: javascript.crypto.ecdsa.verify-verify
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.Verify.verify
function verifyP384(data, signature) {
    const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    return createVerify('sha384').update(data).verify(publicKey, signature);
}

// One-shot module function, destructured import, JOSE spelling of the curve.
// TEST-RULE: javascript.crypto.ecdsa.verify
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.verify
function verifyP521(data, signature) {
    const keys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-521' });
    return verify('sha512', data, keys.publicKey, signature);
}
