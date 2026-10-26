const crypto = require('crypto');
const { createSign, generateKeyPairSync } = require('crypto');

// Inline curve literal, module-qualified factory, assigned sink. The update()
// rule needs the terminating sign() as well, that being where the EC key - the
// only thing naming the family - reaches the Sign instance.
// TEST-RULE: javascript.crypto.ecdsa.sign-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.Sign.update
function signP256(data) {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const signer = crypto.createSign('sha256');
    signer.update(data);
    return signer.sign(privateKey, 'hex');
}

// Curve held in a variable, destructured import, fully chained sink: the shape
// the taint design exists for.
// TEST-RULE: javascript.crypto.ecdsa.sign-sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.Sign.sign
function signP384(data) {
    const curve = 'secp384r1';
    const keys = generateKeyPairSync('ec', { namedCurve: curve });
    return createSign('sha384').update(data).sign(keys.privateKey);
}

// One-shot module function, module-qualified. 'sha512' names the digest only;
// the curve on the key is what makes this ECDSA.
// TEST-RULE: javascript.crypto.ecdsa.sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.sign
function signP521(data) {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
    return crypto.sign('sha512', data, privateKey);
}
