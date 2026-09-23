const crypto = require('crypto');
const { generateKeyPairSync, verify } = require('crypto');

// Inline key-type literal, module-qualified. The algorithm argument is null
// because Ed25519 signs one-shot only and names no digest; the key type is the
// whole of the evidence.
// TEST-RULE: javascript.crypto.eddsa.sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=EdDSA, library=node:crypto, api=crypto.sign
function signEd25519(data) {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    return crypto.sign(null, data, privateKey);
}

// Key type held in a variable, destructured import.
// TEST-RULE: javascript.crypto.eddsa.verify
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=EdDSA, library=node:crypto, api=crypto.verify
function verifyEd448(data, signature) {
    const keyType = 'ed448';
    const keys = generateKeyPairSync(keyType);
    return verify(null, data, keys.publicKey, signature);
}
