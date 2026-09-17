const crypto = require('crypto');
const nodeCrypto = require('node:crypto');
const { privateDecrypt } = require('crypto');

// Module-qualified call, key passed directly, so no padding is named and only
// the base rule reports.
// TEST-RULE: javascript.crypto.rsa.public-encrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, library=node:crypto, api=crypto.publicEncrypt
function encryptToPublicKey(publicKey, plaintext) {
    return crypto.publicEncrypt(publicKey, Buffer.from(plaintext, 'utf8'));
}

// Destructured require, bare call: no receiver to bind, so the import alone
// gates it.
// TEST-RULE: javascript.crypto.rsa.private-decrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, library=node:crypto, api=crypto.privateDecrypt
function decryptWithPrivateKey(privateKey, ciphertext) {
    return privateDecrypt(privateKey, ciphertext);
}

// node: specifier under an alias that is not 'crypto', so the gate has to
// resolve the alias rather than match the receiver by name. Padding held in a
// variable: the shape the taint design exists for.
// TEST-RULE: javascript.crypto.rsa.private-decrypt-oaep
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, algorithmName=RSAES-OAEP, library=node:crypto, api=crypto.privateDecrypt
function decryptWithPrivateKeyOaep(privateKey, ciphertext) {
    const padding = nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING;
    return nodeCrypto.privateDecrypt({ key: privateKey, padding }, ciphertext);
}
