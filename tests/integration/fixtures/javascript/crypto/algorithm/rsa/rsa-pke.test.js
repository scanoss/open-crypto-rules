const crypto = require('crypto');
const nodeCrypto = require('node:crypto');
const { privateDecrypt } = require('crypto');

// Module-qualified call, key passed directly, so no padding is named and only
// the base rule reports.
// TEST-RULE: javascript.crypto.rsa.public-encrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, algorithmName=RSA, operation=encrypt, library=node:crypto, api=crypto.publicEncrypt
function encryptToPublicKey(publicKey, plaintext) {
    return crypto.publicEncrypt(publicKey, Buffer.from(plaintext, 'utf8'));
}

// Destructured require, bare call: no receiver to bind, so the import alone
// gates it.
// TEST-RULE: javascript.crypto.rsa.private-decrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, algorithmName=RSA, operation=decrypt, library=node:crypto, api=crypto.privateDecrypt
function decryptWithPrivateKey(privateKey, ciphertext) {
    return privateDecrypt(privateKey, ciphertext);
}

// node: specifier under an alias that is not 'crypto', so the gate has to
// resolve the alias rather than match the receiver by name. Padding held in a
// variable: the shape the taint design exists for.
// TEST-RULE: javascript.crypto.rsa.private-decrypt-oaep
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, algorithmName=RSA-OAEP, operation=decrypt, library=node:crypto, api=crypto.privateDecrypt
function decryptWithPrivateKeyOaep(privateKey, ciphertext) {
    const padding = nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING;
    return nodeCrypto.privateDecrypt({ key: privateKey, padding }, ciphertext);
}

// Negative: a wrapper exposing its own publicEncrypt(). The import gate binds
// the receiver to the imported alias, so only the crypto.publicEncrypt() inside
// the method reports - the two calls on the wrapper do not, even though this
// file does import node crypto.
class RsaKey {
    constructor(key) { this.key = key; }
    publicEncrypt(data) { return crypto.publicEncrypt(this.key, data); }
}

function encryptThroughWrapper(rsaKey, data) {
    return rsaKey.publicEncrypt(data);
}
