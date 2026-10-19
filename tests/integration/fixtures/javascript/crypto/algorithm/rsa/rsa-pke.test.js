// The six pke rules under require(). rsa-pke-esm.test.js gives each of them a
// second case under import, so every pke rule is proved on both branches of the
// import gate - $MOD binds quoted here and bare there, through separate
// branches, so a gate that works under one does not imply the other.
const crypto = require('crypto');
const nodeCrypto = require('node:crypto');
const forge = require('node-forge-shim');
const { privateDecrypt, privateEncrypt } = require('crypto');

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

// Receiver bound to the same non-'crypto' require alias, on a rule whose other
// case is a plain ESM default import.
// TEST-RULE: javascript.crypto.rsa.public-decrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, library=node:crypto, api=crypto.publicDecrypt
function decryptWithPublicKey(publicKey, ciphertext) {
    return nodeCrypto.publicDecrypt(publicKey, ciphertext).toString('utf8');
}

// Destructured require, bare call, explicit PKCS#1 v1.5 padding - which is the
// only padding Node allows here, so no -oaep rule reports alongside.
// TEST-RULE: javascript.crypto.rsa.private-encrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, library=node:crypto, api=crypto.privateEncrypt
function encryptWithPrivateKey(privateKey, plaintext) {
    return privateEncrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, Buffer.from(plaintext, 'utf8'));
}

// OAEP named by an inline constant. The base public-encrypt rule matches this
// call too, so an OAEP encryption reports twice - the -oaep rule is what adds
// the scheme.
// TEST-RULE: javascript.crypto.rsa.public-encrypt-oaep
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, algorithmName=RSAES-OAEP, library=node:crypto, api=crypto.publicEncrypt
function encryptToPublicKeyOaep(publicKey, plaintext) {
    return crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
    }, Buffer.from(plaintext, 'utf8'));
}

// Negative cases follow, carrying no TEST- comment: the harness generates a
// test per TEST-METADATA block only, so these record a design decision and
// give the next reader something to run by hand rather than failing the suite.

// publicEncrypt reached through an inline require rather than a bound alias.
// The gate matches an assignment or an import, so this spelling is a known gap
// rather than a rule that happens not to fire.
function encryptInlineRequire(publicKey, plaintext) {
    return require('crypto').publicEncrypt(publicKey, Buffer.from(plaintext));
}

// publicEncrypt on a receiver bound to a different module, with a crypto
// require sitting in the same file. The gate unifies the receiver with the
// require it came from, so the crypto import above does not lend this call the
// library. This is the one negative in the family that would start firing if
// the gate ever stopped resolving the binding and matched the receiver by
// name instead - the parameter-receiver form below cannot catch that, having
// no require to resolve in the first place.
function encryptViaOtherLibrary(publicKey, plaintext) {
    return forge.publicEncrypt(publicKey, plaintext);
}

// publicEncrypt of the same name on an unrelated client object.
function encryptViaClient(client, publicKey, plaintext) {
    return client.publicEncrypt(publicKey, plaintext);
}
