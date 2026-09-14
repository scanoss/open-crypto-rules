const crypto = require('crypto');
const { createCipheriv, createDecipheriv } = require('node:crypto');

// TEST-RULE: javascript.crypto.aes.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=AES, algorithmName=AES, algorithmMode=cbc, algorithmParameterSetIdentifier=256, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function encryptCbc(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// TEST-RULE: javascript.crypto.aes.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=AES, algorithmName=AES, algorithmMode=cbc, algorithmParameterSetIdentifier=256, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function decryptCbc(key, iv, ciphertext) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.aes.cipheriv-update-aead
// TEST-METADATA: algorithmPrimitive=ae, algorithmFamily=AES, algorithmMode=gcm, algorithmParameterSetIdentifier=128, operation=encrypt, api=crypto.Cipheriv.update
function encryptGcm(key, iv, plaintext) {
    const algorithm = 'aes-128-gcm';
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { encrypted, tag: cipher.getAuthTag() };
}

// TEST-RULE: javascript.crypto.aes.decipheriv-update-aead
// TEST-METADATA: algorithmPrimitive=ae, algorithmFamily=AES, algorithmMode=gcm, algorithmParameterSetIdentifier=128, operation=decrypt, api=crypto.Decipheriv.update
function decryptGcm(key, iv, tag, ciphertext) {
    const algorithm = 'aes-128-gcm';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// Destructured import, algorithm from a module constant.
// TEST-RULE: javascript.crypto.aes.cipheriv-update
// TEST-METADATA: algorithmMode=ctr, algorithmParameterSetIdentifier=192, operation=encrypt
function encryptCtr(key, iv, plaintext) {
    const algorithm = 'aes-192-ctr';
    const cipher = createCipheriv(algorithm, key, iv);
    return cipher.update(plaintext);
}

// TEST-RULE: javascript.crypto.aes.decipheriv-update
// TEST-METADATA: algorithmMode=ctr, algorithmParameterSetIdentifier=192, operation=decrypt
function decryptCtr(key, iv, ciphertext) {
    const decipher = createDecipheriv('aes-192-ctr', key, iv);
    return decipher.update(ciphertext);
}

// Chained call, no intermediate variable.
// TEST-RULE: javascript.crypto.aes.cipheriv-update
// TEST-METADATA: algorithmMode=ecb, algorithmParameterSetIdentifier=128, operation=encrypt
function encryptEcb(key, plaintext) {
    return crypto.createCipheriv('aes-128-ecb', key, null).update(plaintext);
}

// Instances built with the exported constructors instead of the factories.
// TEST-RULE: javascript.crypto.aes.cipheriv-update
// TEST-METADATA: algorithmMode=ofb, algorithmParameterSetIdentifier=256, operation=encrypt
function encryptOfb(key, iv, plaintext) {
    const cipher = new crypto.Cipheriv('aes-256-ofb', key, iv);
    return cipher.update(plaintext);
}

// TEST-RULE: javascript.crypto.aes.decipheriv-update
// TEST-METADATA: algorithmMode=ofb, algorithmParameterSetIdentifier=256, operation=decrypt
function decryptOfb(key, iv, ciphertext) {
    const { Decipheriv } = crypto;
    return new Decipheriv('aes-256-ofb', key, iv).update(ciphertext);
}

// The exported constructors self-instantiate, so they also return an instance
// when called without new.
// TEST-RULE: javascript.crypto.aes.cipheriv-update
// TEST-METADATA: algorithmMode=cbc, algorithmParameterSetIdentifier=192, operation=encrypt
function encryptCbcNoNew(key, iv, plaintext) {
    const { Cipheriv } = crypto;
    const cipher = Cipheriv('aes-192-cbc', key, iv);
    return cipher.update(plaintext);
}

// TEST-RULE: javascript.crypto.aes.decipheriv-update
// TEST-METADATA: algorithmMode=cbc, algorithmParameterSetIdentifier=192, operation=decrypt
function decryptCbcNoNew(key, iv, ciphertext) {
    return crypto.Decipheriv('aes-192-cbc', key, iv).update(ciphertext);
}

// setAutoPadding() returns the instance, so the chain still ends in update().
// TEST-RULE: javascript.crypto.aes.cipheriv-update
// TEST-METADATA: algorithmMode=cfb, algorithmParameterSetIdentifier=128, operation=encrypt
function encryptCfbUnpadded(key, iv, plaintext) {
    return crypto.createCipheriv('aes-128-cfb', key, iv)
        .setAutoPadding(false)
        .update(plaintext);
}

// Two chainable setters between the factory and update().
// TEST-RULE: javascript.crypto.aes.decipheriv-update-aead
// TEST-METADATA: algorithmPrimitive=ae, algorithmMode=gcm, algorithmParameterSetIdentifier=256, operation=decrypt
function decryptGcmChained(key, iv, aad, tag, ciphertext) {
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
        .setAAD(aad)
        .setAuthTag(tag);
    return decipher.update(ciphertext);
}

// Negative case: the algorithm is a runtime parameter, so no algorithm metadata
// can be proven and nothing should be reported.
function encryptDynamic(algorithm, key, iv, plaintext) {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    return cipher.update(plaintext);
}

// Negative case: update() on a hash, not on a Cipheriv instance.
function digest(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}

// Negative case: update() called on an unrelated object that happens to share
// the method name.
function unrelatedUpdate(key, iv, data) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const store = { update: (value) => value };
    return store.update(data);
}

// Negative case: the instance is used as a Transform stream, so no update()
// call exists. Deliberately out of scope for the update() rules.
function encryptStream(key, iv, input, output) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    input.pipe(cipher).pipe(output);
}

// Negative case: the deprecated password-based crypto.createCipher(), which is
// a different API and derives its own key and IV.
function legacyCipher(password, data) {
    const cipher = crypto.createCipher('aes-256-cbc', password);
    return cipher.update(data, 'utf8', 'hex');
}
