const crypto = require('crypto');
const { createCipheriv, createDecipheriv } = require('node:crypto');

// One positive case per rule. The five emitted fields are the same static
// literals for every case of a rule, and the harness matches a TEST-METADATA
// block against the whole file without consuming the finding, so a second case
// for a rule already covered is satisfied by the first one's finding and
// asserts nothing. The form varies from rule to rule instead: an inline literal
// here, the algorithm held in a variable below, a factory for two rules and a
// constructor for a third, a plain call and two chained ones.

// Inline literal into the qualified factory, instance assigned then used.
// TEST-RULE: javascript.crypto.aes.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=AES, library=node:crypto, api=crypto.Cipheriv.update
function encryptCbc(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// The exported Decipheriv constructor, destructured off the module and called
// with new, chained straight into update(). The name is the uppercase OpenSSL
// short name, which the OBJ_NAME table resolves as readily as the lowercase
// spelling: nothing in it is captured, so the whole string matches
// case-insensitively.
// TEST-RULE: javascript.crypto.aes.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=AES, library=node:crypto, api=crypto.Decipheriv.update
function decryptOfb(key, iv, ciphertext) {
    const { Decipheriv } = crypto;
    return new Decipheriv('AES-256-OFB', key, iv).update(ciphertext);
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.aes.cipheriv-update-aead
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=AES, library=node:crypto, api=crypto.Cipheriv.update
function encryptGcm(key, iv, plaintext) {
    const algorithm = 'aes-128-gcm';
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { encrypted, tag: cipher.getAuthTag() };
}

// Destructured factory, two chainable setters between it and update() for the
// deep-expression operator to absorb, and the id- prefixed spelling of the AEAD
// name.
// TEST-RULE: javascript.crypto.aes.decipheriv-update-aead
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=AES, library=node:crypto, api=crypto.Decipheriv.update
function decryptGcmChained(key, iv, aad, tag, ciphertext) {
    const decipher = createDecipheriv('id-aes256-gcm', key, iv)
        .setAAD(aad)
        .setAuthTag(tag);
    return decipher.update(ciphertext);
}
