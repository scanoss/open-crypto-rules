const crypto = require('crypto');

// Qualified factory, instance assigned and used later in the same statement
// sequence, with generateKeys() in between. The curve string is an ordinary
// literal, but nothing in the rule reads it: the finding is the same whatever
// createECDH() is handed.
// TEST-RULE: javascript.crypto.ecdh.compute-secret
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, library=node:crypto, api=crypto.ECDH.computeSecret
function deriveSharedSecret(theirPublicKey) {
    const alice = crypto.createECDH('prime256v1');
    alice.generateKeys();
    return alice.computeSecret(theirPublicKey, 'hex', 'hex');
}

// Negative: the assignment mentions the ECDH instance, but what it binds is a
// finite-field DH object built from that instance's public key, so the
// computeSecret() below is DH's. An intervening variable counts only when it is
// the instance itself - an alias, or a method call on it.
function deriveDhFromEcdhPublic(theirPublicKey) {
    const ecdh = crypto.createECDH('prime256v1');
    const dh = crypto.createDiffieHellman(ecdh.getPublicKey());
    dh.generateKeys();
    return dh.computeSecret(theirPublicKey, 'hex', 'hex');
}

// Negative: finite-field DH exposes the same method name on an unrelated
// object, which is why the rule matches the producer rather than the method.
// This is Diffie-Hellman, not ECDH, and belongs to a family with no directory
// here yet.
function deriveDhSecret(theirPublicKey) {
    const dh = crypto.createDiffieHellman(2048);
    dh.generateKeys();
    return dh.computeSecret(theirPublicKey, 'hex', 'hex');
}

module.exports = { deriveSharedSecret, deriveDhFromEcdhPublic, deriveDhSecret };
