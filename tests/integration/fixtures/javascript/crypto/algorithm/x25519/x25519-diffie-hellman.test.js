const crypto = require('crypto');

// Two keypairs held whole rather than destructured, the halves reaching the
// one-shot as property reads off the tainted objects. Qualified calls at both
// ends, so the receiver binds through the require. X25519 takes no options
// object at all - there is no curve to name, the type string being the curve.
// TEST-RULE: javascript.crypto.x25519.diffie-hellman
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=X25519, library=node:crypto, api=crypto.diffieHellman
function deriveX25519Secret() {
    const alice = crypto.generateKeyPairSync('x25519');
    const bob = crypto.generateKeyPairSync('x25519');
    return crypto.diffieHellman({ privateKey: alice.privateKey, publicKey: bob.publicKey });
}

module.exports = { deriveX25519Secret };
