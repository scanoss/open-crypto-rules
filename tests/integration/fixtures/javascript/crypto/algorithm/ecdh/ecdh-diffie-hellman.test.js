const { generateKeyPairSync, diffieHellman } = require('node:crypto');

// Destructured require, bare calls at both ends: no receiver to bind, so the
// import alone gates the sink. The keypair is destructured out of the generator
// and the two halves reach the one-shot as shorthand properties - the shape the
// taint design exists for, the sink naming no algorithm of its own. namedCurve
// is a literal here but carries no condition, no field recording the curve.
// TEST-RULE: javascript.crypto.ecdh.diffie-hellman
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, library=node:crypto, api=crypto.diffieHellman
function deriveEcSecret() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    return diffieHellman({ privateKey, publicKey });
}

// Negative: the same one-shot over finite-field 'dh' KeyObjects, which Node
// accepts just as readily - a MODP secret, not a curve one. The 'ec' key type
// on the source is the only thing keeping this from reporting ECDH, and
// asymmetricKeyType, which would settle it, is a runtime value.
function deriveDhSecret() {
    const { privateKey, publicKey } = generateKeyPairSync('dh', { primeLength: 2048 });
    return diffieHellman({ privateKey, publicKey });
}

module.exports = { deriveEcSecret, deriveDhSecret };
