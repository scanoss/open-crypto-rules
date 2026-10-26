// Intervening-variable arm: qualified constructor with new, instance reached
// through a this-returning setter.
//   new crypto.ECDH(...) -> $ECDH2 = $ECDH.$M(...) -> computeSecret()
// One arm per file: the harness matches findings to expectations by file with
// no line locality, so arms sharing a file cannot fail independently.

const crypto = require('node:crypto');

// TEST-RULE: javascript.crypto.ecdh.compute-secret
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, library=node:crypto, api=crypto.ECDH.computeSecret
function deriveSharedSecret(privateKey, theirPublicKey) {
    const ecdh = new crypto.ECDH('secp384r1');
    const party = ecdh.setPrivateKey(privateKey, 'hex');
    return party.computeSecret(theirPublicKey, 'hex', 'hex');
}

module.exports = { deriveSharedSecret };
