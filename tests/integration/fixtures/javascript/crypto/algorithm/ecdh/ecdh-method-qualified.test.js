// Intervening-variable arm: qualified factory, instance reached through a
// this-returning setter.
//   crypto.createECDH(...) -> $ECDH2 = $ECDH.$M(...) -> computeSecret()
// setPrivateKey() and setPublicKey() both return the instance, so the result of
// either is another handle on the same ECDH.
// One arm per file: the harness matches findings to expectations by file with
// no line locality, so arms sharing a file cannot fail independently.

const crypto = require('crypto');

// TEST-RULE: javascript.crypto.ecdh.compute-secret
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, library=node:crypto, api=crypto.ECDH.computeSecret
function deriveSharedSecret(privateKey, theirPublicKey) {
    const ecdh = crypto.createECDH('prime256v1');
    const party = ecdh.setPrivateKey(privateKey, 'hex');
    return party.computeSecret(theirPublicKey, 'hex', 'hex');
}

module.exports = { deriveSharedSecret };
