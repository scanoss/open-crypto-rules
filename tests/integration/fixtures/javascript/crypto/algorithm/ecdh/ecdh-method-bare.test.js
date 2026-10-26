// Intervening-variable arm: bare constructor called without new, Node's legacy
// classes self-instantiating, instance reached through a this-returning setter.
//   ECDH(...) -> $ECDH2 = $ECDH.$M(...) -> computeSecret()
// The deprecated setPublicKey() returns the instance just as setPrivateKey()
// does; one case covers the arm for both.
// One arm per file: the harness matches findings to expectations by file with
// no line locality, so arms sharing a file cannot fail independently.

const { ECDH } = require('crypto');

// TEST-RULE: javascript.crypto.ecdh.compute-secret
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, library=node:crypto, api=crypto.ECDH.computeSecret
function deriveSharedSecret(privateKey, theirPublicKey) {
    const ecdh = ECDH('prime256v1');
    const party = ecdh.setPrivateKey(privateKey, 'hex');
    return party.computeSecret(theirPublicKey, 'hex', 'hex');
}

module.exports = { deriveSharedSecret };
