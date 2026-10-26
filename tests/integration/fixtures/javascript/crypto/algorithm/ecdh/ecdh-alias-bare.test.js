// Intervening-variable arm: bare constructor called without new, Node's legacy
// classes self-instantiating, plain alias.
//   ECDH(...) -> $ECDH2 = $ECDH -> computeSecret()
// The alias is how ECDH reaches the intervening-variable form at all, there
// being no copy() method on the class.
// One arm per file: the harness matches findings to expectations by file with
// no line locality, so arms sharing a file cannot fail independently.

const { ECDH } = require('node:crypto');

// TEST-RULE: javascript.crypto.ecdh.compute-secret
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, library=node:crypto, api=crypto.ECDH.computeSecret
function deriveSharedSecret(theirPublicKey) {
    const party = ECDH('secp521r1');
    party.generateKeys();
    const agreement = party;
    return agreement.computeSecret(theirPublicKey, 'hex', 'hex');
}

module.exports = { deriveSharedSecret };
