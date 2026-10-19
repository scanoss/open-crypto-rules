// Intervening-variable arm: bare constructor with new, plain alias.
//   new ECDH(...) -> $ECDH2 = $ECDH -> computeSecret()
// One arm per file: the harness matches findings to expectations by file with
// no line locality, so arms sharing a file cannot fail independently.

const { ECDH } = require('crypto');

// TEST-RULE: javascript.crypto.ecdh.compute-secret
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, library=node:crypto, api=crypto.ECDH.computeSecret
function deriveSharedSecret(theirPublicKey) {
    const party = new ECDH('secp521r1');
    party.generateKeys();
    const agreement = party;
    return agreement.computeSecret(theirPublicKey, 'hex', 'hex');
}

module.exports = { deriveSharedSecret };
