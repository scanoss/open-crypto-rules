// Intervening-variable arm: qualified factory, plain alias.
//   crypto.createECDH(...) -> $ECDH2 = $ECDH -> computeSecret()
// One arm per file: the harness matches findings to expectations by file with
// no line locality, so arms sharing a file cannot fail independently.

const crypto = require('crypto');

// TEST-RULE: javascript.crypto.ecdh.compute-secret
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, library=node:crypto, api=crypto.ECDH.computeSecret
function deriveSharedSecret(theirPublicKey) {
    const party = crypto.createECDH('prime256v1');
    party.generateKeys();
    const agreement = party;
    return agreement.computeSecret(theirPublicKey, 'hex', 'hex');
}

module.exports = { deriveSharedSecret };
