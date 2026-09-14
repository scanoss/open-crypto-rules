const crypto = require('crypto');

// TEST-RULE: javascript.crypto.sm3.hash-digest
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SM3, algorithmName=SM3, algorithmParameterSetIdentifier=256, operation=digest, library=node:crypto, api=crypto.Hash.digest
function sm3Digest(data) {
    const hash = crypto.createHash('sm3');
    hash.update(data);
    return hash.digest('hex');
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.sm3.hash-digest
// TEST-METADATA: algorithmFamily=SM3, algorithmName=SM3, operation=digest
function sm3DigestFromVariable(data) {
    const algorithm = 'sm3';
    return crypto.createHash(algorithm).update(data).digest('hex');
}
