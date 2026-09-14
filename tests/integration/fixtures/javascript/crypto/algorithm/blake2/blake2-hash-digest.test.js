const crypto = require('crypto');

// TEST-RULE: javascript.crypto.blake2.hash-digest-b512
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=BLAKE2, algorithmName=BLAKE2b-512, algorithmParameterSetIdentifier=512, operation=digest, library=node:crypto, api=crypto.Hash.digest
function blake2b512Digest(data) {
    const hash = crypto.createHash('blake2b512');
    hash.update(data);
    return hash.digest('hex');
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.blake2.hash-digest-s256
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=BLAKE2, algorithmName=BLAKE2s-256, algorithmParameterSetIdentifier=256, operation=digest, library=node:crypto, api=crypto.Hash.digest
function blake2s256DigestFromVariable(data) {
    const algorithm = 'blake2s256';
    const hash = crypto.createHash(algorithm);
    return hash.update(data).digest('hex');
}
