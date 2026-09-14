const { createHash } = require('crypto');

// Destructured import: the factory is called without a module object.
// TEST-RULE: javascript.crypto.sha-1.hash-digest
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-1, algorithmName=SHA-1, algorithmParameterSetIdentifier=160, operation=digest, library=node:crypto, api=crypto.Hash.digest
function sha1Digest(data) {
    const hash = createHash('sha1');
    hash.update(data);
    return hash.digest('hex');
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.sha-1.hash-digest
// TEST-METADATA: algorithmFamily=SHA-1, algorithmName=SHA-1, operation=digest
function sha1DigestFromVariable(data) {
    const algorithm = 'sha1';
    return createHash(algorithm).update(data).digest('hex');
}
