const crypto = require('crypto');

// TEST-RULE: javascript.crypto.md4.hash-digest
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=MD4, algorithmName=MD4, algorithmParameterSetIdentifier=128, operation=digest, library=node:crypto, api=crypto.Hash.digest
function md4Digest(data) {
    const hash = crypto.createHash('md4');
    hash.update(data);
    return hash.digest('hex');
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.md4.hash-digest
// TEST-METADATA: algorithmFamily=MD4, algorithmName=MD4, operation=digest
function md4DigestFromVariable(data) {
    const algorithm = 'md4';
    const hash = crypto.createHash(algorithm);
    return hash.update(data).digest('hex');
}
