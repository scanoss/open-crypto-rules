const crypto = require('crypto');

// Fully chained: createHash().update().digest() in a single expression.
// TEST-RULE: javascript.crypto.md5.hash-digest
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=MD5, algorithmName=MD5, algorithmParameterSetIdentifier=128, operation=digest, library=node:crypto, api=crypto.Hash.digest
function md5Digest(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.md5.hash-digest
// TEST-METADATA: algorithmFamily=MD5, algorithmName=MD5, operation=digest
function md5DigestFromVariable(data) {
    const algorithm = 'md5';
    const hash = crypto.createHash(algorithm);
    hash.update(data);
    return hash.digest('hex');
}

// The exported Hash constructor, used directly.
// TEST-RULE: javascript.crypto.md5.hash-digest
// TEST-METADATA: algorithmFamily=MD5, algorithmName=MD5, api=crypto.Hash.digest
function md5DigestViaConstructor(data) {
    const hash = new crypto.Hash('md5');
    hash.update(data);
    return hash.digest('hex');
}

// The same constructor called without new: it self-instantiates.
// TEST-RULE: javascript.crypto.md5.hash-digest
// TEST-METADATA: algorithmFamily=MD5, algorithmName=MD5, api=crypto.Hash.digest
function md5DigestViaBareConstructor(data) {
    const hash = crypto.Hash('md5');
    hash.update(data);
    return hash.digest('hex');
}
