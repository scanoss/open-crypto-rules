const crypto = require('crypto');

// TEST-RULE: javascript.crypto.ripemd160.hash-digest
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=RIPEMD, algorithmName=RIPEMD160, algorithmParameterSetIdentifier=160, operation=digest, library=node:crypto, api=crypto.Hash.digest
function ripemd160Digest(data) {
    const hash = crypto.createHash('ripemd160');
    hash.update(data);
    return hash.digest('hex');
}

// The rmd160 alias, held in a variable.
// TEST-RULE: javascript.crypto.ripemd160.hash-digest
// TEST-METADATA: algorithmFamily=RIPEMD, algorithmName=RIPEMD160, operation=digest
function rmd160Digest(data) {
    const algorithm = 'rmd160';
    const hash = crypto.createHash(algorithm);
    return hash.update(data).digest('hex');
}
