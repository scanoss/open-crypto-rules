const crypto = require('crypto');

// TEST-RULE: javascript.crypto.sha-3.hash-digest
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-3, algorithmName=SHA3-256, algorithmParameterSetIdentifier=256, operation=digest, library=node:crypto, api=crypto.Hash.digest
function sha3_256Digest(data) {
    const hash = crypto.createHash('sha3-256');
    hash.update(data);
    return hash.digest('hex');
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.sha-3.hash-digest
// TEST-METADATA: algorithmName=SHA3-512, algorithmParameterSetIdentifier=512, operation=digest
function sha3_512DigestFromVariable(data) {
    const algorithm = 'sha3-512';
    return crypto.createHash(algorithm).update(data).digest('hex');
}

// SHAKE is an extendable output function, reported as xof.
// TEST-RULE: javascript.crypto.sha-3.hash-digest-shake
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=xof, algorithmFamily=SHA-3, algorithmName=SHAKE128, algorithmParameterSetIdentifier=128, operation=digest, library=node:crypto, api=crypto.Hash.digest
function shake128Digest(data) {
    const hash = crypto.createHash('shake128', { outputLength: 32 });
    hash.update(data);
    return hash.digest('hex');
}

// TEST-RULE: javascript.crypto.sha-3.hash-digest-shake
// TEST-METADATA: algorithmPrimitive=xof, algorithmName=SHAKE256, algorithmParameterSetIdentifier=256, operation=digest
function shake256DigestFromVariable(data) {
    const algorithm = 'shake256';
    return crypto.createHash(algorithm).update(data).digest('hex');
}

// A Hash piped into from a stream: pipe() returns the Hash it wrote to.
// TEST-RULE: javascript.crypto.sha-3.hash-digest
// TEST-METADATA: algorithmName=SHA3-384, algorithmParameterSetIdentifier=384, operation=digest
function sha3_384DigestOfStream(input) {
    const hash = input.pipe(crypto.createHash('sha3-384'));
    return new Promise((resolve) => hash.on('finish', () => resolve(hash.digest('hex'))));
}
