const crypto = require('crypto');

// TEST-RULE: javascript.crypto.sha-2.hash-digest
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-2, algorithmName=SHA-256, algorithmParameterSetIdentifier=256, operation=digest, library=node:crypto, api=crypto.Hash.digest
function sha256Digest(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.sha-2.hash-digest
// TEST-METADATA: algorithmName=SHA-512, algorithmParameterSetIdentifier=512, operation=digest
function sha512DigestFromVariable(data) {
    const algorithm = 'sha512';
    const hash = crypto.createHash(algorithm);
    return hash.update(data).digest();
}

// Fully chained, with the digest returned as a Buffer.
// TEST-RULE: javascript.crypto.sha-2.hash-digest
// TEST-METADATA: algorithmName=SHA-384, algorithmParameterSetIdentifier=384, operation=digest
function sha384Digest(data) {
    return crypto.createHash('sha384').update(data).digest();
}

// Truncated SHA-512: a distinct algorithm name, not SHA-256.
// TEST-RULE: javascript.crypto.sha-2.hash-digest-truncated
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-2, algorithmName=SHA-512/256, algorithmParameterSetIdentifier=256, operation=digest, library=node:crypto, api=crypto.Hash.digest
function sha512_256Digest(data) {
    const hash = crypto.createHash('sha512-256');
    hash.update(data);
    return hash.digest('hex');
}

// TEST-RULE: javascript.crypto.sha-2.hash-digest-truncated
// TEST-METADATA: algorithmName=SHA-512/224, algorithmParameterSetIdentifier=224, operation=digest
function sha512_224DigestFromVariable(data) {
    const algorithm = 'sha512-224';
    return crypto.createHash(algorithm).update(data).digest('hex');
}

// hash.copy() is the other producer of a Hash: here the original never digests,
// only the copies do, so the copy is the only thing that can carry the finding.
// TEST-RULE: javascript.crypto.sha-2.hash-digest
// TEST-METADATA: algorithmName=SHA-224, algorithmParameterSetIdentifier=224, operation=digest
function sha224DigestsFromCopies(prefix, suffixes) {
    const base = crypto.createHash('sha224');
    base.update(prefix);
    return suffixes.map((suffix) => {
        const hash = base.copy();
        hash.update(suffix);
        return hash.digest('hex');
    });
}

// The instance arrives through a chain of this-returning methods.
// TEST-RULE: javascript.crypto.sha-2.hash-digest
// TEST-METADATA: algorithmName=SHA-256, algorithmParameterSetIdentifier=256, operation=digest
function sha256DigestFromChain(parts) {
    const hash = crypto.createHash('sha256').setEncoding('hex');
    return hash.update(parts[0]).update(parts[1]).digest('hex');
}

// Negative: the algorithm is a runtime parameter, so no algorithm is known and
// nothing should be reported.
function digestWithRuntimeAlgorithm(algorithm, data) {
    return crypto.createHash(algorithm).update(data).digest('hex');
}

// Negative: digest() on an object that is not a Hash.
function encodeRecord(record) {
    return record.digest('hex');
}

// Negative: createHmac names a digest too, but the asset is a MAC and belongs
// to the Hmac rules, not these.
function hmacDigest(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest('hex');
}
