const crypto = require('crypto');
const { createHmac } = require('crypto');

// Fully chained: createHmac().update().digest() in a single expression.
// TEST-RULE: javascript.crypto.hmac.digest-sha-2
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-SHA-256, hashAlgorithm=SHA-256, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacSha256(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest('hex');
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.hmac.digest-sha-2
// TEST-METADATA: algorithmName=HMAC-SHA-512, hashAlgorithm=SHA-512, operation=tag
function hmacSha512FromVariable(key, data) {
    const algorithm = 'sha512';
    const hmac = crypto.createHmac(algorithm, key);
    hmac.update(data);
    return hmac.digest();
}

// Destructured import: the factory is called bare, with no module qualifier.
// TEST-RULE: javascript.crypto.hmac.digest-sha-2
// TEST-METADATA: algorithmName=HMAC-SHA-384, hashAlgorithm=SHA-384
function hmacSha384FromBareFactory(key, data) {
    return createHmac('sha384', key).update(data).digest('hex');
}

// The exported Hmac constructor, used directly.
// TEST-RULE: javascript.crypto.hmac.digest-sha-2
// TEST-METADATA: algorithmName=HMAC-SHA-224, hashAlgorithm=SHA-224, api=crypto.Hmac.digest
function hmacSha224ViaConstructor(key, data) {
    const hmac = new crypto.Hmac('sha224', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// The same constructor called without new: it self-instantiates.
// TEST-RULE: javascript.crypto.hmac.digest-sha-2
// TEST-METADATA: algorithmName=HMAC-SHA-256, hashAlgorithm=SHA-256, api=crypto.Hmac.digest
function hmacSha256ViaBareConstructor(key, data) {
    const hmac = crypto.Hmac('sha256', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// The instance arrives through a chain of this-returning stream methods.
// TEST-RULE: javascript.crypto.hmac.digest-sha-2
// TEST-METADATA: algorithmName=HMAC-SHA-256, hashAlgorithm=SHA-256
function hmacSha256FromChain(key, parts) {
    const hmac = crypto.createHmac('sha256', key).setEncoding('hex');
    return hmac.update(parts[0]).update(parts[1]).digest('hex');
}

// Truncated SHA-512: a distinct digest, not SHA-256.
// TEST-RULE: javascript.crypto.hmac.digest-sha-2-truncated
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-SHA-512/256, hashAlgorithm=SHA-512/256, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacSha512_256(key, data) {
    const hmac = crypto.createHmac('sha512-256', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// TEST-RULE: javascript.crypto.hmac.digest-sha-1
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-SHA-1, hashAlgorithm=SHA-1, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacSha1(key, data) {
    return crypto.createHmac('sha1', key).update(data).digest('hex');
}

// TEST-RULE: javascript.crypto.hmac.digest-sha-3
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-SHA3-256, hashAlgorithm=SHA3-256, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacSha3_256(key, data) {
    const algorithm = 'sha3-256';
    const hmac = crypto.createHmac(algorithm, key);
    hmac.update(data);
    return hmac.digest('hex');
}

// TEST-RULE: javascript.crypto.hmac.digest-md5
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-MD5, hashAlgorithm=MD5, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacMd5(key, data) {
    return crypto.createHmac('md5', key).update(data).digest('hex');
}

// TEST-RULE: javascript.crypto.hmac.digest-md4
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-MD4, hashAlgorithm=MD4, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacMd4(key, data) {
    const hmac = crypto.createHmac('md4', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// The rmd160 alias for the same digest.
// TEST-RULE: javascript.crypto.hmac.digest-ripemd160
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-RIPEMD160, hashAlgorithm=RIPEMD160, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacRipemd160(key, data) {
    const algorithm = 'rmd160';
    return crypto.createHmac(algorithm, key).update(data).digest('hex');
}

// TEST-RULE: javascript.crypto.hmac.digest-blake2-b512
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-BLAKE2b-512, hashAlgorithm=BLAKE2b-512, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacBlake2b512(key, data) {
    return crypto.createHmac('blake2b512', key).update(data).digest('hex');
}

// TEST-RULE: javascript.crypto.hmac.digest-blake2-s256
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-BLAKE2s-256, hashAlgorithm=BLAKE2s-256, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacBlake2s256(key, data) {
    const hmac = crypto.createHmac('blake2s256', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// TEST-RULE: javascript.crypto.hmac.digest-sm3
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=mac, algorithmFamily=HMAC, algorithmName=HMAC-SM3, hashAlgorithm=SM3, operation=tag, library=node:crypto, api=crypto.Hmac.digest
function hmacSm3(key, data) {
    return crypto.createHmac('sm3', key).update(data).digest('hex');
}

// Negative: the digest is a runtime parameter, so no algorithm is known and
// nothing should be reported.
function hmacWithRuntimeAlgorithm(algorithm, key, data) {
    return crypto.createHmac(algorithm, key).update(data).digest('hex');
}
