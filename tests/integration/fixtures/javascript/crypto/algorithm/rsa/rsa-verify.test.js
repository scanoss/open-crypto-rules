const crypto = require('crypto');
const { createVerify, verify } = require('crypto');

// Algorithm held in a variable, exported constructor with new, two-statement
// sink.
// TEST-RULE: javascript.crypto.rsa.verify-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSA, operation=verify, library=node:crypto, api=crypto.Verify.update
function verifySha256(publicKey, data, signature) {
    const algorithm = 'RSA-SHA256';
    const verifier = new crypto.Verify(algorithm);
    verifier.update(data);
    return verifier.verify(publicKey, signature, 'hex');
}

// Inline literal, destructured import, fully chained sink.
// TEST-RULE: javascript.crypto.rsa.verify-verify
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSA, operation=verify, library=node:crypto, api=crypto.Verify.verify
function verifySha512(publicKey, data, signature) {
    return createVerify('rsa-sha512').update(data).verify(publicKey, signature);
}

// PSS is named by the padding option on verify(), not by the algorithm string,
// so this reports RSA-PSS even though 'sha256' names no signature algorithm.
// TEST-RULE: javascript.crypto.rsa.verify-verify-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSA-PSS, operation=verify, library=node:crypto, api=crypto.Verify.verify
function verifyPss(publicKey, data, signature) {
    const verifier = crypto.createVerify('sha256');
    verifier.update(data);
    return verifier.verify({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, signature);
}

// One-shot module function, algorithm held in a variable, module-qualified.
// TEST-RULE: javascript.crypto.rsa.verify
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSA, operation=verify, library=node:crypto, api=crypto.verify
function verifyOneShot(publicKey, data, signature) {
    const algorithm = 'rsa-sha3-256';
    return crypto.verify(algorithm, data, publicKey, signature);
}

// One-shot with PSS, destructured import: the algorithm argument is null
// because the padding, not the digest name, is what identifies the scheme.
// TEST-RULE: javascript.crypto.rsa.verify-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSA-PSS, operation=verify, library=node:crypto, api=crypto.verify
function verifyOneShotPss(publicKey, data, signature) {
    return verify(null, data, {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, signature);
}
