const crypto = require('crypto');
const { createSign } = require('crypto');

// Inline literal, module-qualified factory, two-statement sink.
// TEST-RULE: javascript.crypto.rsa.sign-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSA, operation=sign, library=node:crypto, api=crypto.Sign.update
function signSha256(privateKey, data) {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(data);
    return sign.sign(privateKey, 'hex');
}

// Algorithm held in a variable, destructured import, fully chained sink: the
// shape the taint design exists for.
// TEST-RULE: javascript.crypto.rsa.sign-sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSA, operation=sign, library=node:crypto, api=crypto.Sign.sign
function signSha512(privateKey, data) {
    const algorithm = 'sha512WithRSAEncryption';
    return createSign(algorithm).update(data).sign(privateKey);
}

// PSS is named by the padding option on sign(), not by the algorithm string, so
// this reports RSA-PSS even though 'sha256' names no signature algorithm.
// TEST-RULE: javascript.crypto.rsa.sign-sign-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSA-PSS, operation=sign, library=node:crypto, api=crypto.Sign.sign
function signPss(privateKey, data) {
    const sign = crypto.createSign('sha256');
    sign.update(data);
    return sign.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
}

// Negative: the algorithm is a runtime parameter, so nothing is known and
// nothing should be reported.
function signWithRuntimeAlgorithm(algorithm, privateKey, data) {
    return crypto.createSign(algorithm).update(data).sign(privateKey);
}

// Negative: 'sha256' names a digest, not a signature scheme. The signature
// algorithm comes from the key, which may be EC or DSA, so reporting RSA here
// would be a guess. Only signPss() above reports, and only because of the
// padding option.
function signWithBareDigestName(privateKey, data) {
    return crypto.createSign('sha256').update(data).sign(privateKey);
}
