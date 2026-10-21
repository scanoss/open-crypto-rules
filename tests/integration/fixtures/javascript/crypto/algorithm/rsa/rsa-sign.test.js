const crypto = require('crypto');
const forge = require('node-forge-shim');
const { createSign, sign } = require('crypto');

// Inline literal, module-qualified factory, two-statement sink. The caller
// does the signing, so sign-sign has this function's sign() nowhere to match,
// and the chained case below feeds data through end() rather than update(), so
// this is the only sign-update candidate in the file. Both matter: validation
// is file-scoped with no line locality, so a second candidate anywhere in the
// file would satisfy this block on its own and leave the two-statement sink
// untested.
// TEST-RULE: javascript.crypto.rsa.sign-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.Sign.update
function hashIntoSigner(data) {
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(data);
    return signer;
}

// Algorithm held in a variable, destructured import, fully chained sink: the
// shape the taint design exists for. Data goes in through end(), where
// update() would hand sign-update a second candidate.
// TEST-RULE: javascript.crypto.rsa.sign-sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.Sign.sign
function signSha512(privateKey, data) {
    const algorithm = 'rsa-sha512';
    return createSign(algorithm).end(data).sign(privateKey);
}

// PSS is named by the padding option on sign(), not by the algorithm string, so
// this reports RSA-PSS even though 'sha256' names no signature algorithm.
// TEST-RULE: javascript.crypto.rsa.sign-sign-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSASSA-PSS, library=node:crypto, api=crypto.Sign.sign
function signPss(privateKey, data) {
    const signer = crypto.createSign('sha256');
    signer.update(data);
    return signer.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
}

// One-shot module function, destructured import, inline literal.
// TEST-RULE: javascript.crypto.rsa.sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.sign
function signOneShot(privateKey, data) {
    return sign('RSA-SHA384', data, privateKey);
}

// One-shot with PSS: the algorithm argument is null because the padding, not
// the digest name, is what identifies the scheme here.
// TEST-RULE: javascript.crypto.rsa.sign-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSASSA-PSS, library=node:crypto, api=crypto.sign
function signOneShotPss(privateKey, data) {
    return crypto.sign(null, data, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
}

// Negative cases follow. They carry no TEST- comment, the harness generating a
// test per TEST-METADATA block only, so they record a design decision and give
// the next reader something to run by hand rather than failing the suite.

// The algorithm is a runtime parameter. Nothing is known about it, and
// reporting nothing is the correct outcome - a guess would be a CBOM entry for
// an algorithm this code may never use. This holds only while no caller in
// this file passes a literal: the suite scans with --taint-intrafile, so a
// caller doing signDynamic(key, data, 'RSA-SHA256') makes both sign-update and
// sign-sign fire here, correctly. Keep the literal out of the file.
function signDynamic(privateKey, data, algorithm) {
    return crypto.createSign(algorithm).update(data).sign(privateKey);
}

// createSign and sign() of the same names on a receiver bound to a different
// module, with a crypto require at the top of the file. The gate unifies the
// receiver with the require it came from, so the crypto import does not lend
// these calls the library, and the RSA algorithm string does not either.
function signViaOtherLibrary(privateKey, data) {
    return forge.createSign('RSA-SHA256').update(data).sign(privateKey);
}

// sign() of the same name on an unrelated object, carrying an algorithm string
// the rules do accept. The class rules only reach a sink from a createSign or
// Sign call and the one-shot rules only from a bound crypto receiver, so
// neither the method name nor the string proves anything on its own.
function signOrder(ledger, order) {
    return ledger.sign('RSA-SHA256', order);
}

// An RSA algorithm name with no crypto call anywhere near it. The string is a
// taint source, so a sink pattern that over-reached would surface here.
const SIGNING_DEFAULTS = {
    algorithm: 'RSA-SHA256',
    encoding: 'base64',
};
module.exports = { SIGNING_DEFAULTS };
