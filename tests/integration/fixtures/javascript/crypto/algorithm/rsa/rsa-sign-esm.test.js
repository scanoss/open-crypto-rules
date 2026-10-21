// ESM counterpart to rsa-sign.test.js, and the second and last case each Sign
// rule gets. The import gate reaches require() and the three ESM spellings
// through separate branches - $MOD binds quoted under require and bare under
// import - so a gate that works only under require() fails here. One gate
// spelling per case, and the creation and flow forms are the ones
// rsa-sign.test.js does not take: the exported constructor with and without
// new, and the handoff through an intervening variable. Data is fed through
// end() where update() would give another rule a second candidate finding.
import crypto from 'node:crypto';
import * as nodeCrypto from 'crypto';
import { Sign, sign } from 'crypto';

// Default import under a node: specifier, exported constructor with new.
// TEST-RULE: javascript.crypto.rsa.sign-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.Sign.update
export function hashIntoSigner(data) {
    const signer = new crypto.Sign('RSA-SHA256');
    signer.update(data);
    return signer;
}

// Named import, bare call without new - no receiver to bind, so the import
// alone gates it - reaching the sink through a plain copy of the instance,
// the first of the two handoffs the class rules model. Nothing else in the
// family exercises either handoff.
// TEST-RULE: javascript.crypto.rsa.sign-sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.Sign.sign
export function signSha512(privateKey, data) {
    const signer = Sign('rsa-sha512');
    const alias = signer;
    alias.end(data);
    return alias.sign(privateKey, 'hex');
}

// Namespace import. PSS is named by the padding option, not by the algorithm
// string, so this reports RSA-PSS while 'sha256' keeps the base rule out.
// TEST-RULE: javascript.crypto.rsa.sign-sign-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSASSA-PSS, library=node:crypto, api=crypto.Sign.sign
export function signPss(privateKey, data) {
    const signer = nodeCrypto.createSign('sha256');
    signer.end(data);
    return signer.sign({
        key: privateKey,
        padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
}

// One-shot module function, named import, algorithm held in a variable.
// TEST-RULE: javascript.crypto.rsa.sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.sign
export function signOneShot(privateKey, data) {
    const algorithm = 'RSA-SHA3-256';
    return sign(algorithm, data, privateKey);
}

// One-shot with PSS, default import: the algorithm argument is null because
// the padding, not the digest name, is what identifies the scheme.
// TEST-RULE: javascript.crypto.rsa.sign-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSASSA-PSS, library=node:crypto, api=crypto.sign
export function signOneShotPss(privateKey, data) {
    return crypto.sign(null, data, {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
}
