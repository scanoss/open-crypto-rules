// ESM counterpart to rsa-verify.test.js, and the second and last case each
// Verify rule gets. One gate spelling per case: default import, namespace
// import and named import each reach the Verify rules through their own branch
// of the import gate, so a gate that works only under require() fails here.
// The creation and flow forms are the ones rsa-verify.test.js does not take:
// the bare exported constructor, and the handoff through the instance that
// update() returns. Data is fed through end() elsewhere, where update() would
// give verify-update a further candidate finding in the file.
import nodeCrypto from 'node:crypto';
import * as crypto from 'crypto';
import { Verify, verify } from 'crypto';

// Named import, exported constructor with new and no receiver to bind.
// TEST-RULE: javascript.crypto.rsa.verify-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.Verify.update
export function hashIntoVerifier(data) {
    const verifier = new Verify('RSA-SHA256');
    verifier.update(data);
    return verifier;
}

// Namespace import, factory, algorithm held in a variable.
// TEST-RULE: javascript.crypto.rsa.verify-verify
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.Verify.verify
export function verifySha512(publicKey, data, signature) {
    const algorithm = 'rsa-sha512';
    const verifier = crypto.createVerify(algorithm);
    verifier.end(data);
    return verifier.verify(publicKey, signature);
}

// Default import under a node: specifier, reaching the sink through the handle
// update() hands back - the second of the two handoffs the class rules model,
// and the only case in the family that takes it. PSS is named by the padding
// option, not by the algorithm string, so 'sha256' keeps the base rule out of
// it, and the handoff has to carry the instance for the -pss rule as much as
// for the base one.
// TEST-RULE: javascript.crypto.rsa.verify-verify-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSASSA-PSS, library=node:crypto, api=crypto.Verify.verify
export function verifyPss(publicKey, data, signature) {
    const verifier = nodeCrypto.createVerify('sha256');
    const fed = verifier.update(data);
    return fed.verify({
        key: publicKey,
        padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, signature);
}

// One-shot module function, named import, inline literal.
// TEST-RULE: javascript.crypto.rsa.verify
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, library=node:crypto, api=crypto.verify
export function verifyOneShot(publicKey, data, signature) {
    return verify('RSA-SHA384', data, publicKey, signature);
}

// One-shot with PSS, namespace import: the algorithm argument is null because
// the padding, not the digest name, is what identifies the scheme.
// TEST-RULE: javascript.crypto.rsa.verify-pss
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSA, algorithmName=RSASSA-PSS, library=node:crypto, api=crypto.verify
export function verifyOneShotPss(publicKey, data, signature) {
    return crypto.verify(null, data, {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, signature);
}
