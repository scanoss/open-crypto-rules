// The Sign / Verify instance reached through an intervening variable, which is
// its own set of sink branches: the variable takes the context directly or off
// a single chained call, which in an -update rule may be the update() itself
// or an update() behind one further call. The plain files reach the terminal
// call from the creation variable, so these four shapes need their own
// fixture; the four class rules take one case each, varied over the creation
// spellings the plain files leave untried.
const crypto = require('crypto');
const { createSign, Verify, generateKeyPairSync } = require('crypto');

// Alias takes the update(), which is the one the -update rule reads as its
// update(); bare destructured factory.
// TEST-RULE: javascript.crypto.ecdsa.sign-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.Sign.update
function signAliasedUpdate(data) {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const signer = createSign('sha256');
    const updated = signer.update(data);
    return updated.sign(privateKey, 'hex');
}

// Alias off a single this-returning call, chained sink; module-qualified
// constructor with new.
// TEST-RULE: javascript.crypto.ecdsa.sign-sign
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.Sign.sign
function signAliasedChain(data) {
    const curve = 'P-384';
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });
    const signer = new crypto.Sign('sha384');
    const s = signer.setDefaultEncoding('utf8');
    return s.update(data).sign(privateKey);
}

// Alias off an update() chained behind another this-returning call; exported
// constructor without new, which Node's legacy classes self-instantiate from.
// TEST-RULE: javascript.crypto.ecdsa.verify-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.Verify.update
function verifyAliasedUpdate(data, signature) {
    const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const verifier = crypto.Verify('sha256');
    const v = verifier.setDefaultEncoding('utf8').update(data);
    return v.verify(publicKey, signature);
}

// Plain alias, assigned sink; destructured constructor with new.
// TEST-RULE: javascript.crypto.ecdsa.verify-verify
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, library=node:crypto, api=crypto.Verify.verify
function verifyAliased(data, signature) {
    const keys = generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
    const verifier = new Verify('sha512');
    const v = verifier;
    v.update(data);
    return v.verify(keys.publicKey, signature);
}

// Negative: an intervening variable holds what its right-hand side returned,
// which for a wrapper call is not the context. The branches take the bare
// `$CTX2 = $CTX` and one chained call off it, so a helper return stops the
// match whether it wraps the instance or the update().
function withLogging(ctx) {
    return ctx;
}

function signThroughWrapper(data) {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const signer = crypto.createSign('sha256');
    const wrapped = withLogging(signer);
    wrapped.update(data);
    return wrapped.sign(privateKey);
}

function signThroughWrappedUpdate(data) {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const signer = crypto.createSign('sha256');
    const wrapped = withLogging(signer.update(data));
    return wrapped.sign(privateKey);
}
