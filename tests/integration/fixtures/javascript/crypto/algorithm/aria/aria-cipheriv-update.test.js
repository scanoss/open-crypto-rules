const crypto = require('crypto');

// TEST-RULE: javascript.crypto.aria.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=ARIA, algorithmName=ARIA, algorithmMode=cbc, algorithmParameterSetIdentifier=256, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function ariaEncrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('aria-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.aria.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=ARIA, algorithmName=ARIA, algorithmMode=ctr, algorithmParameterSetIdentifier=128, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function ariaDecrypt(key, iv, ciphertext) {
    const algorithm = 'aria-128-ctr';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// TEST-RULE: javascript.crypto.aria.cipheriv-update-aead
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=ARIA, algorithmName=ARIA, algorithmMode=gcm, algorithmParameterSetIdentifier=256, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function ariaAeadEncrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('aria-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.aria.decipheriv-update-aead
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=ARIA, algorithmName=ARIA, algorithmMode=ccm, algorithmParameterSetIdentifier=192, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function ariaAeadDecrypt(key, iv, ciphertext) {
    const algorithm = 'aria-192-ccm';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
