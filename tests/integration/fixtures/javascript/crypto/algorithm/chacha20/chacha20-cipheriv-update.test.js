const crypto = require('crypto');

// TEST-RULE: javascript.crypto.chacha20.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=stream-cipher, algorithmFamily=ChaCha20, algorithmName=ChaCha20, algorithmParameterSetIdentifier=256, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function chacha20Encrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('chacha20', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.chacha20.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=stream-cipher, algorithmFamily=ChaCha20, algorithmName=ChaCha20, algorithmParameterSetIdentifier=256, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function chacha20Decrypt(key, iv, ciphertext) {
    const algorithm = 'chacha20';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// TEST-RULE: javascript.crypto.chacha20.cipheriv-update-poly1305
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=ChaCha20, algorithmName=ChaCha20-Poly1305, algorithmParameterSetIdentifier=256, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function chacha20Poly1305Encrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.chacha20.decipheriv-update-poly1305
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=ChaCha20, algorithmName=ChaCha20-Poly1305, algorithmParameterSetIdentifier=256, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function chacha20Poly1305Decrypt(key, iv, ciphertext) {
    const algorithm = 'chacha20-poly1305';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
