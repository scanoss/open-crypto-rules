const crypto = require('crypto');

// TEST-RULE: javascript.crypto.rc4.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=stream-cipher, algorithmFamily=RC4, algorithmName=RC4, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function rc4Encrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('rc4', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.rc4.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=stream-cipher, algorithmFamily=RC4, algorithmName=RC4, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function rc4Decrypt(key, iv, ciphertext) {
    const algorithm = 'rc4';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
