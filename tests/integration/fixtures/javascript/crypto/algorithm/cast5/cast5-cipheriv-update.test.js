const crypto = require('crypto');

// TEST-RULE: javascript.crypto.cast5.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=CAST5, algorithmName=CAST5, algorithmMode=cbc, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function cast5Encrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('cast5-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.cast5.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=CAST5, algorithmName=CAST5, algorithmMode=ecb, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function cast5Decrypt(key, iv, ciphertext) {
    const algorithm = 'cast5-ecb';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
