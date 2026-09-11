const crypto = require('crypto');

// TEST-RULE: javascript.crypto.rc2.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=RC2, algorithmName=RC2, algorithmMode=cbc, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function rc2Encrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('rc2-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.rc2.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=RC2, algorithmName=RC2, algorithmMode=ofb, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function rc2Decrypt(key, iv, ciphertext) {
    const algorithm = 'rc2-ofb';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
