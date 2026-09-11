const crypto = require('crypto');

// TEST-RULE: javascript.crypto.sm4.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=SM4, algorithmName=SM4, algorithmMode=cbc, algorithmParameterSetIdentifier=128, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function sm4Encrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('sm4-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.sm4.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=SM4, algorithmName=SM4, algorithmMode=ctr, algorithmParameterSetIdentifier=128, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function sm4Decrypt(key, iv, ciphertext) {
    const algorithm = 'sm4-ctr';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
