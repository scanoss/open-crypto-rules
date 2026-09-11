const crypto = require('crypto');

// TEST-RULE: javascript.crypto.des.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=DES, algorithmName=DES, algorithmMode=cbc, algorithmParameterSetIdentifier=56, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function desEncrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('des-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.des.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=DES, algorithmName=DES, algorithmMode=ecb, algorithmParameterSetIdentifier=56, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function desDecrypt(key, iv, ciphertext) {
    const algorithm = 'des-ecb';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
