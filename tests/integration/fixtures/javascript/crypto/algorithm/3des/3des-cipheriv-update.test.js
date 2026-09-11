const crypto = require('crypto');

// TEST-RULE: javascript.crypto.3des.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=3DES, algorithmName=3DES, algorithmMode=cbc, algorithmParameterSetIdentifier=168, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function tripleDesEncrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.3des.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=3DES, algorithmName=3DES, algorithmMode=ofb, algorithmParameterSetIdentifier=168, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function tripleDesDecrypt(key, iv, ciphertext) {
    const algorithm = 'des-ede3-ofb';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
