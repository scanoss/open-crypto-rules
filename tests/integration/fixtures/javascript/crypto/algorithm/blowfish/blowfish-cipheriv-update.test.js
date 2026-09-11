const crypto = require('crypto');

// TEST-RULE: javascript.crypto.blowfish.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=Blowfish, algorithmName=Blowfish, algorithmMode=cbc, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function blowfishEncrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('bf-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.blowfish.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=Blowfish, algorithmName=Blowfish, algorithmMode=ofb, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function blowfishDecrypt(key, iv, ciphertext) {
    const algorithm = 'bf-ofb';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
