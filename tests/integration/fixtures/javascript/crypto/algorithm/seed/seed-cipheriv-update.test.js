const crypto = require('crypto');

// TEST-RULE: javascript.crypto.seed.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=SEED, algorithmName=SEED, algorithmMode=cbc, algorithmParameterSetIdentifier=128, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function seedEncrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('seed-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.seed.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=SEED, algorithmName=SEED, algorithmMode=ecb, algorithmParameterSetIdentifier=128, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function seedDecrypt(key, iv, ciphertext) {
    const algorithm = 'seed-ecb';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
