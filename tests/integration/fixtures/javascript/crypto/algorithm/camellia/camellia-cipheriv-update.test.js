const crypto = require('crypto');

// TEST-RULE: javascript.crypto.camellia.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=Camellia, algorithmName=Camellia, algorithmMode=cbc, algorithmParameterSetIdentifier=256, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function camelliaEncrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('camellia-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.camellia.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=Camellia, algorithmName=Camellia, algorithmMode=ofb, algorithmParameterSetIdentifier=128, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function camelliaDecrypt(key, iv, ciphertext) {
    const algorithm = 'camellia-128-ofb';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
