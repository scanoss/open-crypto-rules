const crypto = require('crypto');

// TEST-RULE: javascript.crypto.idea.cipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=IDEA, algorithmName=IDEA, algorithmMode=cbc, algorithmParameterSetIdentifier=128, operation=encrypt, library=node:crypto, api=crypto.Cipheriv.update
function ideaEncrypt(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('idea-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Algorithm held in a variable: taint tracking resolves the literal.
// TEST-RULE: javascript.crypto.idea.decipheriv-update
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=IDEA, algorithmName=IDEA, algorithmMode=cfb, algorithmParameterSetIdentifier=128, operation=decrypt, library=node:crypto, api=crypto.Decipheriv.update
function ideaDecrypt(key, iv, ciphertext) {
    const algorithm = 'idea-cfb';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
