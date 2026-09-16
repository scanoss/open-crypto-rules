// ESM counterpart to rsa-pke.test.js. The import gate reaches require() and the
// three ESM spellings through separate branches - $MOD binds quoted under
// require and bare under import - so the ESM branches need their own fixture.
// The six positive cases are split across the two files, one per rule.
import nodeCrypto from 'node:crypto';
import * as crypto from 'crypto';
import { publicEncrypt, constants } from 'node:crypto';
import forge from 'node-forge';

// Default import under a node: specifier, receiver bound to the imported alias.
// TEST-RULE: javascript.crypto.rsa.public-decrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, algorithmName=RSA, operation=decrypt, library=node:crypto, api=crypto.publicDecrypt
export function decryptWithPublicKey(publicKey, ciphertext) {
    return nodeCrypto.publicDecrypt(publicKey, ciphertext).toString('utf8');
}

// Namespace import. Explicit PKCS#1 v1.5 padding, which OAEP is not legal for
// here, so the base rule reports plain RSA and no -oaep rule reports alongside.
// TEST-RULE: javascript.crypto.rsa.private-encrypt
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, algorithmName=RSA, operation=encrypt, library=node:crypto, api=crypto.privateEncrypt
export function encryptWithPrivateKey(privateKey, plaintext) {
    return crypto.privateEncrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    }, Buffer.from(plaintext, 'utf8'));
}

// Named import, bare call: the spelling with no receiver to bind, so the import
// alone gates it. The padding constant is reached through the imported
// constants object rather than crypto.constants.
// TEST-RULE: javascript.crypto.rsa.public-encrypt-oaep
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=pke, algorithmFamily=RSA, algorithmName=RSA-OAEP, operation=encrypt, library=node:crypto, api=crypto.publicEncrypt
export function encryptToPublicKeyOaep(publicKey, plaintext) {
    return publicEncrypt({
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
    }, Buffer.from(plaintext, 'utf8'));
}

// Negative: a same-named method on another library's default import. The gate
// binds the receiver to an alias imported from node crypto, and node-forge does
// not satisfy that, so this does not report even though the file does import
// node crypto for the cases above.
export function encryptWithForge(publicKey, plaintext) {
    return forge.publicEncrypt(publicKey, plaintext);
}
