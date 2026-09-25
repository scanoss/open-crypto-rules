import { generateKeyPairSync, diffieHellman } from 'node:crypto';

// ESM named imports, bare calls at both ends: the import list gates the sink,
// there being no receiver to bind. The keypair is destructured out of the
// generator and passed on as shorthand properties.
// TEST-RULE: javascript.crypto.x448.diffie-hellman
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=X448, library=node:crypto, api=crypto.diffieHellman
export function deriveX448Secret(theirPublicKey) {
    const { privateKey } = generateKeyPairSync('x448');
    return diffieHellman({ privateKey, publicKey: theirPublicKey });
}
