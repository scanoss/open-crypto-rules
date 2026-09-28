import { createPrivateKey, diffieHellman } from 'node:crypto';

// ESM named imports, bare calls at both ends: the import list gates the sink,
// there being no receiver to bind. The private half is imported from a raw
// seed rather than generated, so the key type reaches the rule through the
// asymmetricKeyType option instead of a generator argument - the sibling ecdh
// and x25519 fixtures take the generator form. format is not read; the option
// is, and Node requires it for the raw formats.
// TEST-RULE: javascript.crypto.x448.diffie-hellman
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=X448, library=node:crypto, api=crypto.diffieHellman
export function deriveX448Secret(seed, theirPublicKey) {
    const privateKey = createPrivateKey({ key: seed, format: 'raw-seed', asymmetricKeyType: 'x448' });
    return diffieHellman({ privateKey, publicKey: theirPublicKey });
}
