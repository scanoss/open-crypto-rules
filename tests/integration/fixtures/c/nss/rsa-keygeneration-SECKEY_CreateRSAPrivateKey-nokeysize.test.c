// TEST-RULE: c.crypto.nss.algorithm-pke-rsa-keygeneration
// TEST-METADATA: algorithmName=RSA, library=NSS, api=SECKEY_CreateRSAPrivateKey
SECKEY_CreateRSAPrivateKey(untracked, pubk, cx);
