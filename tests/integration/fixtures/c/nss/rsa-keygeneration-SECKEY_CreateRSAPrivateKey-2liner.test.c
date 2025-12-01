// TEST-RULE: c.crypto.nss.algorithm-pke-rsa-keygeneration
// TEST-METADATA: algorithmName=RSA, library=NSS, api=SECKEY_CreateRSAPrivateKey
// TODO get parameterSetIdentifier=1024
keySizeInBits = 1024;
SECKEY_CreateRSAPrivateKey(keySizeInBits, pubk, cx);
