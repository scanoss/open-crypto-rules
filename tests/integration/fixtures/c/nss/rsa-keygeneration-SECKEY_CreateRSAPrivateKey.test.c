// TEST-RULE: c.crypto.nss.algorithm-pke-rsa-keygeneration
// TEST-METADATA: algorithmName=RSA, library=NSS, api=SECKEY_CreateRSAPrivateKey, algorithmParameterSetIdentifier=1024
SECKEY_CreateRSAPrivateKey(1024, pubk, cx);
