// TEST-RULE: c.crypto.nss.algorithm-block-cipher-encryption
// TEST-METADATA: algorithmName=AES, library=NSS, algorithmPrimitive=block-cipher, api=PK11_CreateContextBySymKey
// TODO algorithmParameterSetIdentifier=xx
ctx = PK11_CreateContextBySymKey(CKM_AES_CBC, operation, key, secParam);