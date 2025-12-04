// TEST-RULE: c.crypto.nss.algorithm-block-cipher-keygeneration
// TEST-METADATA: algorithmName=AES, library=NSS, algorithmPrimitive=block-cipher, api=PK11_TokenKeyGen
// TODO algorithmParameterSetIdentifier=xx
key = PK11_TokenKeyGen(slot, CKM_AES_KEY_GEN, NULL, 1024, keyid, PR_TURE, pwdata);
