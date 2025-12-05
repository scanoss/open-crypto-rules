// TEST-RULE: c.crypto.nss.algorithm-pke-encrypt
// TEST-METADATA: algorithmName=RSA, library=NSS, algorithmPrimitive=pke, api=PK11_Encrypt
r = PK11_Encrypt(privKey, CKM_RSA_PKCS, &param, data_to_encrypt, data_length);
