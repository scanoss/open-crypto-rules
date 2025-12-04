// TEST-RULE: c.crypto.nss.algorithm-pke-sign
// TEST-METADATA: algorithmName=RSA, library=NSS, algorithmPrimitive=pke, api=PK11_Sign
s = PK11_Sign(privKey, CKM_RSA_PKCS, NULL, &signature_item, &hash_item);
