// TEST-RULE: c.crypto.nss.algorithm-digest
// TEST-METADATA: algorithmName=SHA256, library=NSS, algorithmPrimitive=hash, api=PK11_CreateDigestContext
hash_context = PK11_CreateDigestContext(SEC_OID_SHA256);
