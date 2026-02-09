// TEST-METADATA: algorithmName=SHA256, library=NSS, algorithmPrimitive=hash, algorithmFamily=SHA-2, api=PK11_CreateDigestContext

hash_context = PK11_CreateDigestContext(SEC_OID_SHA256);

// TEST-METADATA: algorithmName=RSA, library=NSS, algorithmPrimitive=pke, algorithmFamily=RSAES-PKCS1, api=PK11_GenerateKeyPair

PK11RSAGenParams rsaParams;
rsaParams.keySizeInBits = 1024;
rsaParams.pe = 65537;
prvKey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, &rsaParams,
            &pubKey, PR_TRUE, PR_TRUE, 0);
