// TEST-RULE: c.crypto.nss.algorithm-pke-rsa-keygeneration
// TEST-METADATA: algorithmName=RSA, library=NSS, algorithmPrimitive=pke, api=PK11_GenerateKeyPair
// TODO: parameterSetIdentifier=1024
PK11RSAGenParams rsaParams;
rsaParams.keySizeInBits = 1024;
rsaParams.pe = 65537;
prvKey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, &rsaParams,
            &pubKey, PR_TRUE, PR_TRUE, 0);