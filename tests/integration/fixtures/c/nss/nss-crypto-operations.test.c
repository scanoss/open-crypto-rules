// TEST-METADATA: algorithmName=AES, library=NSS, algorithmPrimitive=block-cipher, api=PK11_CreateContextBySymKey

ctx = PK11_CreateContextBySymKey(CKM_AES_CBC, operation, key, secParam);

// TEST-METADATA: algorithmName=AES, library=NSS, algorithmPrimitive=block-cipher, api=PK11_TokenKeyGen

key = PK11_TokenKeyGen(slot, CKM_AES_KEY_GEN, NULL, 1024, keyid, PR_TURE, pwdata);

// TEST-METADATA: algorithmName=SHA256, library=NSS, algorithmPrimitive=hash, api=PK11_CreateDigestContext

hash_context = PK11_CreateDigestContext(SEC_OID_SHA256);

// TEST-METADATA: algorithmName=RSA, library=NSS, algorithmPrimitive=pke, api=PK11_Encrypt

r = PK11_Encrypt(privKey, CKM_RSA_PKCS, &param, data_to_encrypt, data_length);

// TEST-METADATA: algorithmName=RSA, library=NSS, algorithmPrimitive=pke, api=PK11_GenerateKeyPair

PK11RSAGenParams rsaParams;
rsaParams.keySizeInBits = 1024;
rsaParams.pe = 65537;
prvKey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, &rsaParams,
            &pubKey, PR_TRUE, PR_TRUE, 0);

// TEST-METADATA: algorithmName=RSA, library=NSS, algorithmPrimitive=pke, api=PK11_Sign

s = PK11_Sign(privKey, CKM_RSA_PKCS, NULL, &signature_item, &hash_item);

// TEST-METADATA: algorithmName=RSA, library=NSS, api=SECKEY_CreateRSAPrivateKey

keySizeInBits = 1024;
SECKEY_CreateRSAPrivateKey(keySizeInBits, pubk, cx);

// TEST-METADATA: algorithmName=RSA, library=NSS, api=SECKEY_CreateRSAPrivateKey

SECKEY_CreateRSAPrivateKey(untracked, pubk, cx);

// TEST-METADATA: algorithmName=RSA, library=NSS, algorithmPrimitive=pke, api=SECKEY_CreateRSAPrivateKey, algorithmParameterSetIdentifier=1024

SECKEY_CreateRSAPrivateKey(1024, pubk, cx);
