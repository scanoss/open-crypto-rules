// TEST-METADATA: algorithmName=SHA256, library=OpenSSL, algorithmFamily=SHA-2, algorithmPrimitive=hash, api=EVP_get_digestbyname

md = EVP_get_digestbyname("SHA256");
mdctx = EVP_MD_CTX_new();
EVP_DigestInit_ex2(mdctx, md, NULL);

// TEST-METADATA: algorithmName=MD5, library=OpenSSL, algorithmFamily=MD5, algorithmParameterSetIdentifier=128, algorithmPrimitive=hash

void compute_md5() {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    EVP_DigestInit_ex(ctx, md, NULL);
}

// TEST-METADATA: algorithmName=SHA-1, library=OpenSSL, algorithmFamily=SHA-1

void compute_sha1() {
    const EVP_MD *md = EVP_sha1();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
}

// TEST-METADATA: algorithmName=SHA3-256, library=OpenSSL, algorithmFamily=SHA-3, algorithmPrimitive=hash, api=EVP_get_digestbyname

void compute_sha3() {
    EVP_MD *md = EVP_get_digestbyname("SHA3-256");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
}

// TEST-METADATA: algorithmName=AES-256-gcm, library=OpenSSL, algorithmFamily=AES

void encrypt_aes_gcm() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
}
