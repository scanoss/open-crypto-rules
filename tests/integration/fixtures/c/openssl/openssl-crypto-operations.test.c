// TEST-METADATA: algorithmName=X25519, library=OpenSSL, algorithmFamily=ECDH

#include <openssl/evp.h>

void ecdh_x25519() {
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
    EVP_PKEY_keygen_init(pctx);
}

// TEST-METADATA: algorithmName=ED25519, library=OpenSSL, algorithmFamily=EdDSA

void ed25519_sign() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    EVP_PKEY_sign(ctx, NULL);
}

// TEST-METADATA: algorithmName=RSA-PKCS1, library=OpenSSL, algorithmPrimitive=pke

void rsa_encrypt() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_encrypt(ctx, NULL);
}

// TEST-METADATA: algorithmName=SHA256, library=OpenSSL, api=EVP_DigestInit_ex2

md = EVP_get_digestbyname("SHA256");
mdctx = EVP_MD_CTX_new();
EVP_DigestInit_ex2(mdctx, md, NULL);

// TEST-METADATA: algorithmName=SHA256, library=OpenSSL, api=EVP_Q_digest

EVP_Q_digest(libctx, "SHA256", NULL, buffer, buflen, md, &mdlen);

// TEST-METADATA: algorithmName=SHA256, library=OpenSSL, api=EVP_sha256

EVP_sha256();

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

// TEST-METADATA: algorithmName=SHA-3-256, library=OpenSSL, algorithmFamily=SHA-3, algorithmParameterSetIdentifier=256

void compute_sha3() {
    EVP_MD *md = EVP_get_digestbyname("SHA3-256");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
}

// TEST-METADATA: algorithmName=PBKDF2, library=OpenSSL, algorithmFamily=PBKDF2

void derive_key_pbkdf2() {
    unsigned char key[32];
    PBKDF2_HMAC("password", 8,
                (unsigned char*)"salt", 4,
                10000, EVP_sha256(), 32, key);
}

// TEST-METADATA: algorithmName=AES-128-cbc, library=OpenSSL, algorithmFamily=AES, algorithmParameterSetIdentifier=128, algorithmMode=cbc

void encrypt_aes_cbc() {
    EVP_aes_128_cbc();
}

// TEST-METADATA: algorithmName=AES-256-gcm, library=OpenSSL, algorithmFamily=AES

void encrypt_aes_gcm() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
}

// TEST-METADATA: algorithmName=des_ede3_cbc, algorithmFamily=DES, algorithmPrimitive=block-cipher, library=OpenSSL

void encrypt_3des() {
    EVP_des_ede3_cbc();
}
