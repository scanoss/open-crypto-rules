// TEST-RULE: c.openssl.aes-authenticated-encryption-evp
// TEST-METADATA: algorithmName=AES-256-gcm, library=OpenSSL, algorithmFamily=AES
#include <openssl/evp.h>

void encrypt_aes_gcm() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
}
