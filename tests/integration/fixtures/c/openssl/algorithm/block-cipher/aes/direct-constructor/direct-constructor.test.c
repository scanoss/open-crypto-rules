// TEST-RULE: c.openssl.algorithm.block-cipher.aes.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=AES, algorithmName=AES-128-cbc, library=OpenSSL, api=EVP_aes_128_cbc

#include <openssl/evp.h>

void test_aes_128_cbc_constructor(void) {
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    (void)cipher;
}

// TEST-RULE: c.openssl.algorithm.block-cipher.aes.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=AES, algorithmName=AES-256-ctr, library=OpenSSL, api=EVP_aes_256_ctr

void test_aes_256_ctr_constructor(void) {
    const EVP_CIPHER *cipher = EVP_aes_256_ctr();
    (void)cipher;
}
