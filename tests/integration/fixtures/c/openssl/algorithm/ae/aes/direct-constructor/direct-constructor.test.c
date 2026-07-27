// TEST-RULE: c.openssl.algorithm.ae.aes.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=AES, algorithmName=AES-128-gcm, library=OpenSSL, api=EVP_aes_128_gcm

#include <openssl/evp.h>

void test_aes_128_gcm_constructor(void) {
    const EVP_CIPHER *cipher = EVP_aes_128_gcm();
    (void)cipher;
}

// TEST-RULE: c.openssl.algorithm.ae.aes.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=ae, algorithmFamily=AES, algorithmName=AES-256-ccm, library=OpenSSL, api=EVP_aes_256_ccm

void test_aes_256_ccm_constructor(void) {
    const EVP_CIPHER *cipher = EVP_aes_256_ccm();
    (void)cipher;
}
