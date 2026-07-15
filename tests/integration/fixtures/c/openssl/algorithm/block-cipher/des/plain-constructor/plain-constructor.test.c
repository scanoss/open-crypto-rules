// TEST-RULE: c.openssl.algorithm.block-cipher.des.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=DES, algorithmName=des_cbc, library=OpenSSL, api=EVP_des_cbc

#include <openssl/evp.h>

void test_des_cbc_constructor(void) {
    const EVP_CIPHER *cipher = EVP_des_cbc();
    (void)cipher;
}
