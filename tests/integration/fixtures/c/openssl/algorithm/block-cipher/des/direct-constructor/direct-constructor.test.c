// TEST-RULE: c.openssl.algorithm.block-cipher.3des.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=3DES, algorithmName=des_ede3_cbc, library=OpenSSL, api=EVP_des_ede3_cbc

#include <openssl/evp.h>

void test_des_ede3_cbc_constructor(void) {
    const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
    (void)cipher;
}
