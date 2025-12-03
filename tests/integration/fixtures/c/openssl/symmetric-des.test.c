// TEST-RULE: c.openssl.des-algorithms
// TEST-METADATA: algorithmName=des_ede3_cbc, algorithmFamily=DES, algorithmPrimitive=block-cipher, library=OpenSSL
#include <openssl/evp.h>

void encrypt_3des() {
    // Use legacy DES API pattern
    EVP_des_ede3_cbc();
}
