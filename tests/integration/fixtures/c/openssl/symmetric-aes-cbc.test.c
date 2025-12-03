// TEST-RULE: c.openssl.aes-block-cipher-evp
// TEST-METADATA: algorithmName=AES-128-cbc, library=OpenSSL, algorithmFamily=AES, algorithmParameterSetIdentifier=128, algorithmMode=cbc
#include <openssl/evp.h>

void encrypt_aes_cbc() {
    // Pattern must match EVP_$AES_FUNC() where $AES_FUNC = aes_128_cbc
    EVP_aes_128_cbc();
}
