// TEST-RULE: c.openssl.rsa-key-generation-legacy
// TEST-METADATA: primitive=pke, algorithmName=RSA, parameterSetIdentifier=4096, library=OpenSSL, api=RSA_generate_key

#include <openssl/rsa.h>

int main() {
    RSA *rsa_key = NULL;
    BIGNUM *bne = BN_new();

    BN_set_word(bne, RSA_F4);

    rsa_key = RSA_new();

    // This should trigger the RSA key generation legacy rule with 4096-bit key
    RSA_generate_key_ex(rsa_key, 4096, bne, NULL);

    RSA_free(rsa_key);
    BN_free(bne);

    return 0;
}
