// TEST-RULE: c.openssl.rsa-key-generation-evp
// TEST-METADATA: primitive=pke, algorithmName=RSA, parameterSetIdentifier=2048, library=OpenSSL, api=EVP_PKEY_CTX_set_rsa_keygen_bits

#include <openssl/evp.h>
#include <openssl/rsa.h>

int main() {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);

    // This should trigger the RSA key generation rule with 2048-bit key
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

    EVP_PKEY_keygen(ctx, &pkey);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return 0;
}
