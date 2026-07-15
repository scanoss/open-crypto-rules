// TEST-RULE: c.openssl.algorithm.signature.rsa-pss.padding
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSASSA-PSS, algorithmName=RSA-PSS, library=OpenSSL, api=EVP_PKEY_CTX_set_rsa_padding

#include <openssl/evp.h>
#include <openssl/rsa.h>

int test_rsa_pss_padding(EVP_PKEY_CTX *ctx) {
    return EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
}
