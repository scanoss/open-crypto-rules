// TEST-RULE: c.openssl.algorithm.signature.rsa-pss.saltlen
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSASSA-PSS, algorithmName=RSA-PSS, library=OpenSSL, api=EVP_PKEY_CTX_set_rsa_pss_saltlen

#include <openssl/evp.h>
#include <openssl/rsa.h>

int test_rsa_pss_saltlen(EVP_PKEY_CTX *ctx) {
    return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1);
}
