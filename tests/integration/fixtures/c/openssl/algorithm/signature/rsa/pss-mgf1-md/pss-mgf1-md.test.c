// TEST-RULE: c.openssl.algorithm.signature.rsa-pss.mgf1-md
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=RSASSA-PSS, algorithmName=RSA-PSS, library=OpenSSL, api=EVP_PKEY_CTX_set_rsa_mgf1_md

#include <openssl/evp.h>
#include <openssl/rsa.h>

int test_rsa_pss_mgf1_md(EVP_PKEY_CTX *ctx) {
    return EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
}
