// TEST-RULE: c.openssl.algorithm.hash.sha-2.digestinit
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-2, algorithmName=SHA-256, algorithmParameterSetIdentifier=256, library=OpenSSL, api=EVP_DigestInit

#include <openssl/evp.h>

void test_sha256_digestinit(EVP_MD_CTX *ctx) {
    EVP_DigestInit(ctx, EVP_sha256());
}
