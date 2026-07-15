// TEST-RULE: c.openssl.algorithm.hash.sha-1
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-1, algorithmName=SHA-1, algorithmParameterSetIdentifier=160, library=OpenSSL, api=EVP_DigestInit

#include <openssl/evp.h>

void test_sha1_digestinit(EVP_MD_CTX *ctx) {
    EVP_DigestInit(ctx, EVP_sha1());
}
