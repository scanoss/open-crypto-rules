// TEST-RULE: c.openssl.algorithm.hash.md4
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=MD4, algorithmName=MD4, library=OpenSSL, api=EVP_DigestInit

#include <openssl/evp.h>

void test_md4_digestinit(EVP_MD_CTX *ctx) {
    EVP_DigestInit(ctx, EVP_md4());
}
