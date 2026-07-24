// TEST-RULE: c.openssl.algorithm.hash.md5
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=MD5, algorithmName=MD5, algorithmParameterSetIdentifier=128, library=OpenSSL, api=EVP_DigestInit

#include <openssl/evp.h>

void test_md5_digestinit(EVP_MD_CTX *ctx) {
    EVP_DigestInit(ctx, EVP_md5());
}
