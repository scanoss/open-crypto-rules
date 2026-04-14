// TEST-RULE: c.openssl.algorithm.hash.md4.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=MD4, algorithmName=MD4, algorithmParameterSetIdentifier=128, library=OpenSSL, api=EVP_md4

#include <openssl/evp.h>

const EVP_MD *test_md4_constructor(void) {
    return EVP_md4();
}
