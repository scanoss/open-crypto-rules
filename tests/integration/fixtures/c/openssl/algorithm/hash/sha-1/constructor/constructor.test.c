// TEST-RULE: c.openssl.algorithm.hash.sha-1.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-1, algorithmName=SHA-1, algorithmParameterSetIdentifier=160, library=OpenSSL, api=EVP_sha1

#include <openssl/evp.h>

const EVP_MD *test_sha1_constructor(void) {
    return EVP_sha1();
}
