// TEST-RULE: c.openssl.algorithm.hash.sha-2.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=SHA-2, algorithmName=SHA-256, algorithmParameterSetIdentifier=256, library=OpenSSL, api=EVP_sha256

#include <openssl/evp.h>

const EVP_MD *test_sha256_constructor(void) {
    return EVP_sha256();
}
