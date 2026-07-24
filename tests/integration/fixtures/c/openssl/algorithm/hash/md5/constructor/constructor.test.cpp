// TEST-RULE: c.openssl.algorithm.hash.md5.constructor
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=MD5, algorithmName=MD5, algorithmParameterSetIdentifier=128, library=OpenSSL, api=EVP_md5

#include <openssl/evp.h>

const EVP_MD *test_md5_constructor_cpp() {
    return EVP_md5();
}
