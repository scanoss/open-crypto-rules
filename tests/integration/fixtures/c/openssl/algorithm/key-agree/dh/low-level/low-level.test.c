// TEST-RULE: c.openssl.algorithm.key-agree.dh.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=FFDH, algorithmName=DH, library=OpenSSL, api=DH_generate_key

#include <openssl/dh.h>

void test_dh_generate_key(DH *dh) {
    DH_generate_key(dh);
}

// TEST-RULE: c.openssl.algorithm.key-agree.dh.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=FFDH, algorithmName=DH, library=OpenSSL, api=DH_compute_key

int test_dh_compute_key(unsigned char *secret, const BIGNUM *pub, DH *dh) {
    return DH_compute_key(secret, pub, dh);
}
