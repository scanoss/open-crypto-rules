// TEST-RULE: c.openssl.algorithm.key-agree.ecdh.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, algorithmName=ECDH, library=OpenSSL, api=EC_KEY_new_by_curve_name

#include <openssl/ec.h>

void test_ec_key_new_by_curve_name(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    (void)key;
}

// TEST-RULE: c.openssl.algorithm.key-agree.ecdh.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, algorithmName=ECDH, library=OpenSSL, api=EC_KEY_generate_key

void test_ec_key_generate_key(EC_KEY *key) {
    EC_KEY_generate_key(key);
}

// TEST-RULE: c.openssl.algorithm.key-agree.ecdh.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=key-agree, algorithmFamily=ECDH, algorithmName=ECDH, library=OpenSSL, api=EC_POINT_mul

void test_ec_point_mul(const EC_GROUP *group, EC_POINT *r, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx) {
    EC_POINT_mul(group, r, NULL, q, m, ctx);
}
