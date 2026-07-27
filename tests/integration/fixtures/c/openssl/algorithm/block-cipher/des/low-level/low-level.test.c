// TEST-RULE: c.openssl.algorithm.block-cipher.des.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=DES, algorithmName=DES, library=OpenSSL, api=DES_set_odd_parity

#include <openssl/des.h>

void test_des_set_odd_parity(DES_cblock *block) {
    DES_set_odd_parity(block);
}

// TEST-RULE: c.openssl.algorithm.block-cipher.des.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=DES, algorithmName=DES, library=OpenSSL, api=DES_set_key

void test_des_set_key(DES_cblock *block, DES_key_schedule *schedule) {
    DES_set_key(block, schedule);
}

// TEST-RULE: c.openssl.algorithm.block-cipher.des.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=block-cipher, algorithmFamily=DES, algorithmName=DES, library=OpenSSL, api=DES_ecb_encrypt

void test_des_ecb_encrypt(DES_cblock *in, DES_cblock *out, DES_key_schedule *schedule) {
    DES_ecb_encrypt(in, out, schedule, DES_ENCRYPT);
}
