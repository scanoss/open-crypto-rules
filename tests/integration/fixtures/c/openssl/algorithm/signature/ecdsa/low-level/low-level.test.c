// TEST-RULE: c.openssl.algorithm.signature.ecdsa.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, algorithmName=ECDSA, library=OpenSSL, api=ECDSA_SIG_new

#include <openssl/ecdsa.h>

void test_ecdsa_sig_new(void) {
    ECDSA_SIG *sig = ECDSA_SIG_new();
    (void)sig;
}

// TEST-RULE: c.openssl.algorithm.signature.ecdsa.low-level
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ECDSA, algorithmName=ECDSA, library=OpenSSL, api=d2i_ECDSA_SIG

void test_d2i_ecdsa_sig(const unsigned char *buf) {
    const unsigned char *p = buf;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, 64);
    (void)sig;
}
