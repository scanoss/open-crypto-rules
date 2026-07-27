// TEST-RULE: c.openssl.algorithm.signature.slh-dsa
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=SLH-DSA, library=OpenSSL

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>

int test_slhdsa_ctx_new() {
    // Test 1: EVP_PKEY_CTX_new_from_name with SLH-DSA-SHA2-128s
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "SLH-DSA-SHA2-128s", NULL);
    if (ctx == NULL) {
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int test_slhdsa_q_keygen() {
    // Test 2: EVP_PKEY_Q_keygen convenience function with SLH-DSA-SHAKE-256f
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "SLH-DSA-SHAKE-256f");
    if (pkey == NULL) {
        return -1;
    }
    EVP_PKEY_free(pkey);
    return 0;
}

int test_slhdsa_signature_fetch() {
    // Test 3: EVP_SIGNATURE_fetch with SLH-DSA-SHA2-256s
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "SLH-DSA-SHA2-256s", NULL);
    if (sig == NULL) {
        return -1;
    }
    EVP_SIGNATURE_free(sig);
    return 0;
}

int test_slhdsa_oid_form() {
    // Test 4: OID form id-slh-dsa-sha2-192f
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "id-slh-dsa-sha2-192f", NULL);
    if (ctx == NULL) {
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
