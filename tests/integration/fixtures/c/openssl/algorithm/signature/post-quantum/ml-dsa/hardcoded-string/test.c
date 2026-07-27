// TEST-RULE: c.openssl.algorithm.signature.ml-dsa
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=signature, algorithmFamily=ML-DSA, library=OpenSSL

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>

int test_mldsa_ctx_new() {
    // Test 1: EVP_PKEY_CTX_new_from_name with ML-DSA-65
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (ctx == NULL) {
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int test_mldsa_q_keygen() {
    // Test 2: EVP_PKEY_Q_keygen convenience function with ML-DSA-44
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44");
    if (pkey == NULL) {
        return -1;
    }
    EVP_PKEY_free(pkey);
    return 0;
}

int test_mldsa_signature_fetch() {
    // Test 3: EVP_SIGNATURE_fetch with ML-DSA-87
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(NULL, "ML-DSA-87", NULL);
    if (sig == NULL) {
        return -1;
    }
    EVP_SIGNATURE_free(sig);
    return 0;
}

int test_mldsa_oid_form() {
    // Test 4: OID form id-ml-dsa-65
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "id-ml-dsa-65", NULL);
    if (ctx == NULL) {
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
