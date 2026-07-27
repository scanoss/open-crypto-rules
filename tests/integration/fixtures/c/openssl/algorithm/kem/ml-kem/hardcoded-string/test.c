// TEST-RULE: c.openssl.algorithm.kem.ml-kem
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=kem, algorithmFamily=ML-KEM, library=OpenSSL

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <string.h>

int test_mlkem_ctx_new() {
    // Test 1: EVP_PKEY_CTX_new_from_name with ML-KEM-768
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (ctx == NULL) {
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int test_mlkem_q_keygen() {
    // Test 2: EVP_PKEY_Q_keygen convenience function with ML-KEM-512
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-512");
    if (pkey == NULL) {
        return -1;
    }
    EVP_PKEY_free(pkey);
    return 0;
}

int test_mlkem_encapsulate() {
    // Test 3: Full encapsulate flow with ML-KEM-1024
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    EVP_PKEY *pkey = NULL;

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);

    EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    unsigned char wrapped[1568];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char secret[32];
    size_t secret_len = sizeof(secret);

    EVP_PKEY_encapsulate_init(enc_ctx, NULL);
    EVP_PKEY_encapsulate(enc_ctx, wrapped, &wrapped_len, secret, &secret_len);

    EVP_PKEY_CTX_free(enc_ctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}

int test_mlkem_oid_form() {
    // Test 4: OID form id-alg-ml-kem-768
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "id-alg-ml-kem-768", NULL);
    if (ctx == NULL) {
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
