// TEST-RULE: c.openssl.algorithm.kem.hybrid-ml-kem
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=kem, algorithmFamily=ML-KEM, library=OpenSSL

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

int test_hybrid_mlkem_tls_group() {
    // Test 1: SSL_CTX_set1_groups_list with standalone X25519MLKEM768
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set1_groups_list(ssl_ctx, "X25519MLKEM768");
    SSL_CTX_free(ssl_ctx);
    return 0;
}

int test_hybrid_mlkem_secp256r1() {
    // Test 2: SSL_CTX_set1_groups_list with SecP256r1MLKEM768
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set1_groups_list(ssl_ctx, "SecP256r1MLKEM768");
    SSL_CTX_free(ssl_ctx);
    return 0;
}

int test_hybrid_mlkem_secp384r1() {
    // Test 3: SSL_CTX_set1_groups_list with SecP384r1MLKEM1024
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set1_groups_list(ssl_ctx, "SecP384r1MLKEM1024");
    SSL_CTX_free(ssl_ctx);
    return 0;
}

int test_hybrid_mlkem_colon_list() {
    // Test 4: SSL_CTX_set1_groups_list with colon-separated list
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set1_groups_list(ssl_ctx, "X25519MLKEM768:X25519");
    SSL_CTX_free(ssl_ctx);
    return 0;
}
