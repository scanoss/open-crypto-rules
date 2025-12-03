// TEST-RULE: c.crypto.openssl.algorithm-digest-evp-SHA3-256
// TEST-METADATA: algorithmName=SHA-3-256, library=OpenSSL, algorithmFamily=SHA-3, algorithmParameterSetIdentifier=256
#include <openssl/evp.h>

void compute_sha3() {
    // Use pattern that matches the rule
    EVP_MD *md = EVP_get_digestbyname("SHA3-256");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
}
