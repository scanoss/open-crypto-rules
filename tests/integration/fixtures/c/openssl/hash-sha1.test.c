// TEST-RULE: c.crypto.openssl.algorithm-digest-evp-SHA1
// TEST-METADATA: algorithmName=SHA-1, library=OpenSSL, algorithmFamily=SHA-1
#include <openssl/evp.h>

void compute_sha1() {
    const EVP_MD *md = EVP_sha1();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
}
