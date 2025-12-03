// TEST-RULE: c.crypto.openssl.algorithm-digest-evp-MD5
// TEST-METADATA: algorithmName=MD5, library=OpenSSL, algorithmFamily=MD5, algorithmParameterSetIdentifier=128, algorithmPrimitive=hash
#include <openssl/evp.h>

void compute_md5() {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    EVP_DigestInit_ex(ctx, md, NULL);
}
