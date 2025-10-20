// TEST-RULE: c.openssl.evp-digest-selection
// TEST-METADATA: primitive=hash, algorithmName=sha512, library=OpenSSL, api=EVP

#include <openssl/evp.h>

int main() {
    EVP_MD_CTX *ctx;
    unsigned char message[64] = "Hello, World!";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    ctx = EVP_MD_CTX_new();

    // This should trigger the EVP digest selection rule with SHA-512
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);

    EVP_DigestUpdate(ctx, message, strlen((char *)message));
    EVP_DigestFinal_ex(ctx, digest, &digest_len);

    EVP_MD_CTX_free(ctx);

    return 0;
}
