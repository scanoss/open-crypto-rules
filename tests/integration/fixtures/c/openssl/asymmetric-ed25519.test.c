// TEST-RULE: c.crypto.openssl.algorithm-pke-evp-ED25519-sign
// TEST-METADATA: algorithmName=ED25519, library=OpenSSL, algorithmFamily=EdDSA
#include <openssl/evp.h>

void ed25519_sign() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    EVP_PKEY_sign(ctx, NULL);
}
