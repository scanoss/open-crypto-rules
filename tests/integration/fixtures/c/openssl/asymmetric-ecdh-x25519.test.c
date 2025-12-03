// TEST-RULE: c.crypto.openssl.algorithm-pke-evp-X25519-usage
// TEST-METADATA: algorithmName=X25519, library=OpenSSL, algorithmFamily=ECDH
#include <openssl/evp.h>

void ecdh_x25519() {
    EVP_PKEY_CTX *pctx;
    // Use pattern that matches the rule
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
    EVP_PKEY_keygen_init(pctx);
}
