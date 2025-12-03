// TEST-RULE: c.crypto.openssl.algorithm-pke-evp-rsaEncryption-encrypt
// TEST-METADATA: algorithmName=RSA-PKCS1, library=OpenSSL, algorithmPrimitive=pke
#include <openssl/evp.h>

void rsa_encrypt() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_encrypt(ctx, NULL);
}
