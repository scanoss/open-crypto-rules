// TEST-RULE: c.openssl.evp-cipher-selection-with-keysize
// TEST-METADATA: primitive=block-cipher, algorithmName=camellia, parameterSetIdentifier=256, library=OpenSSL, api=EVP

#include <openssl/evp.h>

int main() {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];  // 256-bit key
    unsigned char iv[16];
    unsigned char plaintext[64];
    unsigned char ciphertext[128];
    int len;

    ctx = EVP_CIPHER_CTX_new();

    // This should trigger the EVP cipher selection rule with Camellia-256-CBC
    EVP_EncryptInit_ex(ctx, EVP_camellia_256_cbc(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
