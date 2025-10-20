// TEST-RULE: c.openssl.rc4-algorithm
// TEST-METADATA: primitive=stream-cipher, algorithmName=RC4, library=OpenSSL, api=EVP_rc4

#include <openssl/evp.h>

int main() {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[16];
    unsigned char plaintext[64];
    unsigned char ciphertext[64];
    int len;

    ctx = EVP_CIPHER_CTX_new();

    // This should trigger the RC4 stream cipher detection rule
    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
