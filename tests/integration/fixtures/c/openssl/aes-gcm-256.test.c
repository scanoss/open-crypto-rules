// TEST-RULE: c.openssl.aes-authenticated-encryption-evp
// TEST-METADATA: primitive=ae, algorithmName=AES, parameterSetIdentifier=256, mode=gcm, library=OpenSSL, api=EVP

#include <openssl/evp.h>

int main() {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char plaintext[64];
    unsigned char ciphertext[128];
    int len;

    ctx = EVP_CIPHER_CTX_new();

    // This should trigger the AES authenticated encryption rule with GCM mode
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
