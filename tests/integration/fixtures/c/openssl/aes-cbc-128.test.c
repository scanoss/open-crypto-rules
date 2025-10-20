// TEST-RULE: c.openssl.aes-block-cipher-evp
// TEST-METADATA: primitive=block-cipher, algorithmName=AES, parameterSetIdentifier=128, mode=cbc, library=OpenSSL, api=EVP

#include <openssl/evp.h>

int main() {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[16];  // 128-bit key
    unsigned char iv[16];
    unsigned char plaintext[64];
    unsigned char ciphertext[128];
    int len;

    ctx = EVP_CIPHER_CTX_new();

    // This should trigger the AES block cipher rule with CBC mode
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
