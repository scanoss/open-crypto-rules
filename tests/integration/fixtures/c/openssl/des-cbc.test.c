// TEST-RULE: c.openssl.des-algorithms
// TEST-METADATA: primitive=block-cipher, algorithmName=des_cbc, library=OpenSSL, api=EVP

#include <openssl/evp.h>

int main() {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[8];
    unsigned char iv[8];
    unsigned char plaintext[64];
    unsigned char ciphertext[128];
    int len;

    ctx = EVP_CIPHER_CTX_new();

    // This should trigger the DES algorithm detection rule with CBC mode
    EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
