// TEST-RULE: c.openssl.aes-key-setup-direct
// TEST-METADATA: primitive=block-cipher, algorithmName=AES, parameterSetIdentifier=256, library=OpenSSL, api=AES_set_encrypt_key

#include <openssl/aes.h>

int main() {
    AES_KEY aes_key;
    unsigned char key[32];  // 256-bit key

    // This should trigger the AES key setup direct rule with 256-bit key
    AES_set_encrypt_key(key, 256, &aes_key);

    return 0;
}
