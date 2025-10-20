// TEST-RULE: c.openssl.pbkdf2-key-derivation
// TEST-METADATA: primitive=kdf, algorithmName=PBKDF2, library=OpenSSL, api=PBKDF2_HMAC

#include <openssl/evp.h>

int main() {
    const char *password = "mypassword";
    unsigned char salt[16];
    unsigned char derived_key[32];  // 32 bytes output
    int iterations = 100000;

    // This should trigger the PBKDF2 key derivation rule with 32-byte output
    PBKDF2_HMAC(password, strlen(password),
                salt, sizeof(salt),
                iterations,
                EVP_sha256(),
                32,  // Key length in bytes
                derived_key);

    return 0;
}
