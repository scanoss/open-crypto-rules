// TEST-RULE: c.openssl.pbkdf2-key-derivation
// TEST-METADATA: algorithmName=PBKDF2, library=OpenSSL, algorithmFamily=PBKDF2
#include <openssl/evp.h>

void derive_key_pbkdf2() {
    unsigned char key[32];
    PBKDF2_HMAC("password", 8,
                (unsigned char*)"salt", 4,
                10000, EVP_sha256(), 32, key);
}
