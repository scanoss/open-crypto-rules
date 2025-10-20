// TEST-RULE: c.openssl.scrypt-key-derivation
// TEST-METADATA: primitive=kdf, algorithmName=scrypt, library=OpenSSL, api=EVP_PBE_scrypt

#include <openssl/evp.h>
#include <openssl/kdf.h>

int main() {
    const char *password = "mypassword";
    unsigned char salt[16];
    unsigned char derived_key[64];  // 64 bytes output
    uint64_t N = 16384;
    uint32_t r = 8;
    uint32_t p = 1;
    size_t maxmem = 32 * 1024 * 1024;

    // This should trigger the scrypt key derivation rule with 64-byte output
    EVP_PBE_scrypt(password, strlen(password),
                   salt, sizeof(salt),
                   N, r, p, maxmem,
                   derived_key, 64);

    return 0;
}
