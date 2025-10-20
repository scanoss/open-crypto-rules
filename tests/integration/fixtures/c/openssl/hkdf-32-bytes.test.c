// TEST-RULE: c.openssl.hkdf-key-derivation
// TEST-METADATA: primitive=kdf, algorithmName=HKDF, library=OpenSSL, api=HKDF

#include <openssl/kdf.h>
#include <openssl/evp.h>

int main() {
    unsigned char out_key[32];  // 32 bytes output
    unsigned char salt[16];
    unsigned char ikm[32];  // Input keying material
    unsigned char info[10];

    // This should trigger the HKDF key derivation rule with 32-byte output
    HKDF(out_key, 32,
         EVP_sha256(),
         salt, sizeof(salt),
         ikm, sizeof(ikm),
         info, sizeof(info));

    return 0;
}
