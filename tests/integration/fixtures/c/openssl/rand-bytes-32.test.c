// TEST-RULE: c.openssl.random-generation-crypto-sizes
// TEST-METADATA: primitive=drbg, algorithmName=OpenSSL-RAND, library=OpenSSL, api=RAND_bytes

#include <openssl/rand.h>

int main() {
    unsigned char buffer[32];  // 32 bytes of random data

    // This should trigger the random generation rule with 32 bytes
    RAND_bytes(buffer, 32);

    return 0;
}
