// TEST-RULE: c.openssl.algorithm.hash.md5
// TEST-METADATA: assetType=algorithm, algorithmPrimitive=hash, algorithmFamily=MD5, algorithmName=MD5, library=OpenSSL

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

int test_md5_hardcoded() {
    // Test 1: EVP_get_digestbyname with hardcoded string
    const EVP_MD *md = EVP_get_digestbyname("MD5");
    if (md == NULL) {
        return -1;
    }

    // Test 2: EVP_MD_fetch with hardcoded string
    EVP_MD *md2 = EVP_MD_fetch(NULL, "MD5", NULL);

    // Test 3: Direct function call
    const EVP_MD *md3 = EVP_md5();

    // Test 4: EVP_DigestInit_ex with fetched digest
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);

    const char *data = "test data";
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestUpdate(ctx, data, strlen(data));
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md2);

    return 0;
}
