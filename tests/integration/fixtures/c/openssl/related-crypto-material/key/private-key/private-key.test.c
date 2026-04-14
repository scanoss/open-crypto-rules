// TEST-RULE: c.openssl.related-crypto-material.private-key.pem
// TEST-METADATA: assetType=related-crypto-material, materialType=private-key, materialFormat=PEM, library=OpenSSL

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>

EVP_PKEY *test_pem_private_key(FILE *fp) {
    return PEM_read_PrivateKey(fp, NULL, NULL, NULL);
}
