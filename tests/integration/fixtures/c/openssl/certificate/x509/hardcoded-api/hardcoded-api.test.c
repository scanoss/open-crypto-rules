// TEST-RULE: c.openssl.certificate.x509
// TEST-METADATA: assetType=certificate, certificateFormat=X.509, library=OpenSSL

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

void test_x509_from_bio(BIO *bio) {
    X509 *cert = d2i_X509_bio(bio, NULL);
    EVP_PKEY *key = X509_get_pubkey(cert);
    (void)key;
}
