// TEST-RULE: c.openssl.protocol.ocsp
// TEST-METADATA: assetType=protocol, protocolType=other, protocolName=OCSP, library=OpenSSL, api=OCSP_basic_verify

#include <openssl/ocsp.h>
#include <openssl/x509.h>

int test_ocsp_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *store) {
    return OCSP_basic_verify(bs, certs, store, 0);
}
