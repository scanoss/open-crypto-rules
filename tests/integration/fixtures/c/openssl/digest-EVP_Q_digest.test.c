// TEST-RULE: c.crypto.openssl.algorithm-digest-evp-SHA256
// TEST-METADATA: algorithmName=SHA256, library=OpenSSL, api=EVP_Q_digest
EVP_Q_digest(libctx, "SHA256", NULL, buffer, buflen, md, &mdlen);
