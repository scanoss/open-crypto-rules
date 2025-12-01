// TEST-RULE: c.crypto.openssl.algorithm-digest-evp-SHA256
// TEST-METADATA: algorithmName=SHA256, library=OpenSSL, api=EVP_DigestInit_ex2
md = EVP_get_digestbyname("SHA256");
mdctx = EVP_MD_CTX_new();
EVP_DigestInit_ex2(mdctx, md, NULL);
