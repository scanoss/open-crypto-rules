#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>

EVP_PKEY *generate_key(OSSL_LIB_CTX *lctx, char *private_key_filename, char *public_key_filename) {
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_ENCODER_CTX *ectx = NULL;
	FILE *keyfile;
	char *name = "RSA";

	pkey = EVP_PKEY_new();
	pctx = EVP_PKEY_CTX_new_from_name(lctx, name, NULL);
	if (EVP_PKEY_keygen_init(pctx) <= 0) {
		fprintf(stderr, "Error in `%s` key initialization\n", name);
		return NULL;
	}
}
