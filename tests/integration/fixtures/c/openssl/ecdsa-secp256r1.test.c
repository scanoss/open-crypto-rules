// TEST-RULE: c.openssl.ec-curve-detection-nid
// TEST-METADATA: primitive=signature, algorithmName=ECDSA, parameterSetIdentifier=secp256r1, curve=secp256r1, library=OpenSSL, api=EC_GROUP_new_by_curve_name

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

int main() {
    EC_GROUP *group;
    EC_KEY *key;

    // This should trigger the elliptic curve detection rule with secp256r1 curve
    group = EC_GROUP_new_by_curve_name(NID_secp256r1);

    key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_KEY_generate_key(key);

    EC_KEY_free(key);
    EC_GROUP_free(group);

    return 0;
}
