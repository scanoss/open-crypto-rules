// TEST-METADATA: assetType=algorithm, findingType=ae, algorithmName=AES-128-GCM, algorithmFamily=AES, library=openssl, algorithmPrimitive=ae, algorithmMode=GCM, algorithmParameterSetIdentifier=128
fn test_aes_128_gcm_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_128_gcm();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=ae, algorithmName=AES-192-GCM, algorithmFamily=AES, library=openssl, algorithmPrimitive=ae, algorithmMode=GCM, algorithmParameterSetIdentifier=192
fn test_aes_192_gcm_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_192_gcm();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=ae, algorithmName=AES-256-GCM, algorithmFamily=AES, library=openssl, algorithmPrimitive=ae, algorithmMode=GCM, algorithmParameterSetIdentifier=256
fn test_aes_256_gcm_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_256_gcm();
    _ = cipher;
}

// TEST-RULE: rust.openssl.aes-gcm.encrypt-aead
// TEST-METADATA: assetType=algorithm, findingType=ae, operation=encrypt, algorithmName=AES-GCM, algorithmFamily=AES, library=openssl, algorithmPrimitive=ae, algorithmMode=GCM
fn test_encrypt_aead() {
    use openssl::symm::{encrypt_aead, Cipher};
    let cipher = Cipher::aes_256_gcm();
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let aad = b"additional data";
    let data = b"plaintext";
    let mut tag = [0u8; 16];
    let _ = encrypt_aead(cipher, &key, Some(&iv), aad, data, &mut tag);
}

// TEST-RULE: rust.openssl.aes-gcm.decrypt-aead
// TEST-METADATA: assetType=algorithm, findingType=ae, operation=decrypt, algorithmName=AES-GCM, algorithmFamily=AES, library=openssl, algorithmPrimitive=ae, algorithmMode=GCM
fn test_decrypt_aead() {
    use openssl::symm::{decrypt_aead, Cipher};
    let cipher = Cipher::aes_256_gcm();
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let aad = b"additional data";
    let ciphertext = [0u8; 32];
    let tag = [0u8; 16];
    let _ = decrypt_aead(cipher, &key, Some(&iv), aad, &ciphertext, &tag);
}
