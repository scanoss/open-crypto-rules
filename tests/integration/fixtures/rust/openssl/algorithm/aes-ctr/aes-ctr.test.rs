// TEST-METADATA: assetType=algorithm, findingType=cipher, algorithmName=AES-128-CTR, algorithmFamily=AES, library=openssl, algorithmPrimitive=block-cipher, algorithmMode=CTR, algorithmParameterSetIdentifier=128
fn test_aes_128_ctr_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_128_ctr();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=cipher, algorithmName=AES-192-CTR, algorithmFamily=AES, library=openssl, algorithmPrimitive=block-cipher, algorithmMode=CTR, algorithmParameterSetIdentifier=192
fn test_aes_192_ctr_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_192_ctr();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=cipher, algorithmName=AES-256-CTR, algorithmFamily=AES, library=openssl, algorithmPrimitive=block-cipher, algorithmMode=CTR, algorithmParameterSetIdentifier=256
fn test_aes_256_ctr_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_256_ctr();
    _ = cipher;
}

// TEST-RULE: rust.openssl.symm.encrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=encrypt, algorithmFamily=AES, library=openssl, algorithmPrimitive=block-cipher
fn test_symm_encrypt() {
    use openssl::symm::{encrypt, Cipher};
    let cipher = Cipher::aes_256_ctr();
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let data = b"plaintext";
    let _ = encrypt(cipher, &key, Some(&iv), data);
}

// TEST-RULE: rust.openssl.symm.decrypt
// TEST-METADATA: assetType=algorithm, findingType=cipher, operation=decrypt, algorithmFamily=AES, library=openssl, algorithmPrimitive=block-cipher
fn test_symm_decrypt() {
    use openssl::symm::{decrypt, Cipher};
    let cipher = Cipher::aes_256_ctr();
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let ciphertext = [0u8; 32];
    let _ = decrypt(cipher, &key, Some(&iv), &ciphertext);
}

// TEST-RULE: rust.openssl.symm.crypter-new
// TEST-METADATA: assetType=algorithm, findingType=cipher, algorithmFamily=AES, library=openssl, algorithmPrimitive=block-cipher
fn test_crypter_new() {
    use openssl::symm::{Cipher, Crypter, Mode};
    let cipher = Cipher::aes_256_ctr();
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv));
    _ = crypter;
}
