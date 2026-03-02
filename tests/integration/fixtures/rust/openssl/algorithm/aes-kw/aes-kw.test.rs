// TEST-RULE: rust.openssl.aes-kw.wrap-key
// TEST-METADATA: assetType=algorithm, findingType=kw, operation=encrypt, algorithmName=AES-Wrap, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap
fn test_wrap_key() {
    use openssl::aes::{wrap_key, AesKey};
    let key_data = [0u8; 32];
    let wrapping_key = AesKey::new_encrypt(&key_data).unwrap();
    let key_to_wrap = [0u8; 32];
    let mut wrapped = [0u8; 40];
    let _ = wrap_key(&wrapping_key, None, &mut wrapped, &key_to_wrap);
}

// TEST-RULE: rust.openssl.aes-kw.unwrap-key
// TEST-METADATA: assetType=algorithm, findingType=kw, operation=decrypt, algorithmName=AES-Wrap, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap
fn test_unwrap_key() {
    use openssl::aes::{unwrap_key, AesKey};
    let key_data = [0u8; 32];
    let unwrapping_key = AesKey::new_decrypt(&key_data).unwrap();
    let wrapped = [0u8; 40];
    let mut unwrapped = [0u8; 32];
    let _ = unwrap_key(&unwrapping_key, None, &mut unwrapped, &wrapped);
}

// TEST-RULE: rust.openssl.aes-kw.aeskey-encrypt
// TEST-METADATA: assetType=algorithm, findingType=kw, operation=keygen, algorithmName=AES, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap
fn test_aeskey_new_encrypt() {
    use openssl::aes::AesKey;
    let key_data = [0u8; 32];
    let aes_key = AesKey::new_encrypt(&key_data);
    _ = aes_key;
}

// TEST-RULE: rust.openssl.aes-kw.aeskey-decrypt
// TEST-METADATA: assetType=algorithm, findingType=kw, operation=keygen, algorithmName=AES, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap
fn test_aeskey_new_decrypt() {
    use openssl::aes::AesKey;
    let key_data = [0u8; 32];
    let aes_key = AesKey::new_decrypt(&key_data);
    _ = aes_key;
}

// TEST-RULE:
// TEST-METADATA: assetType=algorithm, findingType=kw, operation=instantiate, algorithmName=AES-128-Wrap, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap, algorithmParameterSetIdentifier=128
fn test_aes_128_wrap_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_128_wrap();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=kw, operation=instantiate, algorithmName=AES-192-Wrap, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap, algorithmParameterSetIdentifier=192
fn test_aes_192_wrap_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_192_wrap();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=kw, operation=instantiate, algorithmName=AES-256-Wrap, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap, algorithmParameterSetIdentifier=256
fn test_aes_256_wrap_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_256_wrap();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=kw, operation=instantiate, algorithmName=AES-128-Wrap-KWP, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap, algorithmParameterSetIdentifier=128
fn test_aes_128_wrap_pad_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_128_wrap_pad();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=kw, operation=instantiate, algorithmName=AES-192-Wrap-KWP, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap, algorithmParameterSetIdentifier=192
fn test_aes_192_wrap_pad_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_192_wrap_pad();
    _ = cipher;
}

// TEST-METADATA: assetType=algorithm, findingType=kw, operation=instantiate, algorithmName=AES-256-Wrap-KWP, algorithmFamily=AES, library=openssl, algorithmPrimitive=key-wrap, algorithmParameterSetIdentifier=256
fn test_aes_256_wrap_pad_cipher() {
    use openssl::symm::Cipher;
    let cipher = Cipher::aes_256_wrap_pad();
    _ = cipher;
}
