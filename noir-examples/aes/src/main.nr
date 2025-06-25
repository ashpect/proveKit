fn main(input : [u8; 16], iv : [u8; 16], key : [u8; 16]) {
    let ciphertext = std::aes128::aes128_encrypt(input, iv, key); // In this case, the output length will be 32 bytes.
    let zero_array: [u8; 32] = [0; 32];
    assert_eq(ciphertext, zero_array);
}