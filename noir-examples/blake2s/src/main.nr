fn main(x: [u8; 4]) {
    // Example input bytes (same as the inspiration)
    // let x: [u8; 4] = [163, 117, 178, 149]; // some random bytes
    
    // Compute Blake2s hash
    let hash = std::hash::blake2s(x);
    
    // assert hash is 32 bytes
    assert_eq(hash.len(), 32);
    
    // assert hash value is 1b23aa0241350289fc70cf9372437d9a021b875b8baa558b15b0b7687952ec73
    assert_eq(hash, [27, 35, 170, 2, 65, 53, 2, 137, 252, 112, 207, 147, 114, 67, 125, 154, 2, 27, 135, 91, 139, 170, 85, 139, 21, 176, 183, 104, 121, 82, 236, 115]);
}