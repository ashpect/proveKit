use dep::poseidon2;

fn hash_multiple_rounds(mut hash: Field, rounds: u32) -> Field {
    for _ in 0..rounds {
        hash = poseidon2::bn254::hash_1([hash]);
    }
    hash
}

fn main(plains: [Field; 2], result: Field) {
    let hash = poseidon2::bn254::hash_2(plains);
    let rounds = 1000;
    let final_hash = hash_multiple_rounds(hash, rounds);
    println(final_hash);
    assert(final_hash == result);
}
