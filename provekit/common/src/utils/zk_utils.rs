use {
    crate::FieldElement,
    ark_ff::{BigInt, UniformRand, PrimeField},
    rayon::prelude::*,
    sha2::{Digest, Sha256},
    whir::poly_utils::evals::EvaluationsList,
};

pub fn create_masked_polynomial(
    original: EvaluationsList<FieldElement>,
    mask: &[FieldElement],
) -> EvaluationsList<FieldElement> {
    let mut combined = Vec::with_capacity(original.num_evals() * 2);
    combined.extend_from_slice(original.evals());
    combined.extend_from_slice(mask);
    EvaluationsList::new(combined)
}

pub fn generate_random_multilinear_polynomial(num_vars: usize) -> Vec<FieldElement> {
    let num_elements = 1 << num_vars;
    let mut elements = Vec::with_capacity(num_elements);

    // TODO(px): find the optimal chunk size
    const CHUNK_SIZE: usize = 32;

    // Get access to the uninitialized memory
    let spare = elements.spare_capacity_mut();

    // Fill the uninitialized memory in parallel using chunked approach
    spare.par_chunks_mut(CHUNK_SIZE).for_each(|chunk| {
        let mut rng = ark_std::rand::thread_rng();
        for element in chunk {
            element.write(FieldElement::rand(&mut rng));
        }
    });

    unsafe {
        elements.set_len(num_elements);
    }

    elements
}

/// Hashes public input values.
///
/// This function takes public indices and their corresponding witness values,
/// hashes them using SHA-256, and converts the result to a FieldElement.
pub fn hash_public_values(public_indices: Vec<usize>, witness: Vec<FieldElement>) -> FieldElement {
    let mut hasher = Sha256::new();
    for (_idx, value) in public_indices.iter().zip(witness.iter()) {
        for limb in value.into_bigint().0.iter() {
            hasher.update(&limb.to_le_bytes());
        }
    }
    let result = hasher.finalize();

    let limbs = result
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();

    FieldElement::new(BigInt::new(limbs.try_into().unwrap()))
}