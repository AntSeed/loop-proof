#![no_main]

use alloy_sol_types::SolValue;
use checkpoint_core::{AccumulatorInput, validate_accumulator};
use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

fn main() {
    let input = sp1_zkvm::io::read::<AccumulatorInput>();
    for journal in &input.epoch_journals {
        let digest: [u8; 32] = Sha256::digest(journal.as_ref()).into();
        sp1_zkvm::lib::verify::verify_sp1_proof(&input.epoch_recursion_vkey, &digest);
    }
    let journal = validate_accumulator(&input).expect("invalid historical accumulator");
    sp1_zkvm::io::commit_slice(&journal.abi_encode());
}
