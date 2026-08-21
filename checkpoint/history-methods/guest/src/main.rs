#![no_main]

use alloy_sol_types::SolValue;
use history_core::{EpochWitness, validate_epoch};

sp1_zkvm::entrypoint!(main);

fn main() {
    let witness = sp1_zkvm::io::read::<EpochWitness>();
    let journal = validate_epoch(&witness).expect("invalid historical Base header epoch");
    sp1_zkvm::io::commit_slice(&journal.abi_encode());
}
