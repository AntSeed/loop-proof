#![no_main]

use alloy_sol_types::SolValue;
use history_core::{EpochWitness, validate_epoch};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let witness: EpochWitness = env::read();
    let journal = validate_epoch(&witness).expect("invalid historical Base header epoch");
    env::commit_slice(&journal.abi_encode());
}
