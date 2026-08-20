#![no_main]

use alloy_sol_types::SolValue;
use history_core::{HistoricalChunkWitness, validate_history_chunk};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let witness: HistoricalChunkWitness = env::read();
    let journal = validate_history_chunk(&witness).expect("invalid historical Base header chunk");
    env::commit_slice(&journal.abi_encode());
}
