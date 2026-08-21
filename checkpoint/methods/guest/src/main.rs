#![no_main]

use alloy_sol_types::SolValue;
use checkpoint_core::{AccumulatorInput, validate_accumulator};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: AccumulatorInput = env::read();
    for journal in &input.epoch_journals {
        env::verify(input.epoch_image_id.0, journal.as_ref()).expect("epoch receipt verification failed");
    }
    let journal = validate_accumulator(&input).expect("invalid historical accumulator");
    env::commit_slice(&journal.abi_encode());
}
