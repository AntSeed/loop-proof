//! Guest entrypoint. The image ID of this binary IS the on-chain rule:
//! any change to loop-core's thresholds or logic produces a different ID.

use risc0_zkvm::guest::env;

fn main() {
    let input: loop_core::LoopInput = env::read();
    let journal = loop_core::verify(&input).expect("loop predicate not satisfied");
    // ABI-encoded so the on-chain registry can sha256-match and abi.decode it.
    env::commit_slice(&journal.abi_encode());
}
