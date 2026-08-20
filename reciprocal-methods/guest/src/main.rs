use risc0_zkvm::guest::env;

fn main() {
    let input: enforcement_core::ReciprocalInput = env::read();
    let journal = enforcement_core::verify_reciprocal(&input).expect("reciprocal predicate not satisfied");
    env::commit_slice(&journal.abi_encode());
}
