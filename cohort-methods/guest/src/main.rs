use risc0_zkvm::guest::env;

fn main() {
    let input: enforcement_core::CohortInput = env::read();
    let journal = enforcement_core::verify_cohort(&input).expect("cohort predicate not satisfied");
    env::commit_slice(&journal.abi_encode());
}
