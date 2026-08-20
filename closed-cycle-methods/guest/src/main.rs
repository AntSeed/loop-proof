use risc0_zkvm::guest::env;

fn main() {
    let input: enforcement_core::ClosedCycleInput = env::read();
    let journal =
        enforcement_core::verify_closed_cycle(&input).expect("closed-cycle predicate not satisfied");
    env::commit_slice(&journal.abi_encode());
}
