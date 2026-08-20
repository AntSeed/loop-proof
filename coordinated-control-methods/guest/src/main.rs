use risc0_zkvm::guest::env;

fn main() {
    let input: enforcement_core::CoordinatedControlInput = env::read();
    let journal = enforcement_core::verify_coordinated_control(&input)
        .expect("coordinated-control predicate not satisfied");
    env::commit_slice(&journal.abi_encode());
}
