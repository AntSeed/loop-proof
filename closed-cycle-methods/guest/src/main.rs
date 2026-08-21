#![no_main]

sp1_zkvm::entrypoint!(main);

fn main() {
    let bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let input: enforcement_core::ClosedCycleInput =
        serde_json::from_slice(&bytes).expect("decode closed-cycle input");
    let journal =
        enforcement_core::verify_closed_cycle(&input).expect("closed-cycle predicate not satisfied");
    sp1_zkvm::io::commit_slice(&journal.abi_encode());
}
