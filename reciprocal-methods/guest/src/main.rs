#![no_main]

sp1_zkvm::entrypoint!(main);

fn main() {
    let bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let input: enforcement_core::ReciprocalInput =
        serde_json::from_slice(&bytes).expect("decode reciprocal input");
    let journal = enforcement_core::verify_reciprocal(&input).expect("reciprocal predicate not satisfied");
    sp1_zkvm::io::commit_slice(&journal.abi_encode());
}
