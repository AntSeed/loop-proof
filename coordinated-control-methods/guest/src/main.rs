use risc0_zkvm::guest::env;

fn main() {
    let mut length = 0u32;
    env::read_slice(core::slice::from_mut(&mut length));
    let mut bytes = vec![0u8; length as usize];
    env::read_slice(&mut bytes);
    let input: enforcement_core::CoordinatedControlInput =
        serde_json::from_slice(&bytes).expect("decode coordinated-control input");
    let journal = enforcement_core::verify_coordinated_control(&input)
        .expect("coordinated-control predicate not satisfied");
    env::commit_slice(&journal.abi_encode());
}
