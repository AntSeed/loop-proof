//! P0_CLOSED_LOOP guest: the compiled binary's verification key IS the rule.
//! The journal is the ABI-encoded WashJournal; nothing else is committed.

#![no_main]

sp1_zkvm::entrypoint!(main);

fn main() {
    let bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let input: wash_predicate::ClosedLoopInput =
        serde_json::from_slice(&bytes).expect("decode closed-loop input");
    let journal =
        wash_predicate::verify_closed_loop(&input).expect("closed-loop predicate not satisfied");
    sp1_zkvm::io::commit_slice(&journal.abi_encode());
}
