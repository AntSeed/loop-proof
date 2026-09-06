#![no_main]

sp1_zkvm::entrypoint!(main);

fn main() {
    let bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let input: wash_predicate::SellerProofInput =
        serde_json::from_slice(&bytes).expect("decode seller input");
    let verified = wash_predicate::verify_seller(&input).expect("seller predicate not satisfied");
    sp1_zkvm::io::commit_slice(&verified.journal.abi_encode());
}
