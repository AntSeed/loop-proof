#![no_main]

use sha2::{Digest, Sha256};
use wash_predicate::{ChildProofInput, SellerAggregateInput, SellerJournal};

sp1_zkvm::entrypoint!(main);

fn main() {
    let children = sp1_zkvm::io::read::<Vec<ChildProofInput>>();
    let input = sp1_zkvm::io::read::<SellerAggregateInput>();
    for child in &children {
        let digest: [u8; 32] = Sha256::digest(&child.public_values).into();
        sp1_lib::verify::verify_sp1_proof(&child.vkey_digest, &digest);
    }
    let aggregate = SellerJournal::from_children(&children, &input)
        .expect("invalid seller aggregate");
    sp1_zkvm::io::commit_slice(&aggregate.abi_encode());
}
