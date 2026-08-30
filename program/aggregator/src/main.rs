#![no_main]

use sha2::{Digest, Sha256};
use wash_predicate::aggregate::HistoricalManifest;
use wash_predicate::{AggregateJournal, ChildProofInput};

sp1_zkvm::entrypoint!(main);

fn main() {
    let children = sp1_zkvm::io::read::<Vec<ChildProofInput>>();
    let manifest = sp1_zkvm::io::read::<HistoricalManifest>();
    for child in &children {
        let digest: [u8; 32] = Sha256::digest(&child.public_values).into();
        sp1_lib::verify::verify_sp1_proof(&child.vkey_digest, &digest);
    }
    let aggregate = AggregateJournal::from_children(&children, &manifest)
        .expect("invalid historical aggregate");
    sp1_zkvm::io::commit_slice(
        &aggregate
            .committed_public_values(&manifest)
            .expect("invalid aggregate commitment"),
    );
}
