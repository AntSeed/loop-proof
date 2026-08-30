mod common;

use alloy_primitives::B256;
use common::{closed_loop_input, reciprocal_input, LoopCfg, PairCfg};
use wash_predicate::aggregate::{
    vkey_bytes32, HistoricalBlockRef, HistoricalManifest, HistoricalManifestClaim,
    HistoricalManifestSubject, CLOSED_LOOP_PROGRAM_ID, RECIPROCAL_PROGRAM_ID,
};
use wash_predicate::{verify_closed_loop, verify_reciprocal, AggregateJournal, ChildProofInput};

const REPORT_ROOT: B256 = B256::new([0x44; 32]);

#[test]
fn aggregate_requires_the_complete_historical_manifest() {
    let mut closed = verify_closed_loop(&closed_loop_input(&LoopCfg::default())).unwrap();
    let reciprocal = verify_reciprocal(&reciprocal_input(&PairCfg::default())).unwrap();
    for (number, hash) in &mut closed.block_refs {
        if let Some((_, reciprocal_hash)) = reciprocal
            .block_refs
            .iter()
            .find(|(other, _)| other == number)
        {
            *hash = *reciprocal_hash;
        }
    }
    let children = children(&closed, &reciprocal);
    let manifest = manifest(&closed, &reciprocal);
    let aggregate = AggregateJournal::from_children(&children, &manifest).unwrap();

    assert_eq!(aggregate.sellers.len(), 3);
    assert_eq!(aggregate.source_claim_count, 2);
    assert_eq!(aggregate.total_proven_wash_volume, 2_150_000_000);
    assert!(aggregate
        .sellers
        .windows(2)
        .all(|pair| pair[0].seller < pair[1].seller));
    assert_eq!(
        aggregate.block_reference_count as usize,
        manifest.block_refs.len()
    );
    assert!(!aggregate.abi_encode().is_empty());
    let committed = aggregate.committed_public_values(&manifest).unwrap();
    assert_eq!(committed, aggregate.abi_encode());
    assert_eq!(aggregate.report_root, REPORT_ROOT);
    assert_eq!(aggregate.manifest_digest, manifest.digest().unwrap());
}

#[test]
fn aggregate_rejects_missing_or_mismatched_claims() {
    let closed = verify_closed_loop(&closed_loop_input(&LoopCfg::default())).unwrap();
    let reciprocal = verify_reciprocal(&reciprocal_input(&PairCfg::default())).unwrap();
    let children = children(&closed, &reciprocal);
    let manifest = manifest(&closed, &reciprocal);

    assert!(AggregateJournal::from_children(&children[..1], &manifest)
        .unwrap_err()
        .contains("incomplete historical claim set"));

    let mut wrong_volume = manifest.clone();
    wrong_volume.claims[0].subjects[0].proven_wash_volume += 1;
    assert!(AggregateJournal::from_children(&children, &wrong_volume)
        .unwrap_err()
        .contains("results mismatch"));

    let mut wrong_claim = manifest.clone();
    wrong_claim.claims[0].source_claim_id = B256::new([0x99; 32]);
    assert!(AggregateJournal::from_children(&children, &wrong_claim)
        .unwrap_err()
        .contains("unexpected source claim"));
}

fn children(
    closed: &wash_predicate::WashJournal,
    reciprocal: &wash_predicate::WashJournal,
) -> Vec<ChildProofInput> {
    vec![
        ChildProofInput {
            program_id: RECIPROCAL_PROGRAM_ID,
            program_vkey: vkey_bytes32([2; 8]),
            vkey_digest: [2; 8],
            public_values: reciprocal.abi_encode(),
        },
        ChildProofInput {
            program_id: CLOSED_LOOP_PROGRAM_ID,
            program_vkey: vkey_bytes32([1; 8]),
            vkey_digest: [1; 8],
            public_values: closed.abi_encode(),
        },
    ]
}

fn manifest(
    closed: &wash_predicate::WashJournal,
    reciprocal: &wash_predicate::WashJournal,
) -> HistoricalManifest {
    let mut block_refs = closed
        .block_refs
        .iter()
        .chain(&reciprocal.block_refs)
        .copied()
        .collect::<Vec<_>>();
    block_refs.sort_unstable_by_key(|reference| reference.0);
    block_refs.dedup_by_key(|reference| reference.0);
    HistoricalManifest {
        report_root: REPORT_ROOT,
        period_start_block: closed.period_start_block.min(reciprocal.period_start_block),
        period_end_block: closed.period_end_block.max(reciprocal.period_end_block),
        closed_loop_program_vkey: vkey_bytes32([1; 8]),
        reciprocal_program_vkey: vkey_bytes32([2; 8]),
        claims: vec![
            HistoricalManifestClaim {
                source_claim_id: closed.source_claim_id,
                predicate_id: closed.predicate_id,
                period_start_block: closed.period_start_block,
                period_end_block: closed.period_end_block,
                subjects: closed
                    .subjects
                    .iter()
                    .map(|subject| HistoricalManifestSubject {
                        seller: subject.subject,
                        proven_wash_volume: subject.wash_volume,
                    })
                    .collect(),
            },
            HistoricalManifestClaim {
                source_claim_id: reciprocal.source_claim_id,
                predicate_id: reciprocal.predicate_id,
                period_start_block: reciprocal.period_start_block,
                period_end_block: reciprocal.period_end_block,
                subjects: reciprocal
                    .subjects
                    .iter()
                    .map(|subject| HistoricalManifestSubject {
                        seller: subject.subject,
                        proven_wash_volume: subject.wash_volume,
                    })
                    .collect(),
            },
        ],
        block_refs: block_refs
            .into_iter()
            .map(|(number, block_hash)| HistoricalBlockRef { number, block_hash })
            .collect(),
    }
}
