mod common;

use alloy_primitives::{keccak256, B256};
use alloy_sol_types::SolValue;
use common::{closed_loop_input, reciprocal_input, LoopCfg, PairCfg};
use wash_predicate::aggregate::vkey_bytes32;
use wash_predicate::aggregate::{CLOSED_LOOP_PROGRAM_ID, RECIPROCAL_PROGRAM_ID};
use wash_predicate::{verify_closed_loop, verify_reciprocal, AggregateJournal, ChildProofInput};

#[test]
fn aggregate_sorts_findings_and_deduplicates_block_refs() {
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
    let children = vec![
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
    ];
    let aggregate = AggregateJournal::from_children(&children).unwrap();
    assert_eq!(aggregate.findings.len(), 3);
    assert!(aggregate
        .findings
        .windows(2)
        .all(|pair| pair[0].claim_id < pair[1].claim_id));
    assert!(aggregate
        .block_refs
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0));
    for finding in &aggregate.findings {
        assert_ne!(finding.claim_id, B256::ZERO);
        assert!(finding.proven_wash_volume <= finding.total_volume);
    }
    assert!(!aggregate.abi_encode().is_empty());
}

#[test]
fn reciprocal_subjects_receive_distinct_finding_ids() {
    let journal = verify_reciprocal(&reciprocal_input(&PairCfg::default())).unwrap();
    let aggregate = AggregateJournal::from_children(&[ChildProofInput {
        program_id: RECIPROCAL_PROGRAM_ID,
        program_vkey: vkey_bytes32([2; 8]),
        vkey_digest: [2; 8],
        public_values: journal.abi_encode(),
    }])
    .unwrap();
    assert_eq!(aggregate.findings.len(), 2);
    assert_ne!(
        aggregate.findings[0].claim_id,
        aggregate.findings[1].claim_id
    );
    let expected: Vec<_> = journal
        .subjects
        .iter()
        .map(|subject| {
            keccak256((RECIPROCAL_PROGRAM_ID, journal.claim_id, subject.agent_id).abi_encode())
        })
        .collect();
    assert!(aggregate
        .findings
        .iter()
        .all(|finding| expected.contains(&finding.claim_id)));
}
