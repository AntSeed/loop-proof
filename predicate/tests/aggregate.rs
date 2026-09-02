mod common;

use alloy_primitives::{address, b256, B256};
use common::{closed_loop_input, reciprocal_input, LoopCfg, PairCfg};
use wash_predicate::aggregate::{
    block_authentication_root, evidence_digest, vkey_bytes32, HistoricalBlockRef,
    SolSellerSettlement, CLOSED_LOOP_PROGRAM_ID, RECIPROCAL_PROGRAM_ID,
};
use wash_predicate::{
    verify_closed_loop, verify_reciprocal, ChildProofInput, SellerAggregateInput, SellerJournal,
};

#[test]
fn block_authentication_leaf_matches_solidity_abi() {
    let refs = [HistoricalBlockRef {
        number: 123,
        block_hash: B256::new([0xaa; 32]),
    }];
    assert_eq!(
        block_authentication_root(&refs).unwrap(),
        b256!("30527e2a947e958d4041ae91f69cf216b960961be3a4610a31d765da7989b11a")
    );
}

/// Vector shared with `AntseedWashTradingRegistry.t.sol`: the digest must
/// equal Solidity `keccak256(abi.encode(seller, start, end, settlements))`.
#[test]
fn evidence_digest_matches_solidity_abi_encode() {
    let settlements = [
        SolSellerSettlement {
            settlementId: B256::new([0x11; 32]),
            amount: 300,
        },
        SolSellerSettlement {
            settlementId: B256::new([0x22; 32]),
            amount: 450,
        },
    ];
    assert_eq!(
        evidence_digest(
            address!("00000000000000000000000000000000000a11ce"),
            100,
            199,
            &settlements
        ),
        b256!("58e5f0d44d8fe5ba80ddbd5fca67cdc52460974d1658eadcfce9a1e830beba6c")
    );
}

#[test]
fn seller_aggregate_accepts_one_child() {
    let closed = verify_closed_loop(&closed_loop_input(&LoopCfg::default())).unwrap();
    let input = seller_input(&closed);
    let aggregate = SellerJournal::from_children(&[closed_child(&closed)], &input).unwrap();

    assert_eq!(aggregate.seller, closed.subjects[0].subject);
    assert_eq!(aggregate.proven_wash_volume, closed.subjects[0].wash_volume);
    assert_eq!(aggregate.period_start_block, closed.period_start_block);
    assert_eq!(aggregate.period_end_block, closed.period_end_block);
    assert!(!aggregate.abi_encode().is_empty());
}

#[test]
fn seller_aggregate_extracts_one_reciprocal_subject() {
    let reciprocal = verify_reciprocal(&reciprocal_input(&PairCfg::default())).unwrap();
    let mut input = seller_input(&reciprocal);
    input.seller = reciprocal.subjects[1].subject;
    let aggregate = SellerJournal::from_children(&[reciprocal_child(&reciprocal)], &input).unwrap();

    assert_eq!(aggregate.seller, reciprocal.subjects[1].subject);
    assert_eq!(
        aggregate.proven_wash_volume,
        reciprocal.subjects[1].wash_volume
    );
}

#[test]
fn seller_aggregate_unions_disjoint_settlements() {
    let first = verify_closed_loop(&closed_loop_input(&LoopCfg::default())).unwrap();
    let mut second = first.clone();
    second.source_claim_id = B256::new([0x31; 32]);
    second.claim_id = B256::new([0x32; 32]);
    for (index, settlement) in second.subjects[0].settlements.iter_mut().enumerate() {
        settlement.settlement_id = B256::with_last_byte(0x73 + index as u8);
    }
    let expected = first.subjects[0].wash_volume + second.subjects[0].wash_volume;

    let aggregate = SellerJournal::from_children(
        &[closed_child(&first), closed_child(&second)],
        &seller_input(&first),
    )
    .unwrap();
    assert_eq!(aggregate.proven_wash_volume, expected);
}

#[test]
fn seller_aggregate_deduplicates_overlapping_settlements() {
    let first = verify_closed_loop(&closed_loop_input(&LoopCfg::default())).unwrap();
    let mut second = first.clone();
    second.source_claim_id = B256::new([0x41; 32]);
    second.claim_id = B256::new([0x42; 32]);

    let aggregate = SellerJournal::from_children(
        &[closed_child(&first), closed_child(&second)],
        &seller_input(&first),
    )
    .unwrap();
    assert_eq!(aggregate.proven_wash_volume, first.subjects[0].wash_volume);
}

#[test]
fn seller_aggregate_rejects_conflicts_and_period_mismatches() {
    let first = verify_closed_loop(&closed_loop_input(&LoopCfg::default())).unwrap();
    let mut conflicting = first.clone();
    conflicting.source_claim_id = B256::new([0x51; 32]);
    conflicting.claim_id = B256::new([0x52; 32]);
    conflicting.subjects[0].settlements[0].amount += 1;
    conflicting.subjects[0].wash_volume += 1;
    assert!(SellerJournal::from_children(
        &[closed_child(&first), closed_child(&conflicting)],
        &seller_input(&first),
    )
    .unwrap_err()
    .contains("conflicting settlement amount"));

    let mut wrong_period = seller_input(&first);
    wrong_period.period_end_block += 1;
    assert!(
        SellerJournal::from_children(&[closed_child(&first)], &wrong_period)
            .unwrap_err()
            .contains("child identity mismatch")
    );
}

fn seller_input(journal: &wash_predicate::WashJournal) -> SellerAggregateInput {
    SellerAggregateInput {
        seller: journal.subjects[0].subject,
        period_start_block: journal.period_start_block,
        period_end_block: journal.period_end_block,
        closed_loop_program_vkey: vkey_bytes32([1; 8]),
        reciprocal_program_vkey: vkey_bytes32([2; 8]),
    }
}

fn closed_child(journal: &wash_predicate::WashJournal) -> ChildProofInput {
    ChildProofInput {
        program_id: CLOSED_LOOP_PROGRAM_ID,
        program_vkey: vkey_bytes32([1; 8]),
        vkey_digest: [1; 8],
        public_values: journal.abi_encode(),
    }
}

fn reciprocal_child(journal: &wash_predicate::WashJournal) -> ChildProofInput {
    ChildProofInput {
        program_id: RECIPROCAL_PROGRAM_ID,
        program_vkey: vkey_bytes32([2; 8]),
        vkey_digest: [2; 8],
        public_values: journal.abi_encode(),
    }
}
