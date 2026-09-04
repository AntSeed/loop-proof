mod common;

use alloy_primitives::{address, b256, B256};
use common::{
    closed_loop_input, reciprocal_input, total_volume_witness, LoopCfg, PairCfg,
    TOTAL_VOLUME_END_COUNTER,
};
use wash_predicate::seller::{
    block_authentication_chunks, block_authentication_leaf, block_authentication_root,
    evidence_digest, HistoricalBlockRef, SellerJournal, SolSellerSettlement,
};
use wash_predicate::{
    verify_block_authentication_chunk, verify_seller, FundingKind, ReceiptRef, SellerEvidence,
    SellerProofInput, TransactionRef, PERIOD_END_BLOCK, PERIOD_START_BLOCK,
};

#[test]
fn closed_loop_claim_produces_direct_seller_journal() {
    let claim = closed_loop_input(&LoopCfg::default());
    let seller = claim.seller;
    let verified = verify_seller(&input(seller, SellerEvidence::ClosedLoop(claim))).unwrap();
    assert_eq!(verified.journal.schema_version, 1);
    assert_eq!(verified.journal.seller, seller);
    assert!(verified.journal.proven_wash_volume > 0);
    assert_eq!(
        verified.journal.total_seller_volume,
        TOTAL_VOLUME_END_COUNTER
    );
    assert_eq!(
        SellerJournal::abi_decode(&verified.journal.abi_encode()).unwrap(),
        verified.journal
    );
}

#[test]
fn total_volume_is_the_end_counter_and_boundary_joins_block_refs() {
    let claim = closed_loop_input(&LoopCfg::default());
    let seller = claim.seller;
    let proof = input(seller, SellerEvidence::ClosedLoop(claim));
    let verified = verify_seller(&proof).unwrap();
    assert_eq!(
        verified.journal.total_seller_volume,
        TOTAL_VOLUME_END_COUNTER
    );
    assert!(verified
        .block_refs
        .iter()
        .any(|reference| reference.number == PERIOD_END_BLOCK));
}

#[test]
fn unstaked_seller_has_no_denominator() {
    let claim = closed_loop_input(&LoopCfg::default());
    let seller = claim.seller;
    let mut proof = input(seller, SellerEvidence::ClosedLoop(claim));
    proof.total_volume = common::unstaked_total_volume_witness(seller);
    let error = verify_seller(&proof).unwrap_err();
    assert!(
        error.contains("not a staked agent") || error.contains("conflicting boundary block hash"),
        "{error}"
    );
}

#[test]
fn boundary_at_the_wrong_block_is_rejected() {
    let claim = closed_loop_input(&LoopCfg::default());
    let seller = claim.seller;
    let mut proof = input(seller, SellerEvidence::ClosedLoop(claim));
    proof.total_volume.header.number = PERIOD_END_BLOCK - 1;
    let error = verify_seller(&proof).unwrap_err();
    assert!(error.contains("the rule requires block"), "{error}");
}

#[test]
fn reciprocal_claim_proves_each_wallet_separately() {
    let claim = reciprocal_input(&PairCfg::default());
    let first = verify_seller(&input(
        claim.address_a,
        SellerEvidence::Reciprocal(claim.clone()),
    ))
    .unwrap();
    let second = verify_seller(&input(claim.address_b, SellerEvidence::Reciprocal(claim))).unwrap();
    assert_ne!(first.journal.seller, second.journal.seller);
    assert!(first.journal.proven_wash_volume > 0);
    assert!(second.journal.proven_wash_volume > 0);
}

#[test]
fn wrong_seller_is_rejected() {
    let claim = closed_loop_input(&LoopCfg::default());
    let wrong = input(
        address!("0000000000000000000000000000000000000bad"),
        SellerEvidence::ClosedLoop(claim),
    );
    assert!(verify_seller(&wrong)
        .unwrap_err()
        .contains("does not prove target seller"));
}

#[test]
fn invalid_top_level_input_is_rejected() {
    let claim = closed_loop_input(&LoopCfg::default());
    assert!(verify_seller(&SellerProofInput {
        seller: alloy_primitives::Address::ZERO,
        period_start_block: PERIOD_START_BLOCK,
        period_end_block: PERIOD_END_BLOCK,
        total_volume: total_volume_witness(alloy_primitives::Address::ZERO),
        evidence: SellerEvidence::ClosedLoop(claim.clone()),
    })
    .is_err());
    let mut wrong_period = input(claim.seller, SellerEvidence::ClosedLoop(claim));
    wrong_period.period_end_block += 1;
    assert!(verify_seller(&wrong_period)
        .unwrap_err()
        .contains("claim identity mismatch"));
}

#[test]
fn native_funding_is_rejected_through_direct_seller_verification() {
    let mut claim = closed_loop_input(&LoopCfg::default());
    claim.fundings[0].kind = FundingKind::Native {
        transaction: TransactionRef {
            block: 0,
            transaction: 0,
        },
        receipt: ReceiptRef {
            block: 0,
            receipt: 0,
        },
    };
    let error = verify_seller(&input(claim.seller, SellerEvidence::ClosedLoop(claim))).unwrap_err();
    assert!(error.contains("native funding is not supported"));
}

#[test]
fn guest_input_requires_one_evidence_object_and_rejects_legacy_claims() {
    let evidence = closed_loop_input(&LoopCfg::default());
    let original =
        serde_json::to_value(input(evidence.seller, SellerEvidence::ClosedLoop(evidence))).unwrap();
    let decoded: SellerProofInput = serde_json::from_value(original.clone()).unwrap();
    verify_seller(&decoded).unwrap();

    for count in [0, 1, 2] {
        let mut legacy = original.clone();
        let evidence = legacy.as_object_mut().unwrap().remove("evidence").unwrap();
        legacy["claims"] = serde_json::json!(vec![evidence; count]);
        assert!(serde_json::from_value::<SellerProofInput>(legacy).is_err());
    }
    let mut mixed = original.clone();
    mixed["claims"] = serde_json::json!([original["evidence"].clone()]);
    assert!(serde_json::from_value::<SellerProofInput>(mixed).is_err());
    let mut array = original.clone();
    array["evidence"] =
        serde_json::json!([original["evidence"].clone(), original["evidence"].clone()]);
    assert!(serde_json::from_value::<SellerProofInput>(array).is_err());
    let mut missing = original;
    missing.as_object_mut().unwrap().remove("evidence");
    assert!(serde_json::from_value::<SellerProofInput>(missing).is_err());
}

#[test]
fn solidity_vectors_and_merkle_root_are_unchanged() {
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
    let refs = [HistoricalBlockRef {
        number: 123,
        block_hash: B256::new([0xaa; 32]),
    }];
    assert_eq!(
        block_authentication_leaf(0, &refs),
        b256!("30527e2a947e958d4041ae91f69cf216b960961be3a4610a31d765da7989b11a")
    );
    assert_eq!(
        block_authentication_root(&refs),
        Some(block_authentication_leaf(0, &refs))
    );
    let chunks = block_authentication_chunks(&refs).unwrap();
    assert!(verify_block_authentication_chunk(
        block_authentication_root(&refs).unwrap(),
        &chunks[0]
    ));
    let mut tampered = chunks[0].clone();
    tampered.references[0].block_hash = B256::repeat_byte(0xbb);
    assert!(!verify_block_authentication_chunk(
        block_authentication_root(&refs).unwrap(),
        &tampered
    ));
}

fn input(seller: alloy_primitives::Address, evidence: SellerEvidence) -> SellerProofInput {
    SellerProofInput {
        seller,
        period_start_block: PERIOD_START_BLOCK,
        period_end_block: PERIOD_END_BLOCK,
        total_volume: total_volume_witness(seller),
        evidence,
    }
}
