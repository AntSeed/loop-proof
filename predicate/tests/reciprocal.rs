mod common;

use alloy_primitives::address;
use common::*;
use wash_predicate::{
    reciprocal_claim_id, verify_reciprocal, RECIPROCAL_PREDICATE_ID,
};

fn assert_rejects(input: &wash_predicate::ReciprocalInput, needle: &str) {
    let error = verify_reciprocal(input).unwrap_err();
    assert!(error.contains(needle), "expected {needle:?} in {error:?}");
}

#[test]
fn self_financed_pair_produces_the_journal() {
    let journal = verify_reciprocal(&reciprocal_input(&PairCfg::default())).unwrap();
    assert_eq!(journal.predicate_id, RECIPROCAL_PREDICATE_ID);
    assert_eq!(journal.claim_id, reciprocal_claim_id(PAIR_A, PAIR_B));
    assert_eq!(journal.subjects.len(), 2);
    assert_eq!(journal.subjects[0].subject, PAIR_A);
    assert_eq!(journal.subjects[0].wash_volume, 500_000_000);
    assert_eq!(journal.subjects[0].settled_volume, 1_000_000_000);
    assert_eq!(journal.subjects[1].subject, PAIR_B);
    assert_eq!(journal.subjects[1].wash_volume, 450_000_000);
    assert_eq!(journal.subjects[1].settled_volume, 900_000_000);

    let bytes = journal.abi_encode();
    assert_eq!(wash_predicate::WashJournal::abi_decode(&bytes).unwrap(), journal);
}

#[test]
fn externally_financed_volume_is_outside_the_predicate() {
    // Same settled volume, but the pair's protocol inflow is not shown to
    // come from within the pair: honest mutual trade financed elsewhere.
    let mut cfg = PairCfg::default();
    cfg.deposits = vec![];
    assert_rejects(&reciprocal_input(&cfg), "external capital");
}

#[test]
fn reciprocity_boundary_is_exact() {
    // β = 8_000: 400 vs 500 passes exactly…
    let mut cfg = PairCfg::default();
    cfg.a_sells = vec![500_000_000];
    cfg.b_sells = vec![400_000_000];
    cfg.deposits = vec![(PAIR_A, 500_000_000), (PAIR_B, 400_000_000)];
    verify_reciprocal(&reciprocal_input(&cfg)).unwrap();

    // …one unit less does not.
    let mut cfg = PairCfg::default();
    cfg.a_sells = vec![500_000_000];
    cfg.b_sells = vec![399_999_999];
    cfg.deposits = vec![(PAIR_A, 500_000_000), (PAIR_B, 400_000_000)];
    assert_rejects(&reciprocal_input(&cfg), "not reciprocal");
}

#[test]
fn self_financing_boundary_is_exact() {
    // total = 950; α_self = 9_000 → external allowance = 95.
    // internal = 855 with zero end balances sits exactly on the boundary.
    let mut cfg = PairCfg::default();
    cfg.deposits = vec![(PAIR_A, 500_000_000), (PAIR_B, 355_000_000)];
    verify_reciprocal(&reciprocal_input(&cfg)).unwrap();

    let mut cfg = PairCfg::default();
    cfg.deposits = vec![(PAIR_A, 500_000_000), (PAIR_B, 354_999_999)];
    assert_rejects(&reciprocal_input(&cfg), "external capital");
}

#[test]
fn settlements_outside_the_exact_pair_are_rejected() {
    let mut input = reciprocal_input(&PairCfg::default());
    let reference = input.settlements[0];
    let number = input.blocks[reference.block].header.number;
    input.blocks[reference.block] = settlement_block(
        number,
        2_000,
        address!("0000000000000000000000000000000000000077"),
        PAIR_A,
        250_000_000,
        true,
    );
    assert_rejects(&input, "outside the exact pair");
}

#[test]
fn pair_must_be_normalized() {
    let mut input = reciprocal_input(&PairCfg::default());
    std::mem::swap(&mut input.address_a, &mut input.address_b);
    assert_rejects(&input, "normalized");
}

#[test]
fn duplicate_evidence_is_rejected() {
    let mut input = reciprocal_input(&PairCfg::default());
    let first = input.settlements[0];
    input.settlements.push(first);
    assert_rejects(&input, "duplicate settlement");

    let mut input = reciprocal_input(&PairCfg::default());
    let first = input.internal_deposits[0].clone();
    input.internal_deposits.push(first);
    assert_rejects(&input, "duplicate deposit");
}

#[test]
fn zero_settlements_are_rejected() {
    let mut cfg = PairCfg::default();
    cfg.a_sells = vec![250_000_000, 0];
    assert_rejects(&reciprocal_input(&cfg), "zero settlement");
}

#[test]
fn pair_deposits_require_member_attribution_by_signer() {
    // Payer outside the pair.
    let mut input = reciprocal_input(&PairCfg::default());
    let evidence = input.internal_deposits[0].clone();
    let number = input.blocks[evidence.transfer.block].header.number;
    input.blocks[evidence.transfer.block] = deposit_block(
        number,
        1_500,
        address!("0000000000000000000000000000000000000077"),
        PAIR_A,
        500_000_000,
        true,
    );
    assert_rejects(&input, "invalid pair deposit");

    // Payer is a member, but the transaction signer is not that member.
    let mut input = reciprocal_input(&PairCfg::default());
    let evidence = input.internal_deposits[0].clone();
    let number = input.blocks[evidence.transfer.block].header.number;
    input.blocks[evidence.transfer.block] =
        deposit_block(number, 1_500, PAIR_B, PAIR_A, 500_000_000, true);
    assert_rejects(&input, "signer mismatch");
}

#[test]
fn reverted_and_tampered_evidence_is_rejected() {
    let mut input = reciprocal_input(&PairCfg::default());
    let reference = input.settlements[0];
    let number = input.blocks[reference.block].header.number;
    input.blocks[reference.block] =
        settlement_block(number, 2_000, PAIR_B, PAIR_A, 250_000_000, false);
    assert_rejects(&input, "reverted");

    let mut input = reciprocal_input(&PairCfg::default());
    input.blocks[0].header.receipts_root = alloy_primitives::B256::ZERO;
    assert!(verify_reciprocal(&input).is_err());
}

#[test]
fn unstaked_member_commits_a_zero_denominator() {
    let mut cfg = PairCfg::default();
    cfg.agents = [(111, 1_000_000_000), (0, 0)];
    let journal = verify_reciprocal(&reciprocal_input(&cfg)).unwrap();
    assert_eq!(journal.subjects[1].settled_volume, 0);
}
