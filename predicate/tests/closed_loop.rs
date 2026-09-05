mod common;

use alloy_primitives::{address, B256};
use common::*;
use wash_predicate::{
    canonical_evidence_hash, closed_loop_claim_id, cohort_hash, verify_closed_loop,
    FundingEvidence, FundingKind, LogRef, ReceiptRef, ReturnPath, TransactionRef,
    CLOSED_LOOP_PREDICATE_ID, PERIOD_END_BLOCK, PERIOD_START_BLOCK,
};

fn assert_rejects(input: &wash_predicate::ClosedLoopInput, needle: &str) {
    let error = verify_closed_loop(input).unwrap_err();
    assert!(error.contains(needle), "expected {needle:?} in {error:?}");
}

#[test]
fn valid_loop_produces_the_journal() {
    let input = closed_loop_input(&LoopCfg::default());
    let journal = verify_closed_loop(&input).unwrap();

    assert_eq!(journal.predicate_id, CLOSED_LOOP_PREDICATE_ID);
    assert_eq!(journal.period_start_block, PERIOD_START_BLOCK);
    assert_eq!(journal.period_end_block, PERIOD_END_BLOCK);
    assert_eq!(journal.subjects.len(), 1);
    assert_eq!(journal.subjects[0].subject, SELLER);
    assert_eq!(journal.subjects[0].wash_volume, 1_200_000_000);
    assert_eq!(journal.source_claim_id, input.source_claim_id);
    assert_eq!(
        journal.claim_id,
        closed_loop_claim_id(
            PERIOD_START_BLOCK,
            PERIOD_END_BLOCK,
            SELLER,
            FUNDER,
            cohort_hash(&BUYERS),
            canonical_evidence_hash(&input).unwrap(),
        )
    );
    // Block refs are sorted, unique, and include the period-end state block.
    let numbers: Vec<u64> = journal.block_refs.iter().map(|(n, _)| *n).collect();
    let mut sorted = numbers.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(numbers, sorted);
    assert!(numbers.contains(&PERIOD_END_BLOCK));

    // ABI round trip
    let bytes = journal.abi_encode();
    assert_eq!(
        wash_predicate::WashJournal::abi_decode(&bytes).unwrap(),
        journal
    );
}

#[test]
fn tampered_roots_are_rejected() {
    let base = closed_loop_input(&LoopCfg::default());

    let mut receipts = base.clone();
    receipts.blocks[0].header.receipts_root = B256::ZERO;
    assert!(verify_closed_loop(&receipts).is_err());

    let mut transactions = base.clone();
    transactions.blocks[0].header.transactions_root = B256::ZERO;
    assert!(verify_closed_loop(&transactions).is_err());

    let mut state = base.clone();
    let end_state = state.ledgers[0].end.block;
    state.blocks[end_state].header.state_root = B256::ZERO;
    assert!(verify_closed_loop(&state).is_err());
}

#[test]
fn duplicate_evidence_is_rejected() {
    let base = closed_loop_input(&LoopCfg::default());

    let mut duplicate_settlement = base.clone();
    let first = duplicate_settlement.settlements[0];
    duplicate_settlement.settlements.push(first);
    assert_rejects(&duplicate_settlement, "duplicate");

    let mut duplicate_block = base.clone();
    let block = duplicate_block.blocks[0].clone();
    duplicate_block.blocks.push(block);
    assert_rejects(&duplicate_block, "duplicate block");

    // A funding transfer cannot moonlight as a return hop.
    let mut reuse = base.clone();
    let funding_ref = match reuse.fundings[0].kind {
        FundingKind::Usdc { transfer } => transfer,
        _ => unreachable!(),
    };
    reuse.returns.push(ReturnPath {
        transfers: vec![funding_ref],
    });
    assert_rejects(&reuse, "duplicate");
}

#[test]
fn reverted_receipts_are_rejected() {
    let mut cfg = LoopCfg::default();
    cfg.settled = vec![400_000_000; 3];
    let mut input = closed_loop_input(&cfg);
    // Rebuild the first settlement block as reverted.
    let reference = input.settlements[0];
    let block = &input.blocks[reference.block];
    let reverted = settlement_block(
        block.header.number,
        block.header.timestamp,
        BUYERS[0],
        SELLER,
        400_000_000,
        false,
    );
    input.blocks[reference.block] = reverted;
    assert_rejects(&input, "reverted");
}

#[test]
fn settlement_must_follow_its_buyers_funding() {
    let input = {
        let mut input = closed_loop_input(&LoopCfg::default());
        // Move the first settlement's timestamp to before the funding.
        let reference = input.settlements[0];
        let number = input.blocks[reference.block].header.number;
        input.blocks[reference.block] =
            settlement_block(number, 999, BUYERS[0], SELLER, 400_000_000, true);
        input
    };
    assert_rejects(&input, "not after its buyer's funding");
}

#[test]
fn funding_coverage_boundary_is_exact() {
    // Σ settle = 1_200_000_000; α_fund = 9_000 bps → funded ≥ 1_080_000_000.
    let mut cfg = LoopCfg::default();
    cfg.funded = vec![360_000_000, 360_000_000, 359_999_999];
    let input = closed_loop_input(&cfg);
    assert_rejects(&input, "funding below the coverage fraction");
}

#[test]
fn pre_period_capital_receives_no_ledger_credit() {
    // Aggregate funding sits exactly on α_fund, but each buyer settles 400
    // from only 360 of authenticated in-period funding. Hypothetical opening
    // balances are deliberately not part of the witness and cannot close the gap.
    let mut cfg = LoopCfg::default();
    cfg.funded = vec![360_000_000; 3];
    assert_rejects(&closed_loop_input(&cfg), "ledger");
}

#[test]
fn ledger_rejects_buyer_capital_beyond_tolerance() {
    // Buyer 0 ends the period with more protocol balance than the funder
    // provided: funded 400, settled 400, end balance 21 > 400·5% tolerance.
    let mut cfg = LoopCfg::default();
    cfg.end_balances = vec![21_000_000, 0, 0];
    assert_rejects(&closed_loop_input(&cfg), "ledger");

    // Exactly at tolerance passes: end + settled = 420 = funded · 1.05.
    let mut cfg = LoopCfg::default();
    cfg.end_balances = vec![20_000_000, 0, 0];
    verify_closed_loop(&closed_loop_input(&cfg)).unwrap();
}

#[test]
fn ledger_witnesses_are_mandatory() {
    let mut input = closed_loop_input(&LoopCfg::default());
    input.ledgers.clear();
    assert_rejects(&input, "exactly one witness per buyer required");
}

#[test]
fn ledger_witnesses_are_bound_to_the_period_end_block() {
    let mut input = closed_loop_input(&LoopCfg::default());
    input.ledgers[0].end.block = 0;
    assert_rejects(&input, "requires block");
}

#[test]
fn rebates_to_own_buyers_do_not_close_a_loop() {
    // The seller pays out — but to its buyers, not back to the funder.
    let mut cfg = LoopCfg::default();
    cfg.return_paths = vec![
        vec![(BUYERS[0], 400_000_000)],
        vec![(BUYERS[1], 400_000_000)],
        vec![(BUYERS[2], 400_000_000)],
    ];
    assert_rejects(&closed_loop_input(&cfg), "does not terminate at the funder");
}

#[test]
fn missing_or_short_return_is_rejected() {
    let mut cfg = LoopCfg::default();
    cfg.return_paths = vec![];
    assert_rejects(&closed_loop_input(&cfg), "below the coverage fraction");

    // Σ settle = 1_200_000_000; α_return = 3_000 bps → arrival ≥ 360_000_000.
    let mut cfg = LoopCfg::default();
    cfg.return_paths = vec![vec![(FUNDER, 360_000_000)]];
    verify_closed_loop(&closed_loop_input(&cfg)).unwrap();

    let mut cfg = LoopCfg::default();
    cfg.return_paths = vec![vec![(FUNDER, 359_999_999)]];
    assert_rejects(&closed_loop_input(&cfg), "below the coverage fraction");

    cfg.return_paths = vec![vec![(FUNDER, 240_000_000)]];
    assert_rejects(&closed_loop_input(&cfg), "below the coverage fraction");
}

#[test]
fn return_hop_retention_boundary_is_exact() {
    // ρ_hop = 2_800: a hop forwarding exactly 28% passes…
    let mut cfg = LoopCfg::default();
    cfg.return_paths = vec![vec![(RELAY, 2_200_000_000), (FUNDER, 616_000_000)]];
    verify_closed_loop(&closed_loop_input(&cfg)).unwrap();

    // …one unit less does not.
    let mut cfg = LoopCfg::default();
    cfg.return_paths = vec![vec![(RELAY, 2_200_000_000), (FUNDER, 615_999_999)]];
    assert_rejects(
        &closed_loop_input(&cfg),
        "retains more than the permitted share",
    );
}

#[test]
fn amplified_return_paths_credit_only_the_path_bottleneck() {
    let mut cfg = LoopCfg::default();
    cfg.funded = vec![10_000_000];
    cfg.settled = vec![10_000_000];
    cfg.buyers = vec![BUYERS[0]];
    cfg.end_balances = vec![0];
    cfg.return_paths = vec![vec![
        (RELAY, 8_000_000),
        (
            address!("00000000000000000000000000000000000000dd"),
            8_000_000,
        ),
        (FUNDER, 248_000_000),
    ]];
    verify_closed_loop(&closed_loop_input(&cfg)).unwrap();

    cfg.settled = vec![40_000_001];
    cfg.funded = vec![40_000_001];
    assert_rejects(
        &closed_loop_input(&cfg),
        "value reaching the funder below the coverage fraction",
    );
}

#[test]
fn return_path_time_bounds_are_enforced() {
    // Path must start after the earliest settlement…
    let mut input = closed_loop_input(&LoopCfg::default());
    let first_hop = input.returns[0].transfers[0];
    input.blocks[first_hop.block].header.timestamp = 1_999;
    assert_rejects(&input, "begins before the settlements");

    // …and complete within T_path.
    let mut input = closed_loop_input(&LoopCfg::default());
    let last_hop = *input.returns[0].transfers.last().unwrap();
    let first_hop = input.returns[0].transfers[0];
    let start = input.blocks[first_hop.block].header.timestamp;
    input.blocks[last_hop.block].header.timestamp = start + wash_predicate::T_PATH_SECONDS + 1;
    assert_rejects(&input, "exceeds the end-to-end window");
}

#[test]
fn self_funded_loop_needs_no_return_but_rejects_one() {
    // seller == funder == the recoverable signer.
    let mut cfg = LoopCfg::default();
    cfg.seller = FUNDER;
    cfg.funder = FUNDER;
    cfg.return_paths = vec![];
    let input = closed_loop_input(&cfg);
    let journal = verify_closed_loop(&input).unwrap();
    assert_eq!(journal.subjects[0].wash_volume, 1_200_000_000);
    assert_eq!(journal.subjects[0].subject, FUNDER);

    let mut cfg = LoopCfg::default();
    cfg.seller = FUNDER;
    cfg.funder = FUNDER;
    cfg.return_paths = vec![vec![(RELAY, 1_000_000_000)]];
    assert_rejects(
        &closed_loop_input(&cfg),
        "self-funded loop must not carry return paths",
    );
}

#[test]
fn funder_cannot_be_its_own_buyer() {
    let mut cfg = LoopCfg::default();
    let mut buyers = cfg.buyers.clone();
    buyers.push(FUNDER);
    buyers.sort();
    cfg.buyers = buyers;
    cfg.funded = vec![400_000_000; 4];
    cfg.settled = vec![400_000_000; 4];
    cfg.end_balances = vec![0; 4];
    assert_rejects(&closed_loop_input(&cfg), "funder cannot be its own buyer");
}

#[test]
fn a_single_funded_buyer_is_already_a_loop() {
    // No cohort-size or volume floor: tiny magnitudes prove all the same.
    let mut cfg = LoopCfg::default();
    cfg.buyers = vec![BUYERS[0]];
    cfg.funded = vec![2_000_000];
    cfg.settled = vec![2_000_000];
    cfg.end_balances = vec![0];
    cfg.return_paths = vec![vec![(FUNDER, 1_960_000)]];
    let journal = verify_closed_loop(&closed_loop_input(&cfg)).unwrap();
    assert_eq!(journal.subjects[0].wash_volume, 2_000_000);
}

#[test]
fn evidence_outside_the_period_is_rejected() {
    let mut input = closed_loop_input(&LoopCfg::default());
    input.blocks[0].header.number = PERIOD_START_BLOCK - 2;
    assert_rejects(&input, "outside the witness window");
}

#[test]
fn direct_usdc_funding_uses_the_authenticated_transfer_sender() {
    // Direct ERC-20 funding remains valid without a transaction proof because
    // contract custodians may emit the transfer while an operator signs.
    let mut input = closed_loop_input(&LoopCfg::default());
    input.blocks[0].transactions.clear();
    input.blocks[0].header.transactions_root = B256::ZERO;
    verify_closed_loop(&input).unwrap();

    // The authenticated Transfer sender is the funder even when the bundled
    // transaction was signed by a different operator.
    let other = address!("0000000000000000000000000000000000000099");
    let mut cfg = LoopCfg::default();
    cfg.funder = other;
    cfg.return_paths = vec![vec![(other, 960_000_000)]];
    verify_closed_loop(&closed_loop_input(&cfg)).unwrap();
}

#[test]
fn protocol_deposit_funding_is_accepted() {
    let mut input = closed_loop_input(&LoopCfg::default());
    // Replace buyer 0's direct transfer with a protocol deposit.
    let block = deposit_block(
        PERIOD_START_BLOCK,
        1_000,
        FUNDER,
        BUYERS[0],
        400_000_000,
        true,
    );
    input.blocks[0] = block;
    input.fundings[0] = FundingEvidence {
        buyer: BUYERS[0],
        kind: FundingKind::ProtocolDeposit {
            transfer: LogRef {
                block: 0,
                receipt: 0,
                log: 0,
            },
            deposited: LogRef {
                block: 0,
                receipt: 0,
                log: 1,
            },
        },
    };
    verify_closed_loop(&input).unwrap();

    // Deposited log naming a different buyer is rejected.
    let mut wrong = input.clone();
    wrong.blocks[0] = deposit_block(
        PERIOD_START_BLOCK,
        1_000,
        FUNDER,
        BUYERS[1],
        400_000_000,
        true,
    );
    assert_rejects(&wrong, "invalid protocol-deposit funding");
}

#[test]
fn native_funding_is_rejected_in_the_guest() {
    // SELLER is the raw transaction's `to`; use it as the funded buyer so the
    // native evidence itself is shape-valid.
    let mut cfg = LoopCfg::default();
    cfg.seller = address!("00000000000000000000000000000000000000bb");
    cfg.buyers = vec![SELLER];
    cfg.funded = vec![0];
    cfg.settled = vec![400_000_000];
    cfg.end_balances = vec![0];
    cfg.return_paths = vec![vec![(FUNDER, 320_000_000)]];
    let mut input = closed_loop_input(&cfg);
    // Swap the (empty-amount) USDC funding for a native transfer.
    let native = transfer_block(PERIOD_START_BLOCK, 1_000, FUNDER, SELLER, 1, true);
    input.blocks[0] = native;
    input.fundings[0] = FundingEvidence {
        buyer: SELLER,
        kind: FundingKind::Native {
            transaction: TransactionRef {
                block: 0,
                transaction: 0,
            },
            receipt: ReceiptRef {
                block: 0,
                receipt: 0,
            },
        },
    };
    input.ledgers.clear();
    assert_rejects(&input, "native funding is not supported");
}

#[test]
fn native_funding_is_rejected_even_when_usdc_evidence_is_present() {
    let mut input = closed_loop_input(&LoopCfg::default());
    input.blocks[0] = transfer_block(PERIOD_START_BLOCK, 1_000, FUNDER, BUYERS[0], 1, true);
    input.fundings[0].kind = FundingKind::Native {
        transaction: TransactionRef {
            block: 0,
            transaction: 0,
        },
        receipt: ReceiptRef {
            block: 0,
            receipt: 0,
        },
    };
    assert_rejects(&input, "native funding is not supported");
}

#[test]
fn every_buyer_must_be_funded() {
    let mut input = closed_loop_input(&LoopCfg::default());
    input.fundings.remove(2);
    assert_rejects(&input, "every buyer in the cohort must be funded");
}

#[test]
fn cohort_must_be_sorted_unique_nonzero() {
    let mut cfg = LoopCfg::default();
    cfg.buyers = vec![BUYERS[1], BUYERS[0], BUYERS[2]];
    assert_rejects(&closed_loop_input(&cfg), "sorted");
}
