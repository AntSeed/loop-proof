//! P0_CLOSED_LOOP — proves a conserved value loop F → B → S → F and flags
//! the seller S.

use crate::{
    authenticate_blocks, canonical_evidence_hash, closed_loop_claim_id, cohort_hash,
    ensure_event_in_period, meets_ratio,
    resolver::{ChainResolver, LogKey},
    settlement_id, validate_chain, validate_sorted_unique_addresses, BuyerLedger, EvidenceBlock,
    FundingEvidence, FundingKind, LogRef, ReturnPath, SettlementRecord, SubjectRecord, WashJournal,
    ALPHA_FUND_BPS, ALPHA_RETURN_BPS, BASE_CHAIN_ID, BUYER_ACCOUNT_BALANCE_OFFSET,
    CLOSED_LOOP_PREDICATE_ID, DEPOSITS_ADDRESS, DEPOSITS_BUYERS_SLOT, EPSILON_LEDGER_BPS,
    H_MAX_INTERMEDIATE_HOPS, MAX_BUYERS, MAX_RETURN_PATHS, RHO_HOP_BPS, T_PATH_SECONDS,
};
use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClosedLoopInput {
    pub chain_id: u64,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub source_claim_id: B256,
    pub seller: Address,
    pub funder: Address,
    /// Sorted, unique, nonzero; must not contain the funder. May contain the
    /// seller (a seller buying from itself is a loop shape, not an excuse).
    pub buyers: Vec<Address>,
    pub blocks: Vec<EvidenceBlock>,
    pub fundings: Vec<FundingEvidence>,
    pub settlements: Vec<LogRef>,
    /// Empty iff `seller == funder` (the return leg holds by identity).
    pub returns: Vec<ReturnPath>,
    /// Exactly one authenticated ledger witness per buyer, in `buyers` order.
    pub ledgers: Vec<BuyerLedger>,
}

pub fn verify_closed_loop(input: &ClosedLoopInput) -> Result<WashJournal, String> {
    validate_chain(input.chain_id)?;
    if input.period_start_block == 0 || input.period_start_block > input.period_end_block {
        return Err("closed loop: invalid period".into());
    }
    if input.seller == Address::ZERO || input.funder == Address::ZERO {
        return Err("closed loop: zero seller or funder".into());
    }
    // No minimum cohort size: one funded buyer in a conserved circuit is
    // already a proven loop.
    validate_sorted_unique_addresses(&input.buyers, 1, MAX_BUYERS, "buyers")?;
    if input.buyers.binary_search(&input.funder).is_ok() {
        return Err("closed loop: funder cannot be its own buyer".into());
    }

    let block_refs = authenticate_blocks(
        &input.blocks,
        input.period_start_block,
        input.period_end_block,
    )?;
    let resolver = ChainResolver {
        blocks: &input.blocks,
    };
    let mut used_logs: BTreeSet<LogKey> = BTreeSet::new();
    let mut used_transactions: BTreeSet<(u64, u64)> = BTreeSet::new();

    // ── FUND ──────────────────────────────────────────────────────────────
    let funding = verify_fundings(input, &resolver, &mut used_logs, &mut used_transactions)?;

    // ── SETTLE (measurement + ordering) ───────────────────────────────────
    let settle = verify_settlements(input, &resolver, &funding, &mut used_logs)?;

    // ── Funding coverage: Σ FUND ≥ α_fund · Σ SETTLE ──────────────────────
    if funding.native_mode {
        if !input.ledgers.is_empty() {
            return Err("ledger: native funding must not include USDC ledgers".into());
        }
    } else {
        if !meets_ratio(funding.total_usdc, settle.total, ALPHA_FUND_BPS) {
            return Err("closed loop: funding below the coverage fraction".into());
        }

        // ── Attribution (LEDGER) ──────────────────────────────────────────
        verify_ledgers(input, &resolver, &funding, &settle)?;
    }

    // ── RETURN ────────────────────────────────────────────────────────────
    verify_returns(input, &resolver, &settle, &mut used_logs)?;

    Ok(WashJournal {
        predicate_id: CLOSED_LOOP_PREDICATE_ID,
        chain_id: BASE_CHAIN_ID,
        period_start_block: input.period_start_block,
        period_end_block: input.period_end_block,
        source_claim_id: input.source_claim_id,
        claim_id: closed_loop_claim_id(
            input.period_start_block,
            input.period_end_block,
            input.seller,
            input.funder,
            cohort_hash(&input.buyers),
            canonical_evidence_hash(input)?,
        ),
        subjects: vec![SubjectRecord {
            subject: input.seller,
            wash_volume: settle.total,
            settlements: settle.settlements,
        }],
        block_refs,
    })
}

struct FundingSummary {
    /// USDC-denominated funding per buyer (forms Usdc + ProtocolDeposit).
    usdc_per_buyer: BTreeMap<Address, u128>,
    total_usdc: u128,
    /// Earliest funding timestamp per buyer — settlements must come after.
    earliest_time: BTreeMap<Address, u64>,
    native_mode: bool,
}

fn verify_fundings(
    input: &ClosedLoopInput,
    resolver: &ChainResolver<'_>,
    used_logs: &mut BTreeSet<LogKey>,
    used_transactions: &mut BTreeSet<(u64, u64)>,
) -> Result<FundingSummary, String> {
    let cohort: BTreeSet<Address> = input.buyers.iter().copied().collect();
    let has_native = input
        .fundings
        .iter()
        .any(|evidence| matches!(evidence.kind, FundingKind::Native { .. }));
    let has_usdc = input
        .fundings
        .iter()
        .any(|evidence| !matches!(evidence.kind, FundingKind::Native { .. }));
    if has_native && has_usdc {
        return Err("funding: cannot mix native and USDC evidence".into());
    }
    let mut summary = FundingSummary {
        usdc_per_buyer: BTreeMap::new(),
        total_usdc: 0,
        earliest_time: BTreeMap::new(),
        native_mode: has_native,
    };
    for evidence in &input.fundings {
        if !cohort.contains(&evidence.buyer) {
            return Err("funding: buyer outside the cohort".into());
        }
        let (usdc_amount, time) = match evidence.kind {
            FundingKind::Usdc { transfer } => {
                let key = resolver.log_key(transfer)?;
                if !used_logs.insert(key) {
                    return Err("funding: duplicate evidence".into());
                }
                let (from, to, amount, block) = resolver.usdc_transfer(transfer)?;
                ensure_event_in_period(
                    block,
                    input.period_start_block,
                    input.period_end_block,
                    "funding transfer",
                )?;
                if from != input.funder || to != evidence.buyer || amount == 0 {
                    return Err("funding: invalid direct USDC funding".into());
                }
                resolver.require_signer(input.funder, transfer)?;
                (amount, resolver.timestamp(transfer)?)
            }
            FundingKind::ProtocolDeposit {
                transfer,
                deposited,
            } => {
                if transfer.block != deposited.block || transfer.receipt != deposited.receipt {
                    return Err("funding: deposit logs must share one receipt".into());
                }
                let transfer_key = resolver.log_key(transfer)?;
                let deposited_key = resolver.log_key(deposited)?;
                if transfer_key >= deposited_key {
                    return Err("funding: transfer must precede its Deposited log".into());
                }
                if !used_logs.insert(transfer_key) || !used_logs.insert(deposited_key) {
                    return Err("funding: duplicate evidence".into());
                }
                let (from, to, transferred, block) = resolver.usdc_transfer(transfer)?;
                ensure_event_in_period(
                    block,
                    input.period_start_block,
                    input.period_end_block,
                    "funding deposit",
                )?;
                let (deposit_buyer, deposited_amount, _) = resolver.protocol_deposit(deposited)?;
                if from != input.funder
                    || to != DEPOSITS_ADDRESS
                    || deposit_buyer != evidence.buyer
                    || transferred != deposited_amount
                    || deposited_amount == 0
                {
                    return Err("funding: invalid protocol-deposit funding".into());
                }
                resolver.require_signer(input.funder, transfer)?;
                (deposited_amount, resolver.timestamp(transfer)?)
            }
            FundingKind::Native {
                transaction,
                receipt,
            } => {
                let (receipt_proof, receipt_block) = resolver.receipt(receipt)?;
                if !loop_core::receipt_success(&receipt_proof.value)? {
                    return Err("funding: native funding receipt reverted".into());
                }
                let (envelope, signer, transaction_block) =
                    resolver.decoded_transaction(transaction)?;
                let (transaction_proof, _) = resolver.transaction(transaction)?;
                if receipt.block != transaction.block
                    || receipt_proof.tx_index != transaction_proof.tx_index
                    || receipt_block.header.number != transaction_block.header.number
                {
                    return Err("funding: native receipt/transaction mismatch".into());
                }
                ensure_event_in_period(
                    transaction_block.header.number,
                    input.period_start_block,
                    input.period_end_block,
                    "native funding",
                )?;
                if !used_transactions
                    .insert((transaction_block.header.number, transaction_proof.tx_index))
                {
                    return Err("funding: duplicate evidence".into());
                }
                use alloy_consensus::Transaction;
                if signer != input.funder
                    || envelope.to() != Some(evidence.buyer)
                    || envelope.value().is_zero()
                {
                    return Err("funding: invalid native funding".into());
                }
                // Native value is a different unit: it establishes funding
                // order and shape but never counts toward USDC sums.
                (0, transaction_block.header.timestamp)
            }
        };
        if usdc_amount > 0 {
            let per = summary.usdc_per_buyer.entry(evidence.buyer).or_default();
            *per = per.checked_add(usdc_amount).ok_or("funding: overflow")?;
            summary.total_usdc = summary
                .total_usdc
                .checked_add(usdc_amount)
                .ok_or("funding: overflow")?;
        }
        summary
            .earliest_time
            .entry(evidence.buyer)
            .and_modify(|t| *t = (*t).min(time))
            .or_insert(time);
    }
    for buyer in &input.buyers {
        if !summary.earliest_time.contains_key(buyer) {
            return Err("funding: every buyer in the cohort must be funded".into());
        }
    }
    Ok(summary)
}

struct SettleSummary {
    total: u128,
    per_buyer: BTreeMap<Address, u128>,
    earliest_time: u64,
    settlements: Vec<SettlementRecord>,
}

fn verify_settlements(
    input: &ClosedLoopInput,
    resolver: &ChainResolver<'_>,
    funding: &FundingSummary,
    used_logs: &mut BTreeSet<LogKey>,
) -> Result<SettleSummary, String> {
    if input.settlements.is_empty() {
        return Err("settlements: none referenced".into());
    }
    let cohort: BTreeSet<Address> = input.buyers.iter().copied().collect();
    let mut total = 0u128;
    let mut per_buyer = BTreeMap::<Address, u128>::new();
    let mut earliest_time = u64::MAX;
    let mut settlements = Vec::with_capacity(input.settlements.len());
    for reference in &input.settlements {
        let key = resolver.log_key(*reference)?;
        if !used_logs.insert(key) {
            return Err("settlements: duplicate evidence".into());
        }
        let (_, buyer, seller, amount, block) = resolver.settlement(*reference)?;
        ensure_event_in_period(
            block,
            input.period_start_block,
            input.period_end_block,
            "settlement",
        )?;
        if seller != input.seller || !cohort.contains(&buyer) || amount == 0 {
            return Err("settlements: subject or amount mismatch".into());
        }
        let time = resolver.timestamp(*reference)?;
        if time <= funding.earliest_time[&buyer] {
            return Err("settlements: settlement is not after its buyer's funding".into());
        }
        total = total.checked_add(amount).ok_or("settlements: overflow")?;
        settlements.push(SettlementRecord {
            settlement_id: settlement_id(BASE_CHAIN_ID, key.0, key.1, key.2),
            amount,
        });
        let per = per_buyer.entry(buyer).or_default();
        *per = per.checked_add(amount).ok_or("settlements: overflow")?;
        earliest_time = earliest_time.min(time);
    }
    Ok(SettleSummary {
        total,
        per_buyer,
        earliest_time,
        settlements,
    })
}

/// Attribution: for each buyer, the capital it settled with must be the
/// funder's, reconciled against the protocol's own accounting at the period
/// end. Opening balances receive no credit, so only authenticated in-period
/// funding can finance the selected settlements:
///
///   balance_end + settledₑᵥ  ≤  funded · (1 + ε_ledger)
///
/// Any protocol capital beyond what the funder demonstrably provided breaks
/// the inequality and rejects the claim. Pre-period capital can therefore
/// cause a false negative, but can never make the predicate easier to satisfy.
fn verify_ledgers(
    input: &ClosedLoopInput,
    resolver: &ChainResolver<'_>,
    funding: &FundingSummary,
    settle: &SettleSummary,
) -> Result<(), String> {
    if input.ledgers.len() != input.buyers.len() {
        return Err("ledger: exactly one witness per buyer required".into());
    }
    for (buyer, ledger) in input.buyers.iter().zip(&input.ledgers) {
        let slot = loop_core::slot_offset(
            loop_core::mapping_slot_address(*buyer, DEPOSITS_BUYERS_SLOT),
            BUYER_ACCOUNT_BALANCE_OFFSET,
        );
        let balance_end =
            resolver.storage_value(&ledger.end, input.period_end_block, DEPOSITS_ADDRESS, slot)?;
        let settled = settle.per_buyer.get(buyer).copied().unwrap_or(0);
        let funded = funding.usdc_per_buyer.get(buyer).copied().unwrap_or(0);
        let lhs = (balance_end + U256::from(settled)) * U256::from(10_000u64);
        let rhs = U256::from(funded) * U256::from(10_000 + EPSILON_LEDGER_BPS);
        if lhs > rhs {
            return Err(
                "ledger: buyer inflow exceeds funder-attributed capital beyond tolerance".into(),
            );
        }
    }
    Ok(())
}

/// RETURN: value paths seller → … → funder, each hop retaining ρ_hop, each
/// path completing within T_path, together carrying α_return of the settled
/// volume back to the funder. When seller == funder the leg holds by
/// identity.
fn verify_returns(
    input: &ClosedLoopInput,
    resolver: &ChainResolver<'_>,
    settle: &SettleSummary,
    used_logs: &mut BTreeSet<LogKey>,
) -> Result<(), String> {
    if input.seller == input.funder {
        if !input.returns.is_empty() {
            return Err("return: self-funded loop must not carry return paths".into());
        }
        return Ok(());
    }
    if input.returns.len() > MAX_RETURN_PATHS {
        return Err("return: too many paths".into());
    }
    let mut returned = 0u128;
    for path in &input.returns {
        if path.transfers.is_empty() || path.transfers.len() > H_MAX_INTERMEDIATE_HOPS + 1 {
            return Err("return: path length outside witness bounds".into());
        }
        let mut expected_from = input.seller;
        let mut previous_amount: Option<u128> = None;
        let mut previous_key: Option<LogKey> = None;
        let mut first_time = 0u64;
        let mut path_credit = u128::MAX;
        for (position, reference) in path.transfers.iter().enumerate() {
            let key = resolver.log_key(*reference)?;
            if !used_logs.insert(key) {
                return Err("return: duplicate evidence".into());
            }
            let (from, to, amount, block) = resolver.usdc_transfer(*reference)?;
            ensure_event_in_period(
                block,
                input.period_start_block,
                input.period_end_block,
                "return transfer",
            )?;
            let time = resolver.timestamp(*reference)?;
            if from != expected_from || from == to || amount == 0 {
                return Err("return: broken path".into());
            }
            if let Some(previous) = previous_key {
                if key <= previous {
                    return Err("return: path is not time-ordered".into());
                }
            }
            if let Some(previous) = previous_amount {
                // Each hop forwards at least ρ_hop of what it received.
                if !crate::meets_ratio(amount, previous, RHO_HOP_BPS) {
                    return Err("return: hop retains more than the permitted share".into());
                }
            }
            if position == 0 {
                // Ordering: a return element closes settlements, so it must
                // come strictly after the earliest counted settlement.
                if time <= settle.earliest_time {
                    return Err("return: path begins before the settlements it closes".into());
                }
                first_time = time;
            } else if time.saturating_sub(first_time) > T_PATH_SECONDS {
                return Err("return: path exceeds the end-to-end window".into());
            }
            expected_from = to;
            previous_amount = Some(amount);
            previous_key = Some(key);
            path_credit = path_credit.min(amount);
        }
        if expected_from != input.funder {
            return Err("return: path does not terminate at the funder".into());
        }
        returned = returned
            .checked_add(path_credit)
            .ok_or("return: overflow")?;
    }
    if !meets_ratio(returned, settle.total, ALPHA_RETURN_BPS) {
        return Err("return: value reaching the funder below the coverage fraction".into());
    }
    Ok(())
}
