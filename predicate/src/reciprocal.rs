//! P0_RECIPROCAL — proves the conserved loop in its circular form: a
//! normalized pair recycling one pool of capital between themselves, and
//! flags both wallets.
//!
//! What separates recycled capital from genuine two-way trade is
//! self-financing: two providers who buy from each other with independently
//! earned funds inject external capital proportional to their volume and are
//! therefore outside the predicate.

use crate::{
    authenticate_blocks, canonical_evidence_hash, ensure_event_in_period, meets_ratio,
    reciprocal_claim_id,
    resolver::{ChainResolver, LogKey},
    stats::verify_subject_stats,
    validate_chain, BuyerLedger, EvidenceBlock, LogRef, SellerStatsWitness, SubjectRecord,
    WashJournal, ALPHA_SELF_BPS, BASE_CHAIN_ID, BETA_RECIPROCAL_BPS,
    BUYER_ACCOUNT_BALANCE_OFFSET, DEPOSITS_ADDRESS, DEPOSITS_BUYERS_SLOT, PERIOD_END_BLOCK,
    PERIOD_LEDGER_START_BLOCK, PERIOD_START_BLOCK, RECIPROCAL_PREDICATE_ID,
};
use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A protocol deposit crediting one pair member, financed and signed by a
/// pair member — capital the pair moved into itself rather than raised
/// elsewhere.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairDepositEvidence {
    /// The buyer account credited (must be a pair member).
    pub member: Address,
    /// USDC transfer payer → Deposits in the deposit receipt.
    pub transfer: LogRef,
    /// `Deposited(member, amount)` in the same receipt.
    pub deposited: LogRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReciprocalInput {
    pub chain_id: u64,
    /// Normalized: `address_a < address_b`, both nonzero.
    pub address_a: Address,
    pub address_b: Address,
    pub blocks: Vec<EvidenceBlock>,
    /// Settlements in both directions between exactly this pair.
    pub settlements: Vec<LogRef>,
    /// Deposits into either member financed from within the pair.
    pub internal_deposits: Vec<PairDepositEvidence>,
    pub ledger_a: BuyerLedger,
    pub ledger_b: BuyerLedger,
    pub stats_a: SellerStatsWitness,
    pub stats_b: SellerStatsWitness,
}

pub fn verify_reciprocal(input: &ReciprocalInput) -> Result<WashJournal, String> {
    validate_chain(input.chain_id)?;
    if input.address_a == Address::ZERO
        || input.address_b == Address::ZERO
        || input.address_a >= input.address_b
    {
        return Err("reciprocal: pair must be nonzero and normalized".into());
    }
    let block_refs = authenticate_blocks(&input.blocks)?;
    let resolver = ChainResolver { blocks: &input.blocks };
    let mut used_logs: BTreeSet<LogKey> = BTreeSet::new();

    // ── Measurement: settled volume in each direction ─────────────────────
    if input.settlements.is_empty() {
        return Err("reciprocal: no settlements referenced".into());
    }
    let (mut sells_a, mut sells_b) = (0u128, 0u128);
    for reference in &input.settlements {
        let key = resolver.log_key(*reference)?;
        if !used_logs.insert(key) {
            return Err("reciprocal: duplicate settlement evidence".into());
        }
        let (_, buyer, seller, amount, block) = resolver.settlement(*reference)?;
        ensure_event_in_period(block, "reciprocal settlement")?;
        if amount == 0 {
            return Err("reciprocal: zero settlement".into());
        }
        if buyer == input.address_b && seller == input.address_a {
            sells_a = sells_a.checked_add(amount).ok_or("reciprocal: overflow")?;
        } else if buyer == input.address_a && seller == input.address_b {
            sells_b = sells_b.checked_add(amount).ok_or("reciprocal: overflow")?;
        } else {
            return Err("reciprocal: settlement outside the exact pair".into());
        }
    }
    let total = sells_a.checked_add(sells_b).ok_or("reciprocal: overflow")?;

    // ── Reciprocity: neither side is a net seller at scale ────────────────
    let (low, high) = (sells_a.min(sells_b), sells_a.max(sells_b));
    if !meets_ratio(low, high, BETA_RECIPROCAL_BPS) {
        return Err("reciprocal: directional volumes are not reciprocal".into());
    }

    // ── Pair-internal financing evidence ──────────────────────────────────
    let mut internal_total = 0u128;
    for evidence in &input.internal_deposits {
        if evidence.member != input.address_a && evidence.member != input.address_b {
            return Err("reciprocal: deposit credited outside the pair".into());
        }
        if evidence.transfer.block != evidence.deposited.block
            || evidence.transfer.receipt != evidence.deposited.receipt
        {
            return Err("reciprocal: deposit logs must share one receipt".into());
        }
        let transfer_key = resolver.log_key(evidence.transfer)?;
        let deposited_key = resolver.log_key(evidence.deposited)?;
        if transfer_key >= deposited_key {
            return Err("reciprocal: transfer must precede its Deposited log".into());
        }
        if !used_logs.insert(transfer_key) || !used_logs.insert(deposited_key) {
            return Err("reciprocal: duplicate deposit evidence".into());
        }
        let (from, to, transferred, block) = resolver.usdc_transfer(evidence.transfer)?;
        ensure_event_in_period(block, "pair deposit")?;
        let (deposit_buyer, deposited_amount, _) = resolver.protocol_deposit(evidence.deposited)?;
        if to != DEPOSITS_ADDRESS
            || deposit_buyer != evidence.member
            || transferred != deposited_amount
            || deposited_amount == 0
            || (from != input.address_a && from != input.address_b)
        {
            return Err("reciprocal: invalid pair deposit".into());
        }
        // Attribution by signer recovery: the deposit transaction must be
        // sent by the wallet whose USDC financed it.
        resolver.require_signer(from, evidence.transfer)?;
        internal_total =
            internal_total.checked_add(deposited_amount).ok_or("reciprocal: overflow")?;
    }

    // ── Self-financing (LEDGER): external inflow ≤ (1 − α_self) · total ───
    //
    //   Σ_w (balance_end + boughtₑᵥ)  ≤  Σ_w balance_start
    //                                    + internal deposits
    //                                    + (1 − α_self) · total
    //
    // Each wallet's bought volume equals the other's sold volume, so
    // Σ_w boughtₑᵥ = total.
    let balance =
        |ledger: &BuyerLedger, member: Address| -> Result<(U256, U256), String> {
            let slot = loop_core::slot_offset(
                loop_core::mapping_slot_address(member, DEPOSITS_BUYERS_SLOT),
                BUYER_ACCOUNT_BALANCE_OFFSET,
            );
            Ok((
                resolver.storage_value(
                    &ledger.start,
                    PERIOD_LEDGER_START_BLOCK,
                    DEPOSITS_ADDRESS,
                    slot,
                )?,
                resolver.storage_value(&ledger.end, PERIOD_END_BLOCK, DEPOSITS_ADDRESS, slot)?,
            ))
        };
    let (start_a, end_a) = balance(&input.ledger_a, input.address_a)?;
    let (start_b, end_b) = balance(&input.ledger_b, input.address_b)?;
    let lhs = (end_a + end_b + U256::from(total)) * U256::from(10_000u64);
    let rhs = (start_a + start_b + U256::from(internal_total)) * U256::from(10_000u64)
        + U256::from(total) * U256::from(10_000 - ALPHA_SELF_BPS);
    if lhs > rhs {
        return Err("reciprocal: pair volume financed by external capital".into());
    }

    // ── Denominators for both subjects ────────────────────────────────────
    let settled_a = verify_subject_stats(&resolver, input.address_a, &input.stats_a)?;
    let settled_b = verify_subject_stats(&resolver, input.address_b, &input.stats_b)?;

    Ok(WashJournal {
        predicate_id: RECIPROCAL_PREDICATE_ID,
        chain_id: BASE_CHAIN_ID,
        period_start_block: PERIOD_START_BLOCK,
        period_end_block: PERIOD_END_BLOCK,
        claim_id: reciprocal_claim_id(
            input.address_a,
            input.address_b,
            canonical_evidence_hash(input)?,
        ),
        subjects: vec![
            SubjectRecord {
                subject: input.address_a,
                wash_volume: sells_a,
                settled_volume: settled_a,
            },
            SubjectRecord {
                subject: input.address_b,
                wash_volume: sells_b,
                settled_volume: settled_b,
            },
        ],
        block_refs,
    })
}
