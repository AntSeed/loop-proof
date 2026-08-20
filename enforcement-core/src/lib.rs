use alloy_consensus::{transaction::SignerRecoverable, Header, Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{address, keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolValue;
use loop_core::{
    receipt_log, trie_index_key, verify_receipt_inclusion, ReceiptProof, CHANNEL_SETTLED_TOPIC,
    TRANSFER_TOPIC,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const PREDICATE_VERSION: u32 = 1;
pub const BASE_CHAIN_ID: u64 = 8_453;
pub const USDC_ADDRESS: Address = address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
pub const CHANNELS_ADDRESS: Address = address!("BA66d3b4fbCf472F6F11D6F9F96aaCE96516F09d");
pub const DEPOSITS_ADDRESS: Address = address!("0F7a3a8f4Da01637d1202bb5443fcF7F88F99fD2");
pub const PENALTY_BPS: u16 = 9_000;
pub const MINIMUM_BUYERS: usize = 3;
pub const MINIMUM_VOLUME_RAW: u128 = 1_000_000_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MerkleStep {
    pub sibling: B256,
    pub sibling_on_left: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MembershipProof {
    pub steps: Vec<MerkleStep>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LogRef {
    pub block: usize,
    pub receipt: usize,
    pub log: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TransactionRef {
    pub block: usize,
    pub transaction: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionProof {
    pub tx_index: u64,
    pub value: Bytes,
    pub proof: Vec<Bytes>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnforcementBlock {
    pub header: Header,
    pub receipts: Vec<ReceiptProof>,
    pub transactions: Vec<TransactionProof>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EvidenceLocation {
    Log(LogRef),
    UsdcDeposit {
        transfer: LogRef,
        deposited: LogRef,
    },
    NativeTransaction(TransactionRef),
    RelayPath {
        seller_payment: LogRef,
        relay_forward: LogRef,
        funder_receipt: LogRef,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SelectedEvidence {
    pub dependency_leaf: Bytes,
    pub dependency_membership: MembershipProof,
    pub location: EvidenceLocation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CohortInput {
    pub chain_id: u64,
    pub usdc: Address,
    pub channels: Address,
    pub deposits: Address,
    pub report_root: B256,
    pub claim_leaf: Bytes,
    pub claim_membership: MembershipProof,
    pub blocks: Vec<EnforcementBlock>,
    pub evidence: Vec<SelectedEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReciprocalInput {
    pub chain_id: u64,
    pub channels: Address,
    pub report_root: B256,
    pub claim_leaf: Bytes,
    pub claim_membership: MembershipProof,
    pub blocks: Vec<EnforcementBlock>,
    pub evidence: Vec<SelectedEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CohortJournal {
    pub predicate_version: u32,
    pub claim_type: u8,
    pub claim_id: B256,
    pub report_root: B256,
    pub seller: Address,
    pub penalty_bps: u16,
    pub linked_buyer_count: u32,
    pub qualified_volume_raw: u128,
    pub block_refs: Vec<(u64, B256)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReciprocalJournal {
    pub predicate_version: u32,
    pub claim_id: B256,
    pub report_root: B256,
    pub seller_a: Address,
    pub seller_b: Address,
    pub penalty_bps: u16,
    pub settlement_count: u32,
    pub qualified_volume_raw: u128,
    pub block_refs: Vec<(u64, B256)>,
}

alloy_sol_types::sol! {
    struct SolBlockRef { uint64 number; bytes32 blockHash; }
    struct SolCohortJournal {
        uint32 predicateVersion;
        uint8 claimType;
        bytes32 claimId;
        bytes32 reportRoot;
        address seller;
        uint16 penaltyBps;
        uint32 linkedBuyerCount;
        uint128 qualifiedVolumeRaw;
        SolBlockRef[] blockRefs;
    }
    struct SolReciprocalJournal {
        uint32 predicateVersion;
        bytes32 claimId;
        bytes32 reportRoot;
        address sellerA;
        address sellerB;
        uint16 penaltyBps;
        uint32 settlementCount;
        uint128 qualifiedVolumeRaw;
        SolBlockRef[] blockRefs;
    }
}

impl CohortJournal {
    pub fn abi_encode(&self) -> Vec<u8> {
        SolCohortJournal {
            predicateVersion: self.predicate_version,
            claimType: self.claim_type,
            claimId: self.claim_id,
            reportRoot: self.report_root,
            seller: self.seller,
            penaltyBps: self.penalty_bps,
            linkedBuyerCount: self.linked_buyer_count,
            qualifiedVolumeRaw: self.qualified_volume_raw,
            blockRefs: self
                .block_refs
                .iter()
                .map(|(number, block_hash)| SolBlockRef {
                    number: *number,
                    blockHash: *block_hash,
                })
                .collect(),
        }
        .abi_encode()
    }
}

impl ReciprocalJournal {
    pub fn abi_encode(&self) -> Vec<u8> {
        SolReciprocalJournal {
            predicateVersion: self.predicate_version,
            claimId: self.claim_id,
            reportRoot: self.report_root,
            sellerA: self.seller_a,
            sellerB: self.seller_b,
            penaltyBps: self.penalty_bps,
            settlementCount: self.settlement_count,
            qualifiedVolumeRaw: self.qualified_volume_raw,
            blockRefs: self
                .block_refs
                .iter()
                .map(|(number, block_hash)| SolBlockRef {
                    number: *number,
                    blockHash: *block_hash,
                })
                .collect(),
        }
        .abi_encode()
    }
}

pub fn verify_cohort(input: &CohortInput) -> Result<CohortJournal, String> {
    validate_configuration(input.chain_id, input.usdc, input.channels, input.deposits)?;
    let claim = verify_claim(
        &input.claim_leaf,
        &input.claim_membership,
        input.report_root,
    )?;
    let claim_type = string_field(&claim, "type")?;
    let claim_type_code = match claim_type {
        "P0_CLOSED_LOOP" => 1,
        "P1_COORDINATED_CONTROL" => 2,
        _ => return Err("cohort: wrong claim type".into()),
    };
    let seller = address_field(&claim, "seller")?;
    let claim_id = b256_field(&claim, "claimId")?;
    let dependency_root = b256_field(&claim, "dependencyRoot")?;
    let approved_buyers = address_array(&claim, "approvedBuyers")?;
    let approved_funders = address_array(&claim, "approvedFunders")?;
    let (period_start, period_end_exclusive) = period_bounds(&claim)?;
    if approved_buyers.is_empty() || approved_funders.is_empty() {
        return Err("cohort: empty approved buyer or funder set".into());
    }

    let block_refs = authenticate_blocks(&input.blocks)?;
    let resolver = Resolver {
        blocks: &input.blocks,
    };
    let mut funding_block_by_buyer = BTreeMap::<Address, u64>::new();
    let mut settlement_buyers = BTreeSet::new();
    let mut used_chain_evidence = BTreeSet::new();
    let mut used_dependencies = BTreeSet::new();
    let mut qualified_volume_raw = 0u128;
    let mut cohort_funder = None;
    let mut direct_funder_closures = BTreeSet::new();
    let mut direct_buyer_closures = BTreeSet::new();
    let mut relay_path_funders = Vec::new();

    for selected in &input.evidence {
        let dependency_id = dependency_hash(&selected.dependency_leaf);
        if !used_dependencies.insert(dependency_id) {
            return Err("duplicate report dependency".into());
        }
        let dependency = verify_dependency(selected, dependency_root)?;
        let evidence_type = string_field(&dependency, "evidenceType")?;
        match (evidence_type, &selected.location) {
            ("USDC_FUNDING", EvidenceLocation::Log(reference)) => {
                ensure_unique(&mut used_chain_evidence, resolver.log_identity(*reference)?)?;
                let buyer = address_field(&dependency, "buyer")?;
                let funder = address_field(&dependency, "funder")?;
                ensure_approved(&approved_buyers, buyer)?;
                set_cohort_funder(&mut cohort_funder, &approved_funders, funder)?;
                resolver.bind_log_dependency(&dependency, *reference)?;
                let expected_value = decimal_u128_field(&dependency, "amountRaw")?;
                let (from, to, value, block) = resolver.usdc_transfer(*reference, input.usdc)?;
                if from != funder || to != buyer || value == 0 || value != expected_value {
                    return Err("cohort: invalid direct USDC funding".into());
                }
                funding_block_by_buyer
                    .entry(buyer)
                    .and_modify(|current| *current = (*current).min(block))
                    .or_insert(block);
            }
            (
                "USDC_FUNDING",
                EvidenceLocation::UsdcDeposit {
                    transfer,
                    deposited,
                },
            ) => {
                ensure_unique(&mut used_chain_evidence, resolver.log_identity(*transfer)?)?;
                ensure_unique(&mut used_chain_evidence, resolver.log_identity(*deposited)?)?;
                let buyer = address_field(&dependency, "buyer")?;
                let funder = address_field(&dependency, "funder")?;
                ensure_approved(&approved_buyers, buyer)?;
                set_cohort_funder(&mut cohort_funder, &approved_funders, funder)?;
                resolver.bind_log_dependency(&dependency, *transfer)?;
                let expected_value = decimal_u128_field(&dependency, "amountRaw")?;
                if optional_string_field(&dependency, "fundingKind")?
                    .is_some_and(|kind| kind != "protocol_deposit")
                {
                    return Err("cohort: deposit dependency has wrong funding kind".into());
                }
                let (from, to, value, block) = resolver.usdc_transfer(*transfer, input.usdc)?;
                if from != funder || to != input.deposits || value == 0 || value != expected_value {
                    return Err("cohort: invalid deposit transfer".into());
                }
                let (log, deposit_block) = resolver.receipt_log(*deposited)?;
                if transfer.block != deposited.block
                    || transfer.receipt != deposited.receipt
                    || deposit_block != block
                    || log.address != input.deposits
                    || log.topics.len() != 2
                    || log.topics[0] != loop_core::DEPOSITED_TOPIC
                    || topic_address(&log.topics[1]) != buyer
                    || log.data.len() != 32
                    || u128::try_from(U256::from_be_slice(&log.data))
                        .map_err(|_| "deposit value overflow")?
                        != value
                {
                    return Err("cohort: invalid Deposited event".into());
                }
                funding_block_by_buyer
                    .entry(buyer)
                    .and_modify(|current| *current = (*current).min(block))
                    .or_insert(block);
            }
            ("NATIVE_FUNDING", EvidenceLocation::NativeTransaction(reference)) => {
                ensure_unique(
                    &mut used_chain_evidence,
                    resolver.transaction_identity(*reference)?,
                )?;
                let buyer = address_field(&dependency, "buyer")?;
                let funder = address_field(&dependency, "funder")?;
                ensure_approved(&approved_buyers, buyer)?;
                set_cohort_funder(&mut cohort_funder, &approved_funders, funder)?;
                resolver.bind_transaction_dependency(&dependency, *reference)?;
                let expected_value = decimal_u256_field(&dependency, "amountWei")?;
                let (from, to, value, block) = resolver.native_transaction(*reference)?;
                if from != funder || to != buyer || value == U256::ZERO || value != expected_value {
                    return Err("cohort: invalid native funding".into());
                }
                funding_block_by_buyer
                    .entry(buyer)
                    .and_modify(|current| *current = (*current).min(block))
                    .or_insert(block);
            }
            ("SETTLEMENT", EvidenceLocation::Log(reference)) => {
                ensure_unique(&mut used_chain_evidence, resolver.log_identity(*reference)?)?;
                let buyer = address_field(&dependency, "buyer")?;
                let expected_seller = address_field(&dependency, "seller")?;
                let expected_amount = decimal_u128_field(&dependency, "amountRaw")?;
                let expected_channel = b256_field(&dependency, "channelId")?;
                ensure_approved(&approved_buyers, buyer)?;
                let funding_block = *funding_block_by_buyer
                    .get(&buyer)
                    .ok_or("cohort: settlement buyer is not funded")?;
                resolver.bind_log_dependency(&dependency, *reference)?;
                let (channel, actual_buyer, actual_seller, amount, block) =
                    resolver.settlement(*reference, input.channels)?;
                ensure_positive_settlement(amount, "cohort")?;
                if block < period_start || block >= period_end_exclusive {
                    return Err("cohort: settlement outside approved period".into());
                }
                if channel != expected_channel
                    || actual_buyer != buyer
                    || actual_seller != seller
                    || expected_seller != seller
                    || amount != expected_amount
                    || block <= funding_block
                {
                    return Err("cohort: invalid post-funding settlement".into());
                }
                settlement_buyers.insert(buyer);
                qualified_volume_raw = qualified_volume_raw
                    .checked_add(amount)
                    .ok_or("cohort: volume overflow")?;
            }
            ("DIRECT_SELLER_FUNDER", EvidenceLocation::Log(reference)) => {
                ensure_unique(&mut used_chain_evidence, resolver.log_identity(*reference)?)?;
                let dependency_seller = address_field(&dependency, "seller")?;
                let funder = address_field(&dependency, "funder")?;
                ensure_approved(&approved_funders, funder)?;
                resolver.bind_log_dependency(&dependency, *reference)?;
                let (from, to, value, _) = resolver.usdc_transfer(*reference, input.usdc)?;
                if dependency_seller != seller
                    || from != address_field(&dependency, "from")?
                    || to != address_field(&dependency, "to")?
                    || value != decimal_u128_field(&dependency, "amountRaw")?
                    || value == 0
                    || !((from == seller && to == funder) || (from == funder && to == seller))
                {
                    return Err("cohort: invalid direct seller-funder closure".into());
                }
                direct_funder_closures.insert(funder);
            }
            ("DIRECT_SELLER_BUYER", EvidenceLocation::Log(reference)) => {
                ensure_unique(&mut used_chain_evidence, resolver.log_identity(*reference)?)?;
                let dependency_seller = address_field(&dependency, "seller")?;
                let buyer = address_field(&dependency, "buyer")?;
                ensure_approved(&approved_buyers, buyer)?;
                resolver.bind_log_dependency(&dependency, *reference)?;
                let (from, to, value, _) = resolver.usdc_transfer(*reference, input.usdc)?;
                if dependency_seller != seller
                    || from != address_field(&dependency, "from")?
                    || to != address_field(&dependency, "to")?
                    || value != decimal_u128_field(&dependency, "amountRaw")?
                    || value == 0
                    || !((from == seller && to == buyer) || (from == buyer && to == seller))
                {
                    return Err("cohort: invalid direct seller-buyer closure".into());
                }
                direct_buyer_closures.insert(buyer);
            }
            (
                "RELAY_PATH",
                EvidenceLocation::RelayPath {
                    seller_payment,
                    relay_forward,
                    funder_receipt,
                },
            ) => {
                for reference in [seller_payment, relay_forward, funder_receipt] {
                    ensure_unique(&mut used_chain_evidence, resolver.log_identity(*reference)?)?;
                }
                let dependency_seller = address_field(&dependency, "seller")?;
                let funder = address_field(&dependency, "funder")?;
                ensure_approved(&approved_funders, funder)?;
                if dependency_seller != seller {
                    return Err("cohort: relay seller mismatch".into());
                }
                let relay_parts = [
                    (value_field(&dependency, "sellerPayment")?, *seller_payment),
                    (value_field(&dependency, "relayForward")?, *relay_forward),
                    (value_field(&dependency, "funderReceipt")?, *funder_receipt),
                ];
                for (part, reference) in relay_parts {
                    resolver.bind_log_dependency(part, reference)?;
                    let (from, to, value, _) = resolver.usdc_transfer(reference, input.usdc)?;
                    if from != address_field(part, "from")?
                        || to != address_field(part, "to")?
                        || value != decimal_u128_field(part, "amountRaw")?
                    {
                        return Err("cohort: relay dependency mismatch".into());
                    }
                }
                if !resolver.relay_path(
                    *seller_payment,
                    *relay_forward,
                    *funder_receipt,
                    seller,
                    funder,
                    input.usdc,
                )? {
                    return Err("cohort: invalid relay path".into());
                }
                relay_path_funders.push(funder);
            }
            _ => {
                return Err(format!(
                    "cohort: evidence/location mismatch for {evidence_type}"
                ))
            }
        }
    }

    let cohort_funder = cohort_funder.ok_or("cohort: no common funder proven")?;
    if settlement_buyers.len() < MINIMUM_BUYERS {
        return Err("cohort: fewer than three linked buyers".into());
    }
    if qualified_volume_raw < MINIMUM_VOLUME_RAW {
        return Err("cohort: qualified volume below 1,000 USDC".into());
    }
    if claim_type_code == 1 {
        let direct_funder = direct_funder_closures.contains(&cohort_funder);
        let direct_buyer = direct_buyer_closures
            .iter()
            .any(|buyer| settlement_buyers.contains(buyer));
        let relay_count = relay_path_funders
            .iter()
            .filter(|funder| **funder == cohort_funder)
            .count();
        if !direct_funder && !direct_buyer && relay_count < 3 {
            return Err("cohort: P0 closure not proven for common funder cohort".into());
        }
    }

    Ok(CohortJournal {
        predicate_version: PREDICATE_VERSION,
        claim_type: claim_type_code,
        claim_id,
        report_root: input.report_root,
        seller,
        penalty_bps: PENALTY_BPS,
        linked_buyer_count: settlement_buyers.len() as u32,
        qualified_volume_raw,
        block_refs,
    })
}

pub fn verify_reciprocal(input: &ReciprocalInput) -> Result<ReciprocalJournal, String> {
    if input.chain_id != BASE_CHAIN_ID || input.channels != CHANNELS_ADDRESS {
        return Err("reciprocal: unrecognized configuration".into());
    }
    let claim = verify_claim(
        &input.claim_leaf,
        &input.claim_membership,
        input.report_root,
    )?;
    if string_field(&claim, "type")? != "P0_RECIPROCAL" {
        return Err("reciprocal: wrong claim type".into());
    }
    let seller_a = address_field(&claim, "walletA")?;
    let seller_b = address_field(&claim, "walletB")?;
    let claim_id = b256_field(&claim, "claimId")?;
    let dependency_root = b256_field(&claim, "dependencyRoot")?;
    let (period_start, period_end_exclusive) = period_bounds(&claim)?;
    let block_refs = authenticate_blocks(&input.blocks)?;
    let resolver = Resolver {
        blocks: &input.blocks,
    };
    let mut used_chain_evidence = BTreeSet::new();
    let mut used_dependencies = BTreeSet::new();
    let mut directions = 0u8;
    let mut settlements = 0u32;
    let mut qualified_volume_raw = 0u128;
    for selected in &input.evidence {
        let dependency_id = dependency_hash(&selected.dependency_leaf);
        if !used_dependencies.insert(dependency_id) {
            return Err("duplicate report dependency".into());
        }
        let dependency = verify_dependency(selected, dependency_root)?;
        if string_field(&dependency, "evidenceType")? != "RECIPROCAL_SETTLEMENT" {
            return Err("reciprocal: wrong evidence type".into());
        }
        let reference = match selected.location {
            EvidenceLocation::Log(reference) => reference,
            _ => return Err("reciprocal: settlement requires a log".into()),
        };
        ensure_unique(&mut used_chain_evidence, resolver.log_identity(reference)?)?;
        resolver.bind_log_dependency(&dependency, reference)?;
        let expected_buyer = address_field(&dependency, "buyer")?;
        let expected_seller = address_field(&dependency, "seller")?;
        let expected_amount = decimal_u128_field(&dependency, "amountRaw")?;
        let expected_channel = b256_field(&dependency, "channelId")?;
        let (channel, buyer, seller, amount, block) =
            resolver.settlement(reference, input.channels)?;
        ensure_positive_settlement(amount, "reciprocal")?;
        if block < period_start || block >= period_end_exclusive {
            return Err("reciprocal: settlement outside approved period".into());
        }
        if channel != expected_channel
            || buyer != expected_buyer
            || seller != expected_seller
            || amount != expected_amount
        {
            return Err("reciprocal: dependency does not match settlement".into());
        }
        if buyer == seller_a && seller == seller_b {
            directions |= 1;
        } else if buyer == seller_b && seller == seller_a {
            directions |= 2;
        } else {
            return Err("reciprocal: settlement outside ordered pair".into());
        }
        settlements += 1;
        qualified_volume_raw = qualified_volume_raw
            .checked_add(amount)
            .ok_or("reciprocal: volume overflow")?;
    }
    if settlements < 100 || directions != 3 {
        return Err("reciprocal: requires 100 bidirectional settlements".into());
    }
    Ok(ReciprocalJournal {
        predicate_version: PREDICATE_VERSION,
        claim_id,
        report_root: input.report_root,
        seller_a,
        seller_b,
        penalty_bps: PENALTY_BPS,
        settlement_count: settlements,
        qualified_volume_raw,
        block_refs,
    })
}

fn validate_configuration(
    chain_id: u64,
    usdc: Address,
    channels: Address,
    deposits: Address,
) -> Result<(), String> {
    if chain_id != BASE_CHAIN_ID
        || usdc != USDC_ADDRESS
        || channels != CHANNELS_ADDRESS
        || deposits != DEPOSITS_ADDRESS
    {
        return Err("cohort: unrecognized configuration".into());
    }
    Ok(())
}

fn authenticate_blocks(blocks: &[EnforcementBlock]) -> Result<Vec<(u64, B256)>, String> {
    let mut numbers = BTreeSet::new();
    let mut refs = Vec::new();
    for block in blocks {
        if !numbers.insert(block.header.number) {
            return Err("duplicate block evidence".into());
        }
        let mut receipt_indexes = BTreeSet::new();
        for receipt in &block.receipts {
            if !receipt_indexes.insert(receipt.tx_index) {
                return Err("duplicate receipt proof".into());
            }
            verify_receipt_inclusion(&block.header, receipt)?;
        }
        let mut transaction_indexes = BTreeSet::new();
        for transaction in &block.transactions {
            if !transaction_indexes.insert(transaction.tx_index) {
                return Err("duplicate transaction proof".into());
            }
            verify_transaction_inclusion(&block.header, transaction)?;
        }
        refs.push((block.header.number, block.header.hash_slow()));
    }
    refs.sort_unstable_by_key(|(number, _)| *number);
    Ok(refs)
}

fn verify_transaction_inclusion(
    header: &Header,
    transaction: &TransactionProof,
) -> Result<(), String> {
    let key = alloy_trie::Nibbles::unpack(trie_index_key(transaction.tx_index));
    alloy_trie::proof::verify_proof(
        header.transactions_root,
        key,
        Some(transaction.value.to_vec()),
        transaction.proof.iter(),
    )
    .map_err(|error| format!("transaction inclusion: {error}"))
}

fn verify_claim(bytes: &[u8], proof: &MembershipProof, report_root: B256) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("claim JSON: {error}"))?;
    verify_membership(domain_hash(b"claim-leaf\0", bytes), proof, report_root)?;
    Ok(value)
}

fn verify_dependency(selected: &SelectedEvidence, dependency_root: B256) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(&selected.dependency_leaf)
        .map_err(|error| format!("dependency JSON: {error}"))?;
    verify_membership(
        domain_hash(b"dependency\0", &selected.dependency_leaf),
        &selected.dependency_membership,
        dependency_root,
    )?;
    Ok(value)
}

fn dependency_hash(bytes: &[u8]) -> B256 {
    domain_hash(b"dependency\0", bytes)
}

pub fn verify_membership(
    mut hash: B256,
    proof: &MembershipProof,
    expected_root: B256,
) -> Result<(), String> {
    for step in &proof.steps {
        let mut hasher = Sha256::new();
        hasher.update([1]);
        if step.sibling_on_left {
            hasher.update(step.sibling);
            hasher.update(hash);
        } else {
            hasher.update(hash);
            hasher.update(step.sibling);
        }
        hash = B256::from_slice(&hasher.finalize());
    }
    if hash != expected_root {
        return Err("Merkle membership mismatch".into());
    }
    Ok(())
}

fn domain_hash(domain: &[u8], value: &[u8]) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    B256::from_slice(&hasher.finalize())
}

struct Resolver<'a> {
    blocks: &'a [EnforcementBlock],
}

impl Resolver<'_> {
    fn receipt_log(&self, reference: LogRef) -> Result<(loop_core::ParsedLog, u64), String> {
        let block = self
            .blocks
            .get(reference.block)
            .ok_or("block reference out of range")?;
        let receipt = block
            .receipts
            .get(reference.receipt)
            .ok_or("receipt reference out of range")?;
        Ok((
            receipt_log(&receipt.value, reference.log)?,
            block.header.number,
        ))
    }

    fn log_identity(&self, reference: LogRef) -> Result<(u8, u64, u64, usize), String> {
        let block = self
            .blocks
            .get(reference.block)
            .ok_or("block reference out of range")?;
        let receipt = block
            .receipts
            .get(reference.receipt)
            .ok_or("receipt reference out of range")?;
        Ok((0, block.header.number, receipt.tx_index, reference.log))
    }

    fn transaction_identity(
        &self,
        reference: TransactionRef,
    ) -> Result<(u8, u64, u64, usize), String> {
        let block = self
            .blocks
            .get(reference.block)
            .ok_or("block reference out of range")?;
        let transaction = block
            .transactions
            .get(reference.transaction)
            .ok_or("transaction reference out of range")?;
        Ok((1, block.header.number, transaction.tx_index, 0))
    }

    fn transaction_for_log(
        &self,
        reference: LogRef,
    ) -> Result<(TransactionRef, &TransactionProof), String> {
        let block = self
            .blocks
            .get(reference.block)
            .ok_or("block reference out of range")?;
        let receipt = block
            .receipts
            .get(reference.receipt)
            .ok_or("receipt reference out of range")?;
        let mut matches = block
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, transaction)| transaction.tx_index == receipt.tx_index);
        let (position, transaction) = matches
            .next()
            .ok_or("authenticated transaction missing for receipt")?;
        if matches.next().is_some() {
            return Err("duplicate authenticated transaction for receipt".into());
        }
        Ok((
            TransactionRef {
                block: reference.block,
                transaction: position,
            },
            transaction,
        ))
    }

    fn bind_log_dependency(&self, dependency: &Value, reference: LogRef) -> Result<(), String> {
        let (transaction_ref, _) = self.transaction_for_log(reference)?;
        self.bind_transaction_dependency(dependency, transaction_ref)
    }

    fn bind_transaction_dependency(
        &self,
        dependency: &Value,
        reference: TransactionRef,
    ) -> Result<(), String> {
        let block = self
            .blocks
            .get(reference.block)
            .ok_or("block reference out of range")?;
        let transaction = block
            .transactions
            .get(reference.transaction)
            .ok_or("transaction reference out of range")?;
        if b256_field(dependency, "transactionHash")? != keccak256(transaction.value.as_ref()) {
            return Err("dependency transaction hash mismatch".into());
        }
        if optional_u64_field(dependency, "blockNumber")?
            .is_some_and(|number| number != block.header.number)
        {
            return Err("dependency block number mismatch".into());
        }
        if optional_u64_field(dependency, "transactionIndex")?
            .is_some_and(|index| index != transaction.tx_index)
        {
            return Err("dependency transaction index mismatch".into());
        }
        if optional_u64_field(dependency, "timestamp")?
            .is_some_and(|timestamp| timestamp != block.header.timestamp)
        {
            return Err("dependency block timestamp mismatch".into());
        }
        Ok(())
    }

    fn usdc_transfer(
        &self,
        reference: LogRef,
        usdc: Address,
    ) -> Result<(Address, Address, u128, u64), String> {
        let (log, block) = self.receipt_log(reference)?;
        if log.address != usdc
            || log.topics.len() != 3
            || log.topics[0] != TRANSFER_TOPIC
            || log.data.len() != 32
        {
            return Err("not a USDC transfer".into());
        }
        let value =
            u128::try_from(U256::from_be_slice(&log.data)).map_err(|_| "USDC value overflow")?;
        Ok((
            topic_address(&log.topics[1]),
            topic_address(&log.topics[2]),
            value,
            block,
        ))
    }

    fn settlement(
        &self,
        reference: LogRef,
        channels: Address,
    ) -> Result<(B256, Address, Address, u128, u64), String> {
        let (log, block) = self.receipt_log(reference)?;
        if log.address != channels
            || log.topics.len() != 4
            || log.topics[0] != CHANNEL_SETTLED_TOPIC
            || log.data.len() < 64
        {
            return Err("not a ChannelSettled event".into());
        }
        let amount = u128::try_from(U256::from_be_slice(&log.data[32..64]))
            .map_err(|_| "settlement value overflow")?;
        Ok((
            log.topics[1],
            topic_address(&log.topics[2]),
            topic_address(&log.topics[3]),
            amount,
            block,
        ))
    }

    fn native_transaction(
        &self,
        reference: TransactionRef,
    ) -> Result<(Address, Address, U256, u64), String> {
        let block = self
            .blocks
            .get(reference.block)
            .ok_or("block reference out of range")?;
        let proof = block
            .transactions
            .get(reference.transaction)
            .ok_or("transaction reference out of range")?;
        let mut bytes = proof.value.as_ref();
        let envelope = TxEnvelope::decode_2718(&mut bytes)
            .map_err(|error| format!("transaction decode: {error}"))?;
        if !bytes.is_empty()
            || !(envelope.is_legacy() || envelope.is_eip2930() || envelope.is_eip1559())
        {
            return Err("unsupported transaction type".into());
        }
        let signer = envelope
            .recover_signer()
            .map_err(|_| "transaction signer recovery failed")?;
        let to = envelope
            .to()
            .ok_or("native funding cannot create a contract")?;
        Ok((signer, to, envelope.value(), block.header.number))
    }

    fn relay_path(
        &self,
        first: LogRef,
        second: LogRef,
        third: LogRef,
        seller: Address,
        funder: Address,
        usdc: Address,
    ) -> Result<bool, String> {
        let (from1, to1, amount1, block1) = self.usdc_transfer(first, usdc)?;
        let (from2, to2, amount2, block2) = self.usdc_transfer(second, usdc)?;
        let (from3, to3, amount3, block3) = self.usdc_transfer(third, usdc)?;
        let timestamp1 = self.blocks[first.block].header.timestamp;
        let timestamp2 = self.blocks[second.block].header.timestamp;
        let timestamp3 = self.blocks[third.block].header.timestamp;
        if !valid_relay_amounts(amount1, amount2, amount3)
            || from1 != seller
            || to1 != from2
            || to2 != from3
            || to3 != funder
            || block2 < block1
            || block3 < block2
            || timestamp2 < timestamp1
            || timestamp3 < timestamp2
            || timestamp2 - timestamp1 > 86_400
            || timestamp3 - timestamp2 > 86_400
        {
            return Ok(false);
        }
        Ok(true)
    }
}

fn ensure_positive_settlement(amount: u128, context: &str) -> Result<(), String> {
    if amount == 0 {
        return Err(format!("{context}: zero-value settlement"));
    }
    Ok(())
}

fn valid_relay_amounts(seller_amount: u128, forwarded_amount: u128, received_amount: u128) -> bool {
    if seller_amount == 0
        || forwarded_amount == 0
        || received_amount == 0
        || received_amount > forwarded_amount
    {
        return false;
    }
    let amount_delta = seller_amount.abs_diff(forwarded_amount);
    let retained = forwarded_amount - received_amount;
    amount_delta <= 1_000
        && (retained <= 1_000_000
            || received_amount.saturating_mul(10_000) >= forwarded_amount.saturating_mul(9_800))
}

fn ensure_unique(
    set: &mut BTreeSet<(u8, u64, u64, usize)>,
    identity: (u8, u64, u64, usize),
) -> Result<(), String> {
    if !set.insert(identity) {
        return Err("duplicate authenticated evidence".into());
    }
    Ok(())
}

fn ensure_approved(approved: &[Address], buyer: Address) -> Result<(), String> {
    if !approved.contains(&buyer) {
        return Err("buyer is not approved by report claim".into());
    }
    Ok(())
}

fn set_cohort_funder(
    cohort_funder: &mut Option<Address>,
    approved_funders: &[Address],
    funder: Address,
) -> Result<(), String> {
    ensure_approved(approved_funders, funder)
        .map_err(|_| "cohort: funder is not approved by report claim")?;
    if cohort_funder.is_some_and(|expected| expected != funder) {
        return Err("cohort: buyers do not share one approved funder".into());
    }
    *cohort_funder = Some(funder);
    Ok(())
}

fn period_bounds(claim: &Value) -> Result<(u64, u64), String> {
    let period = value_field(claim, "period")?;
    let start = u64_field(period, "startBlock")?;
    let end_exclusive = u64_field(period, "endBlockExclusive")?;
    if start >= end_exclusive {
        return Err("invalid claim period".into());
    }
    Ok((start, end_exclusive))
}

fn value_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value, String> {
    value
        .get(field)
        .ok_or_else(|| format!("missing value field {field}"))
}

fn u64_field(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing u64 field {field}"))
}

fn optional_u64_field(value: &Value, field: &str) -> Result<Option<u64>, String> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("invalid optional u64 field {field}")),
    }
}

fn optional_string_field<'a>(value: &'a Value, field: &str) -> Result<Option<&'a str>, String> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("invalid optional string field {field}")),
    }
}

fn decimal_u128_field(value: &Value, field: &str) -> Result<u128, String> {
    string_field(value, field)?
        .parse()
        .map_err(|_| format!("invalid decimal u128 field {field}"))
}

fn decimal_u256_field(value: &Value, field: &str) -> Result<U256, String> {
    U256::from_str_radix(string_field(value, field)?, 10)
        .map_err(|_| format!("invalid decimal U256 field {field}"))
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {field}"))
}

fn address_field(value: &Value, field: &str) -> Result<Address, String> {
    string_field(value, field)?
        .parse()
        .map_err(|_| format!("invalid address field {field}"))
}

fn b256_field(value: &Value, field: &str) -> Result<B256, String> {
    string_field(value, field)?
        .parse()
        .map_err(|_| format!("invalid bytes32 field {field}"))
}

fn address_array(value: &Value, field: &str) -> Result<Vec<Address>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing address array {field}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| format!("invalid address in {field}"))?
                .parse()
                .map_err(|_| format!("invalid address in {field}"))
        })
        .collect()
}

fn topic_address(topic: &B256) -> Address {
    Address::from_slice(&topic.as_slice()[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verifies_ordered_sha256_merkle_membership() {
        let left = domain_hash(b"dependency\0", br#"{"id":1}"#);
        let right = domain_hash(b"dependency\0", br#"{"id":2}"#);
        let mut hasher = Sha256::new();
        hasher.update([1]);
        hasher.update(left);
        hasher.update(right);
        let root = B256::from_slice(&hasher.finalize());
        let proof = MembershipProof {
            steps: vec![MerkleStep {
                sibling: right,
                sibling_on_left: false,
            }],
        };
        assert!(verify_membership(left, &proof, root).is_ok());
        assert!(verify_membership(right, &proof, root).is_err());
    }

    #[test]
    fn rejects_unapproved_and_mixed_cohort_funders() {
        let approved = [address!("0000000000000000000000000000000000000001")];
        let mut cohort_funder = None;
        assert!(set_cohort_funder(&mut cohort_funder, &approved, approved[0]).is_ok());
        assert_eq!(cohort_funder, Some(approved[0]));
        assert!(set_cohort_funder(
            &mut cohort_funder,
            &[
                approved[0],
                address!("0000000000000000000000000000000000000002")
            ],
            address!("0000000000000000000000000000000000000002"),
        )
        .is_err());
        assert!(set_cohort_funder(
            &mut None,
            &approved,
            address!("0000000000000000000000000000000000000003"),
        )
        .is_err());
    }

    #[test]
    fn rejects_zero_value_settlements() {
        assert!(ensure_positive_settlement(0, "cohort").is_err());
        assert!(ensure_positive_settlement(1, "cohort").is_ok());
    }

    #[test]
    fn rejects_zero_or_amplifying_relay_paths() {
        assert!(!valid_relay_amounts(0, 1, 1));
        assert!(!valid_relay_amounts(1, 1, 2));
        assert!(valid_relay_amounts(1_000_000, 1_000_000, 990_000));
    }

    #[test]
    fn rejects_dependency_transaction_hash_mismatch() {
        let transaction = TransactionProof {
            tx_index: 0,
            value: Bytes::from(vec![1, 2, 3]),
            proof: Vec::new(),
        };
        let blocks = [EnforcementBlock {
            header: Header::default(),
            receipts: Vec::new(),
            transactions: vec![transaction],
        }];
        let resolver = Resolver { blocks: &blocks };
        let dependency = json!({
            "transactionHash": B256::ZERO.to_string(),
            "blockNumber": null,
            "transactionIndex": null,
            "timestamp": null,
        });
        assert_eq!(
            resolver
                .bind_transaction_dependency(
                    &dependency,
                    TransactionRef {
                        block: 0,
                        transaction: 0,
                    },
                )
                .unwrap_err(),
            "dependency transaction hash mismatch"
        );
    }
}
