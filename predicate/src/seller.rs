use crate::{
    verify_closed_loop, verify_reciprocal, ClosedLoopInput, ReciprocalInput, WashJournal,
    AGENT_STATS_TOTAL_VOLUME_OFFSET, BASE_CHAIN_ID, CHANNELS_ADDRESS, CHANNELS_AGENT_STATS_SLOT,
    STAKING_ADDRESS, STAKING_SELLER_AGENT_ID_SLOT,
};
use alloy_consensus::Header;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use loop_core::StorageProof;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SELLER_JOURNAL_SCHEMA_VERSION: u32 = 1;
pub const BLOCK_AUTHENTICATION_CHUNK_SIZE: usize = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "input",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum SellerEvidence {
    ClosedLoop(ClosedLoopInput),
    Reciprocal(ReciprocalInput),
}

/// Authenticated reads of the protocol's own cumulative settled-volume
/// counter at one period boundary: `AntseedStaking.sellerAgentId[seller]`
/// binds the seller to its agent id, then
/// `AntseedChannels._agentStats[agentId].totalVolumeUsdc` is the counter the
/// contract increments on every settlement — an accumulator that cannot
/// cherry-pick. Slots are derived from pinned layout constants, never from
/// the witness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotalVolumeBoundary {
    /// Boundary block header; it joins the journal's block references, so
    /// the registry blockhash-authenticates it like every other evidence
    /// block.
    pub header: Header,
    /// Proof for `sellerAgentId[seller]` on the staking contract.
    pub agent_id: StorageProof,
    /// Proof for `_agentStats[agentId].totalVolumeUsdc` on the channels
    /// contract.
    pub total_volume: StorageProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SellerProofInput {
    pub seller: Address,
    pub period_start_block: u64,
    pub period_end_block: u64,
    /// Read at `period_end_block`. The enforcement period starts at the
    /// protocol's genesis: the channels contract recorded no settlement
    /// before `period_start_block` (verified on-chain — no `ChannelSettled`
    /// log predates it), so every seller's counter was zero at the period
    /// start and the period-end reading IS the period total. A future
    /// period with a nonzero opening counter needs a start boundary and a
    /// new vkey.
    pub total_volume: TotalVolumeBoundary,
    pub evidence: SellerEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalBlockRef {
    pub number: u64,
    pub block_hash: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellerJournal {
    pub schema_version: u32,
    pub chain_id: u64,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub seller: Address,
    pub proven_wash_volume: u128,
    /// `AntseedChannels` cumulative settled volume for this seller over the
    /// period, proven from boundary state. The denominator for the proven
    /// wash share: `proven_wash_volume / total_seller_volume`.
    pub total_seller_volume: u128,
    pub evidence_digest: B256,
    pub block_reference_count: u32,
    pub block_authentication_chunk_size: u32,
    pub block_authentication_chunk_count: u32,
    pub block_authentication_root: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockAuthenticationChunk {
    pub index: u32,
    pub references: Vec<HistoricalBlockRef>,
    pub proof: Vec<B256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSeller {
    pub journal: SellerJournal,
    pub block_refs: Vec<HistoricalBlockRef>,
}

alloy_sol_types::sol! {
    struct SolSellerSettlement {
        bytes32 settlementId;
        uint128 amount;
    }

    struct SolSellerJournal {
        uint32 schemaVersion;
        uint64 chainId;
        uint64 periodStartBlock;
        uint64 periodEndBlock;
        address seller;
        uint128 provenWashVolume;
        uint128 totalSellerVolume;
        bytes32 evidenceDigest;
        uint32 blockReferenceCount;
        uint32 blockAuthenticationChunkSize;
        uint32 blockAuthenticationChunkCount;
        bytes32 blockAuthenticationRoot;
    }

    struct SolAuthenticationBlockRef {
        uint64 number;
        bytes32 blockHash;
    }
}

impl SellerJournal {
    pub fn abi_encode(&self) -> Vec<u8> {
        SolSellerJournal {
            schemaVersion: self.schema_version,
            chainId: self.chain_id,
            periodStartBlock: self.period_start_block,
            periodEndBlock: self.period_end_block,
            seller: self.seller,
            provenWashVolume: self.proven_wash_volume,
            totalSellerVolume: self.total_seller_volume,
            evidenceDigest: self.evidence_digest,
            blockReferenceCount: self.block_reference_count,
            blockAuthenticationChunkSize: self.block_authentication_chunk_size,
            blockAuthenticationChunkCount: self.block_authentication_chunk_count,
            blockAuthenticationRoot: self.block_authentication_root,
        }
        .abi_encode()
    }

    pub fn abi_decode(data: &[u8]) -> Result<Self, String> {
        let journal = SolSellerJournal::abi_decode(data)
            .map_err(|error| format!("seller proof: journal abi: {error}"))?;
        Ok(Self {
            schema_version: journal.schemaVersion,
            chain_id: journal.chainId,
            period_start_block: journal.periodStartBlock,
            period_end_block: journal.periodEndBlock,
            seller: journal.seller,
            proven_wash_volume: journal.provenWashVolume,
            total_seller_volume: journal.totalSellerVolume,
            evidence_digest: journal.evidenceDigest,
            block_reference_count: journal.blockReferenceCount,
            block_authentication_chunk_size: journal.blockAuthenticationChunkSize,
            block_authentication_chunk_count: journal.blockAuthenticationChunkCount,
            block_authentication_root: journal.blockAuthenticationRoot,
        })
    }
}

pub fn verify_seller(input: &SellerProofInput) -> Result<VerifiedSeller, String> {
    validate_input(input)?;
    let mut settlements = BTreeMap::<B256, u128>::new();
    let mut block_refs = BTreeMap::<u64, B256>::new();
    let journal = match &input.evidence {
        SellerEvidence::ClosedLoop(evidence) => verify_closed_loop(evidence),
        SellerEvidence::Reciprocal(evidence) => verify_reciprocal(evidence),
    }?;
    validate_evidence(
        &journal,
        input.seller,
        input.period_start_block,
        input.period_end_block,
        &mut settlements,
        &mut block_refs,
    )?;

    let total_seller_volume = verify_total_volume(input, &mut block_refs)?;

    let proven_wash_volume = sum_settlements(&settlements)?;
    if proven_wash_volume == 0 {
        return Err("seller proof: zero final volume".into());
    }

    let block_refs = block_refs
        .into_iter()
        .map(|(number, block_hash)| HistoricalBlockRef { number, block_hash })
        .collect::<Vec<_>>();
    let authentication_chunks = block_authentication_chunks(&block_refs)?;
    let block_authentication_root =
        block_authentication_root(&block_refs).ok_or("seller proof: no block references")?;
    let settlement_values = settlements
        .iter()
        .map(|(settlement_id, amount)| SolSellerSettlement {
            settlementId: *settlement_id,
            amount: *amount,
        })
        .collect::<Vec<_>>();
    let evidence_digest = evidence_digest(
        input.seller,
        input.period_start_block,
        input.period_end_block,
        &settlement_values,
    );

    Ok(VerifiedSeller {
        journal: SellerJournal {
            schema_version: SELLER_JOURNAL_SCHEMA_VERSION,
            chain_id: BASE_CHAIN_ID,
            period_start_block: input.period_start_block,
            period_end_block: input.period_end_block,
            seller: input.seller,
            proven_wash_volume,
            total_seller_volume,
            evidence_digest,
            block_reference_count: block_refs
                .len()
                .try_into()
                .map_err(|_| "seller proof: too many block references")?,
            block_authentication_chunk_size: BLOCK_AUTHENTICATION_CHUNK_SIZE as u32,
            block_authentication_chunk_count: authentication_chunks
                .len()
                .try_into()
                .map_err(|_| "seller proof: too many block chunks")?,
            block_authentication_root,
        },
        block_refs,
    })
}

fn validate_input(input: &SellerProofInput) -> Result<(), String> {
    if input.seller == Address::ZERO
        || input.period_start_block == 0
        || input.period_start_block > input.period_end_block
    {
        return Err("seller proof: invalid input".into());
    }
    Ok(())
}

/// Prove the seller's total settled volume over the period from the
/// protocol's own cumulative counter at the period end.
///
/// The period starts at protocol genesis (no settlement predates it), so
/// the period-end counter is the period total — no start boundary needed.
/// The boundary header joins `block_refs`, so the registry authenticates it
/// against canonical Base history exactly like claim evidence. The seller
/// must be a staked agent at the period end: no agent id means no
/// attributable counter and therefore no denominator.
fn verify_total_volume(
    input: &SellerProofInput,
    block_refs: &mut BTreeMap<u64, B256>,
) -> Result<u128, String> {
    let end =
        verify_total_volume_boundary(&input.total_volume, input.period_end_block, input.seller)?;
    if end.agent_id.is_zero() {
        return Err("total volume: seller is not a staked agent at the period end".into());
    }
    let (number, hash) = (
        input.total_volume.header.number,
        input.total_volume.header.hash_slow(),
    );
    match block_refs.get(&number) {
        Some(existing) if *existing != hash => {
            return Err("total volume: conflicting boundary block hash".into())
        }
        _ => {
            block_refs.insert(number, hash);
        }
    }
    Ok(end.counter)
}

struct BoundaryReading {
    agent_id: U256,
    counter: u128,
}

fn verify_total_volume_boundary(
    boundary: &TotalVolumeBoundary,
    expected_block: u64,
    seller: Address,
) -> Result<BoundaryReading, String> {
    if boundary.header.number != expected_block {
        return Err(format!(
            "total volume: boundary at block {} but the rule requires block {expected_block}",
            boundary.header.number
        ));
    }
    let agent_id_slot = loop_core::mapping_slot_address(seller, STAKING_SELLER_AGENT_ID_SLOT);
    let agent_id = loop_core::verify_storage_value(
        boundary.header.state_root,
        STAKING_ADDRESS,
        agent_id_slot,
        &boundary.agent_id,
    )?;
    // A zero agent id is a valid reading (seller not staked at this
    // boundary); the caller decides whether that is acceptable. The counter
    // slot is then `_agentStats[0]`, which the contract never writes.
    let counter_slot = loop_core::slot_offset(
        loop_core::mapping_slot_u256(agent_id, CHANNELS_AGENT_STATS_SLOT),
        AGENT_STATS_TOTAL_VOLUME_OFFSET,
    );
    let counter = loop_core::verify_storage_value(
        boundary.header.state_root,
        CHANNELS_ADDRESS,
        counter_slot,
        &boundary.total_volume,
    )?;
    Ok(BoundaryReading {
        agent_id,
        counter: u128::try_from(counter).map_err(|_| "total volume: counter overflow")?,
    })
}

fn validate_evidence(
    journal: &WashJournal,
    seller: Address,
    period_start_block: u64,
    period_end_block: u64,
    settlements: &mut BTreeMap<B256, u128>,
    block_refs: &mut BTreeMap<u64, B256>,
) -> Result<(), String> {
    if journal.chain_id != BASE_CHAIN_ID
        || journal.period_start_block != period_start_block
        || journal.period_end_block != period_end_block
        || journal.source_claim_id == B256::ZERO
        || journal.claim_id == B256::ZERO
    {
        return Err("seller proof: claim identity mismatch".into());
    }
    let mut subjects = journal
        .subjects
        .iter()
        .filter(|subject| subject.subject == seller);
    let subject = subjects
        .next()
        .ok_or("seller proof: claim does not prove target seller")?;
    if subjects.next().is_some() {
        return Err("seller proof: duplicate target seller in claim".into());
    }

    let mut claim_volume = 0u128;
    for settlement in &subject.settlements {
        if settlement.settlement_id == B256::ZERO || settlement.amount == 0 {
            return Err("seller proof: invalid settlement record".into());
        }
        claim_volume = claim_volume
            .checked_add(settlement.amount)
            .ok_or("seller proof: volume overflow")?;
        if settlements
            .insert(settlement.settlement_id, settlement.amount)
            .is_some()
        {
            return Err("seller proof: duplicate settlement in evidence".into());
        }
    }
    if claim_volume == 0 || claim_volume != subject.wash_volume {
        return Err("seller proof: claim settlement total mismatch".into());
    }

    for (number, block_hash) in &journal.block_refs {
        if *block_hash == B256::ZERO {
            return Err("seller proof: zero claim block hash".into());
        }
        match block_refs.insert(*number, *block_hash) {
            Some(existing) if existing != *block_hash => {
                return Err("seller proof: conflicting claim block hash".into())
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn evidence_digest(
    seller: Address,
    period_start_block: u64,
    period_end_block: u64,
    settlements: &[SolSellerSettlement],
) -> B256 {
    keccak256((seller, period_start_block, period_end_block, settlements).abi_encode_params())
}

pub fn block_authentication_chunks(
    refs: &[HistoricalBlockRef],
) -> Result<Vec<BlockAuthenticationChunk>, String> {
    if refs.is_empty() {
        return Err("seller proof: no block references".into());
    }
    if refs
        .iter()
        .any(|reference| reference.block_hash == B256::ZERO)
        || refs.windows(2).any(|pair| pair[0].number >= pair[1].number)
    {
        return Err("seller proof: invalid block references".into());
    }
    let leaves = refs
        .chunks(BLOCK_AUTHENTICATION_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| block_authentication_leaf(index as u32, chunk))
        .collect::<Vec<_>>();
    Ok(refs
        .chunks(BLOCK_AUTHENTICATION_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| BlockAuthenticationChunk {
            index: index as u32,
            references: chunk.to_vec(),
            proof: merkle_proof(&leaves, index),
        })
        .collect())
}

pub fn block_authentication_root(refs: &[HistoricalBlockRef]) -> Option<B256> {
    let leaves = refs
        .chunks(BLOCK_AUTHENTICATION_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| block_authentication_leaf(index as u32, chunk))
        .collect::<Vec<_>>();
    merkle_root(&leaves)
}

pub fn block_authentication_leaf(index: u32, refs: &[HistoricalBlockRef]) -> B256 {
    let references = refs
        .iter()
        .map(|reference| SolAuthenticationBlockRef {
            number: reference.number,
            blockHash: reference.block_hash,
        })
        .collect::<Vec<_>>();
    keccak256((index, references).abi_encode_params())
}

pub fn verify_block_authentication_chunk(root: B256, chunk: &BlockAuthenticationChunk) -> bool {
    if root == B256::ZERO
        || chunk.references.is_empty()
        || chunk.references.len() > BLOCK_AUTHENTICATION_CHUNK_SIZE
        || chunk
            .references
            .iter()
            .any(|reference| reference.block_hash == B256::ZERO)
        || chunk
            .references
            .windows(2)
            .any(|pair| pair[0].number >= pair[1].number)
    {
        return false;
    }
    let mut hash = block_authentication_leaf(chunk.index, &chunk.references);
    let mut index = chunk.index as usize;
    for sibling in &chunk.proof {
        hash = if index % 2 == 0 {
            keccak256((hash, *sibling).abi_encode())
        } else {
            keccak256((*sibling, hash).abi_encode())
        };
        index /= 2;
    }
    hash == root
}

fn sum_settlements(settlements: &BTreeMap<B256, u128>) -> Result<u128, String> {
    settlements.values().try_fold(0u128, |total, amount| {
        total
            .checked_add(*amount)
            .ok_or_else(|| "seller proof: volume overflow".into())
    })
}

fn merkle_root(leaves: &[B256]) -> Option<B256> {
    let mut level = leaves.to_vec();
    if level.is_empty() {
        return None;
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| keccak256((pair[0], *pair.get(1).unwrap_or(&pair[0])).abi_encode()))
            .collect();
    }
    level.first().copied()
}

fn merkle_proof(leaves: &[B256], leaf_index: usize) -> Vec<B256> {
    let mut level = leaves.to_vec();
    let mut index = leaf_index;
    let mut proof = Vec::new();
    while level.len() > 1 {
        let sibling = if index % 2 == 0 {
            *level.get(index + 1).unwrap_or(&level[index])
        } else {
            level[index - 1]
        };
        proof.push(sibling);
        level = level
            .chunks(2)
            .map(|pair| keccak256((pair[0], *pair.get(1).unwrap_or(&pair[0])).abi_encode()))
            .collect();
        index /= 2;
    }
    proof
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SettlementRecord, SubjectRecord};

    #[test]
    fn evidence_rejects_duplicate_settlements_and_conflicting_block_hashes() {
        let seller = Address::repeat_byte(0x11);
        let original = journal(seller, B256::repeat_byte(1), B256::repeat_byte(2), 7, 100);
        for amount in [100, 101] {
            let mut duplicate = original.clone();
            duplicate.subjects[0].settlements.push(SettlementRecord {
                settlement_id: B256::repeat_byte(2),
                amount,
            });
            duplicate.subjects[0].wash_volume += amount;
            let error = validate_evidence(
                &duplicate,
                seller,
                10,
                20,
                &mut BTreeMap::new(),
                &mut BTreeMap::new(),
            )
            .unwrap_err();
            assert!(error.contains("duplicate settlement in evidence"));
        }
        let mut conflicting = original;
        conflicting.block_refs.push((15, B256::repeat_byte(8)));
        let error = validate_evidence(
            &conflicting,
            seller,
            10,
            20,
            &mut BTreeMap::new(),
            &mut BTreeMap::new(),
        )
        .unwrap_err();
        assert!(error.contains("conflicting claim block hash"));
    }

    #[test]
    fn final_volume_uses_checked_arithmetic() {
        let settlements =
            BTreeMap::from([(B256::repeat_byte(1), u128::MAX), (B256::repeat_byte(2), 1)]);
        assert!(sum_settlements(&settlements)
            .unwrap_err()
            .contains("volume overflow"));
    }

    fn journal(
        seller: Address,
        claim_id: B256,
        settlement_id: B256,
        block_hash_byte: u8,
        amount: u128,
    ) -> WashJournal {
        WashJournal {
            predicate_id: 1,
            chain_id: BASE_CHAIN_ID,
            period_start_block: 10,
            period_end_block: 20,
            source_claim_id: claim_id,
            claim_id,
            subjects: vec![SubjectRecord {
                subject: seller,
                wash_volume: amount,
                settlements: vec![SettlementRecord {
                    settlement_id,
                    amount,
                }],
            }],
            block_refs: vec![(15, B256::repeat_byte(block_hash_byte))],
        }
    }
}
