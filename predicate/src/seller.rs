use crate::{
    verify_closed_loop, verify_reciprocal, ClosedLoopInput, ReciprocalInput, WashJournal,
    BASE_CHAIN_ID,
};
use alloy_primitives::{keccak256, Address, B256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SELLER_JOURNAL_SCHEMA_VERSION: u32 = 2;
pub const BLOCK_AUTHENTICATION_CHUNK_SIZE: usize = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "input", rename_all = "kebab-case")]
pub enum SellerClaimInput {
    ClosedLoop(ClosedLoopInput),
    Reciprocal(ReciprocalInput),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SellerProofInput {
    pub seller: Address,
    pub period_start_block: u64,
    pub period_end_block: u64,
    pub claims: Vec<SellerClaimInput>,
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
    let mut claim_ids = BTreeSet::new();
    let mut settlements = BTreeMap::<B256, u128>::new();
    let mut block_refs = BTreeMap::<u64, B256>::new();

    for claim in &input.claims {
        let journal = match claim {
            SellerClaimInput::ClosedLoop(claim) => verify_closed_loop(claim),
            SellerClaimInput::Reciprocal(claim) => verify_reciprocal(claim),
        }?;
        validate_claim(
            &journal,
            input,
            &mut claim_ids,
            &mut settlements,
            &mut block_refs,
        )?;
    }

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
    if input.claims.is_empty()
        || input.seller == Address::ZERO
        || input.period_start_block == 0
        || input.period_start_block > input.period_end_block
    {
        return Err("seller proof: invalid input".into());
    }
    Ok(())
}

fn validate_claim(
    journal: &WashJournal,
    input: &SellerProofInput,
    claim_ids: &mut BTreeSet<B256>,
    settlements: &mut BTreeMap<B256, u128>,
    block_refs: &mut BTreeMap<u64, B256>,
) -> Result<(), String> {
    if journal.chain_id != BASE_CHAIN_ID
        || journal.period_start_block != input.period_start_block
        || journal.period_end_block != input.period_end_block
        || journal.source_claim_id == B256::ZERO
        || journal.claim_id == B256::ZERO
    {
        return Err("seller proof: claim identity mismatch".into());
    }
    if claim_ids.contains(&journal.claim_id) {
        return Err("seller proof: duplicate claim id".into());
    }

    let mut subjects = journal
        .subjects
        .iter()
        .filter(|subject| subject.subject == input.seller);
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
        match settlements.get(&settlement.settlement_id) {
            Some(amount) if *amount != settlement.amount => {
                return Err("seller proof: conflicting settlement amount".into())
            }
            _ => {}
        }
    }
    if claim_volume == 0 || claim_volume != subject.wash_volume {
        return Err("seller proof: claim settlement total mismatch".into());
    }

    for (number, block_hash) in &journal.block_refs {
        if *block_hash == B256::ZERO {
            return Err("seller proof: zero claim block hash".into());
        }
        match block_refs.get(number) {
            Some(existing) if *existing != *block_hash => {
                return Err("seller proof: conflicting claim block hash".into())
            }
            _ => {}
        }
    }
    claim_ids.insert(journal.claim_id);
    for settlement in &subject.settlements {
        settlements
            .entry(settlement.settlement_id)
            .or_insert(settlement.amount);
    }
    for (number, block_hash) in &journal.block_refs {
        block_refs.entry(*number).or_insert(*block_hash);
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
    fn merge_rejects_conflicting_settlement_amounts_and_block_hashes() {
        let seller = Address::repeat_byte(0x11);
        let input = SellerProofInput {
            seller,
            period_start_block: 10,
            period_end_block: 20,
            claims: Vec::new(),
        };
        let mut claim_ids = BTreeSet::new();
        let mut settlements = BTreeMap::new();
        let mut block_refs = BTreeMap::new();
        validate_claim(
            &journal(seller, B256::repeat_byte(1), B256::repeat_byte(2), 7, 100),
            &input,
            &mut claim_ids,
            &mut settlements,
            &mut block_refs,
        )
        .unwrap();

        let amount_conflict = validate_claim(
            &journal(seller, B256::repeat_byte(3), B256::repeat_byte(2), 8, 101),
            &input,
            &mut claim_ids,
            &mut settlements,
            &mut block_refs,
        )
        .unwrap_err();
        assert!(amount_conflict.contains("conflicting settlement amount"));

        let block_conflict = validate_claim(
            &journal(seller, B256::repeat_byte(4), B256::repeat_byte(5), 9, 101),
            &input,
            &mut claim_ids,
            &mut settlements,
            &mut block_refs,
        )
        .unwrap_err();
        assert!(block_conflict.contains("conflicting claim block hash"));
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
