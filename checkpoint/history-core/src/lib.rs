use alloy_consensus::Header;
use alloy_primitives::{B256, Bytes, keccak256};
use alloy_rlp::Decodable;
use alloy_sol_types::{SolValue, sol};
use serde::{Deserialize, Serialize};

pub const JOURNAL_VERSION: u32 = 2;
pub const BASE_CHAIN_ID: u64 = 8_453;
pub const HISTORICAL_START_BLOCK: u64 = 44_469_557;
pub const REQUIRED_COVERAGE_END_BLOCK: u64 = 49_936_172;
pub const EPOCH_SIZE: usize = 16_384;
pub const EPOCH_TREE_DEPTH: usize = 14;
pub const EIP2935_WINDOW: u64 = 8_191;
pub const MAX_BOUNDLESS_INPUT_BYTES: usize = 50_000_000;

const BLOCK_LEAF_DOMAIN: u8 = 0x00;
const BLOCK_NODE_DOMAIN: u8 = 0x02;
const EPOCH_LEAF_DOMAIN: u8 = 0x10;
const MMR_NODE_DOMAIN: u8 = 0x11;
const MMR_ROOT_DOMAIN: u8 = 0x12;

sol! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct EpochJournal {
        uint32 version;
        uint64 chainId;
        uint32 epochIndex;
        uint64 startBlockNumber;
        uint64 endBlockNumber;
        bytes32 firstParentHash;
        bytes32 endBlockHash;
        uint32 blockCount;
        bytes32 blockRoot;
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct AccumulatorJournal {
        uint32 version;
        uint64 chainId;
        bytes32 epochImageId;
        uint64 startBlockNumber;
        uint64 endBlockNumber;
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;
        uint64 blockCount;
        uint32 epochSize;
        uint32 epochCount;
        bytes32 mmrRoot;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochWitness {
    pub epoch_index: u32,
    pub base_headers_rlp: Vec<Bytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccumulatorInput {
    pub epoch_image_id: B256,
    pub epoch_journals: Vec<Bytes>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProof {
    pub mountain_siblings: Vec<B256>,
    pub peaks: Vec<B256>,
    pub target_peak_index: u32,
}

pub fn epoch_start(epoch_index: u32) -> Result<u64, String> {
    HISTORICAL_START_BLOCK
        .checked_add(u64::from(epoch_index) * EPOCH_SIZE as u64)
        .ok_or_else(|| "epoch start overflow".into())
}

pub fn epoch_end(epoch_index: u32) -> Result<u64, String> {
    epoch_start(epoch_index)?
        .checked_add(EPOCH_SIZE as u64 - 1)
        .ok_or_else(|| "epoch end overflow".into())
}

pub fn validate_epoch(witness: &EpochWitness) -> Result<EpochJournal, String> {
    if witness.base_headers_rlp.len() != EPOCH_SIZE {
        return Err("epoch must contain exactly 16,384 headers".into());
    }
    let expected_start = epoch_start(witness.epoch_index)?;
    let expected_end = epoch_end(witness.epoch_index)?;
    let mut headers = Vec::with_capacity(EPOCH_SIZE);
    let mut hashes = Vec::with_capacity(EPOCH_SIZE);
    for encoded in &witness.base_headers_rlp {
        let mut input = encoded.as_ref();
        let header = Header::decode(&mut input)
            .map_err(|error| format!("invalid Base header RLP: {error}"))?;
        if !input.is_empty() {
            return Err("trailing bytes in Base header RLP".into());
        }
        if alloy_rlp::encode(&header).as_slice() != encoded.as_ref() {
            return Err("non-canonical Base header RLP".into());
        }
        hashes.push(keccak256(encoded.as_ref()));
        headers.push(header);
    }
    if headers[0].number != expected_start || headers[EPOCH_SIZE - 1].number != expected_end {
        return Err("epoch header range mismatch".into());
    }
    for index in 1..headers.len() {
        if headers[index].number != headers[index - 1].number + 1 {
            return Err("epoch headers are not contiguous".into());
        }
        if headers[index].parent_hash != hashes[index - 1] {
            return Err("epoch header parent hash mismatch".into());
        }
    }
    Ok(EpochJournal {
        version: JOURNAL_VERSION,
        chainId: BASE_CHAIN_ID,
        epochIndex: witness.epoch_index,
        startBlockNumber: expected_start,
        endBlockNumber: expected_end,
        firstParentHash: headers[0].parent_hash,
        endBlockHash: hashes[EPOCH_SIZE - 1],
        blockCount: EPOCH_SIZE as u32,
        blockRoot: block_merkle_root(expected_start, &hashes)?,
    })
}

pub fn validate_accumulator(input: &AccumulatorInput) -> Result<AccumulatorJournal, String> {
    if input.epoch_image_id == B256::ZERO {
        return Err("missing epoch image ID".into());
    }
    if input.epoch_journals.is_empty() {
        return Err("missing epoch journals".into());
    }
    let mut journals = Vec::with_capacity(input.epoch_journals.len());
    for encoded in &input.epoch_journals {
        let journal = EpochJournal::abi_decode(encoded)
            .map_err(|error| format!("epoch journal ABI: {error}"))?;
        journals.push(journal);
    }
    for (index, journal) in journals.iter().enumerate() {
        let epoch_index = u32::try_from(index).map_err(|_| "epoch index overflow")?;
        if journal.version != JOURNAL_VERSION
            || journal.chainId != BASE_CHAIN_ID
            || journal.epochIndex != epoch_index
            || journal.startBlockNumber != epoch_start(epoch_index)?
            || journal.endBlockNumber != epoch_end(epoch_index)?
            || journal.blockCount != EPOCH_SIZE as u32
            || journal.firstParentHash == B256::ZERO
            || journal.endBlockHash == B256::ZERO
            || journal.blockRoot == B256::ZERO
        {
            return Err("invalid epoch journal geometry".into());
        }
        if index > 0 {
            let previous = &journals[index - 1];
            if journal.startBlockNumber != previous.endBlockNumber + 1
                || journal.firstParentHash != previous.endBlockHash
            {
                return Err("epoch journals are not contiguous".into());
            }
        }
    }
    let last = journals.last().expect("checked non-empty");
    if last.endBlockNumber < REQUIRED_COVERAGE_END_BLOCK {
        return Err("accumulator does not cover the proof period".into());
    }
    let leaves = journals.iter().map(epoch_commitment).collect::<Vec<_>>();
    let peaks = mmr_peaks(&leaves)?;
    let epoch_count = u32::try_from(journals.len()).map_err(|_| "epoch count overflow")?;
    let block_count = u64::from(epoch_count)
        .checked_mul(EPOCH_SIZE as u64)
        .ok_or("block count overflow")?;
    Ok(AccumulatorJournal {
        version: JOURNAL_VERSION,
        chainId: BASE_CHAIN_ID,
        epochImageId: input.epoch_image_id,
        startBlockNumber: HISTORICAL_START_BLOCK,
        endBlockNumber: last.endBlockNumber,
        anchorBlockNumber: last.endBlockNumber,
        anchorBlockHash: last.endBlockHash,
        blockCount: block_count,
        epochSize: EPOCH_SIZE as u32,
        epochCount: epoch_count,
        mmrRoot: mmr_root(epoch_count, &peaks),
    })
}

pub fn block_leaf(block_number: u64, block_hash: B256) -> B256 {
    let mut input = [0_u8; 41];
    input[0] = BLOCK_LEAF_DOMAIN;
    input[1..9].copy_from_slice(&block_number.to_be_bytes());
    input[9..].copy_from_slice(block_hash.as_slice());
    keccak256(input)
}

pub fn block_node(left: B256, right: B256) -> B256 {
    hash_pair(BLOCK_NODE_DOMAIN, left, right)
}

pub fn block_merkle_root(start: u64, hashes: &[B256]) -> Result<B256, String> {
    if hashes.len() != EPOCH_SIZE {
        return Err("block tree requires exactly one epoch".into());
    }
    let leaves = hashes
        .iter()
        .copied()
        .enumerate()
        .map(|(index, hash)| block_leaf(start + index as u64, hash))
        .collect::<Vec<_>>();
    merkle_root(leaves, block_node)
}

pub fn block_merkle_proof(
    start: u64,
    hashes: &[B256],
    block_number: u64,
) -> Result<Vec<B256>, String> {
    if hashes.len() != EPOCH_SIZE || block_number < start {
        return Err("block is outside epoch".into());
    }
    let target = usize::try_from(block_number - start).map_err(|_| "block index overflow")?;
    if target >= EPOCH_SIZE {
        return Err("block is outside epoch".into());
    }
    let mut layer = hashes
        .iter()
        .copied()
        .enumerate()
        .map(|(index, hash)| block_leaf(start + index as u64, hash))
        .collect::<Vec<_>>();
    let mut index = target;
    let mut proof = Vec::with_capacity(EPOCH_TREE_DEPTH);
    while layer.len() > 1 {
        proof.push(layer[index ^ 1]);
        layer = layer
            .chunks_exact(2)
            .map(|pair| block_node(pair[0], pair[1]))
            .collect();
        index /= 2;
    }
    Ok(proof)
}

pub fn verify_block_merkle_proof(
    root: B256,
    block_number: u64,
    block_hash: B256,
    siblings: &[B256],
) -> bool {
    if siblings.len() != EPOCH_TREE_DEPTH || block_number < HISTORICAL_START_BLOCK {
        return false;
    }
    let mut index = (block_number - HISTORICAL_START_BLOCK) % EPOCH_SIZE as u64;
    let mut current = block_leaf(block_number, block_hash);
    for sibling in siblings {
        current = if index & 1 == 0 {
            block_node(current, *sibling)
        } else {
            block_node(*sibling, current)
        };
        index >>= 1;
    }
    current == root
}

pub fn epoch_commitment(journal: &EpochJournal) -> B256 {
    let mut input = Vec::with_capacity(1 + 8 + 4 + 8 + 8 + 32 + 32 + 32);
    input.push(EPOCH_LEAF_DOMAIN);
    input.extend_from_slice(&journal.chainId.to_be_bytes());
    input.extend_from_slice(&journal.epochIndex.to_be_bytes());
    input.extend_from_slice(&journal.startBlockNumber.to_be_bytes());
    input.extend_from_slice(&journal.endBlockNumber.to_be_bytes());
    input.extend_from_slice(journal.firstParentHash.as_slice());
    input.extend_from_slice(journal.endBlockHash.as_slice());
    input.extend_from_slice(journal.blockRoot.as_slice());
    keccak256(input)
}

pub fn mmr_node(height: u8, left: B256, right: B256) -> B256 {
    let mut input = [0_u8; 66];
    input[0] = MMR_NODE_DOMAIN;
    input[1] = height;
    input[2..34].copy_from_slice(left.as_slice());
    input[34..].copy_from_slice(right.as_slice());
    keccak256(input)
}

pub fn mmr_peaks(leaves: &[B256]) -> Result<Vec<B256>, String> {
    if leaves.is_empty() {
        return Err("MMR requires at least one leaf".into());
    }
    let mut peaks_by_height: Vec<Option<B256>> = Vec::new();
    for leaf in leaves {
        let mut current = *leaf;
        let mut height = 0usize;
        loop {
            if height == peaks_by_height.len() {
                peaks_by_height.push(Some(current));
                break;
            }
            if let Some(left) = peaks_by_height[height].take() {
                current = mmr_node((height + 1) as u8, left, current);
                height += 1;
            } else {
                peaks_by_height[height] = Some(current);
                break;
            }
        }
    }
    Ok(peaks_by_height.into_iter().rev().flatten().collect())
}

pub fn mmr_root(epoch_count: u32, peaks: &[B256]) -> B256 {
    let mut input = Vec::with_capacity(5 + peaks.len() * 32);
    input.push(MMR_ROOT_DOMAIN);
    input.extend_from_slice(&epoch_count.to_be_bytes());
    for peak in peaks {
        input.extend_from_slice(peak.as_slice());
    }
    keccak256(input)
}

pub fn mmr_proof(leaves: &[B256], target: usize) -> Result<MmrProof, String> {
    if target >= leaves.len() || leaves.is_empty() {
        return Err("MMR target out of range".into());
    }
    let mountains = mountain_ranges(leaves.len());
    let (target_peak_index, (start, size)) = mountains
        .iter()
        .copied()
        .enumerate()
        .find(|(_, (start, size))| target >= *start && target < *start + *size)
        .ok_or("MMR target mountain missing")?;
    let mut layer = leaves[start..start + size].to_vec();
    let mut index = target - start;
    let mut siblings = Vec::with_capacity(size.trailing_zeros() as usize);
    while layer.len() > 1 {
        siblings.push(layer[index ^ 1]);
        let height = siblings.len() as u8;
        layer = layer
            .chunks_exact(2)
            .map(|pair| mmr_node(height, pair[0], pair[1]))
            .collect();
        index /= 2;
    }
    Ok(MmrProof {
        mountain_siblings: siblings,
        peaks: mmr_peaks(leaves)?,
        target_peak_index: target_peak_index as u32,
    })
}

pub fn verify_mmr_proof(
    root: B256,
    epoch_count: u32,
    epoch_index: u32,
    leaf: B256,
    proof: &MmrProof,
) -> bool {
    if epoch_count == 0 || epoch_index >= epoch_count {
        return false;
    }
    let mountains = mountain_ranges(epoch_count as usize);
    let Some((target_peak_index, (start, size))) =
        mountains
            .iter()
            .copied()
            .enumerate()
            .find(|(_, (start, size))| {
                epoch_index as usize >= *start && (epoch_index as usize) < *start + *size
            })
    else {
        return false;
    };
    if proof.target_peak_index as usize != target_peak_index
        || proof.peaks.len() != mountains.len()
        || proof.mountain_siblings.len() != size.trailing_zeros() as usize
    {
        return false;
    }
    let mut index = epoch_index as usize - start;
    let mut current = leaf;
    for (level, sibling) in proof.mountain_siblings.iter().enumerate() {
        current = if index & 1 == 0 {
            mmr_node((level + 1) as u8, current, *sibling)
        } else {
            mmr_node((level + 1) as u8, *sibling, current)
        };
        index >>= 1;
    }
    current == proof.peaks[target_peak_index] && mmr_root(epoch_count, &proof.peaks) == root
}

fn mountain_ranges(count: usize) -> Vec<(usize, usize)> {
    let mut remaining = count;
    let mut start = 0usize;
    let mut ranges = Vec::new();
    while remaining > 0 {
        let height = usize::BITS - 1 - remaining.leading_zeros();
        let size = 1usize << height;
        ranges.push((start, size));
        start += size;
        remaining -= size;
    }
    ranges
}

fn hash_pair(domain: u8, left: B256, right: B256) -> B256 {
    let mut input = [0_u8; 65];
    input[0] = domain;
    input[1..33].copy_from_slice(left.as_slice());
    input[33..].copy_from_slice(right.as_slice());
    keccak256(input)
}

fn merkle_root(
    mut layer: Vec<B256>,
    node: impl Fn(B256, B256) -> B256 + Copy,
) -> Result<B256, String> {
    if layer.is_empty() || !layer.len().is_power_of_two() {
        return Err("Merkle layer length must be a non-zero power of two".into());
    }
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| node(pair[0], pair[1]))
            .collect();
    }
    Ok(layer[0])
}

impl EpochJournal {
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        Self::abi_decode(data).map_err(|error| format!("epoch journal ABI: {error}"))
    }
}

impl AccumulatorJournal {
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        Self::abi_decode(data).map_err(|error| format!("accumulator journal ABI: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmr_membership_round_trips_multiple_peak_shapes() {
        for count in 1..40usize {
            let leaves = (0..count)
                .map(|index| keccak256(index.to_be_bytes()))
                .collect::<Vec<_>>();
            let peaks = mmr_peaks(&leaves).unwrap();
            let root = mmr_root(count as u32, &peaks);
            for target in 0..count {
                let proof = mmr_proof(&leaves, target).unwrap();
                assert!(verify_mmr_proof(
                    root,
                    count as u32,
                    target as u32,
                    leaves[target],
                    &proof
                ));
                assert!(!verify_mmr_proof(
                    root,
                    count as u32,
                    target as u32,
                    B256::ZERO,
                    &proof
                ));
            }
        }
    }

    #[test]
    fn epoch_ranges_are_aligned() {
        assert_eq!(epoch_start(0).unwrap(), HISTORICAL_START_BLOCK);
        assert_eq!(
            epoch_end(0).unwrap(),
            HISTORICAL_START_BLOCK + EPOCH_SIZE as u64 - 1
        );
        assert_eq!(
            epoch_start(1).unwrap(),
            HISTORICAL_START_BLOCK + EPOCH_SIZE as u64
        );
    }
}
