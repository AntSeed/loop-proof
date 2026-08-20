use alloy_consensus::Header;
use alloy_primitives::{B256, Bytes};
use alloy_rlp::Decodable;
use alloy_sol_types::{SolValue, sol};
use serde::{Deserialize, Serialize};

pub const JOURNAL_VERSION: u32 = 1;
pub const BASE_CHAIN_ID: u64 = 8_453;
pub const HISTORICAL_START_BLOCK: u64 = 44_469_557;
pub const HISTORICAL_ANCHOR_BLOCK: u64 = 46_302_990;
pub const HISTORICAL_END_BLOCK: u64 = HISTORICAL_ANCHOR_BLOCK - 1;
pub const CHUNK_SIZE: usize = 16_384;
pub const CHUNK_TREE_DEPTH: usize = 14;
pub const HISTORICAL_BLOCK_COUNT: u64 = HISTORICAL_ANCHOR_BLOCK - HISTORICAL_START_BLOCK;
pub const HISTORICAL_CHUNK_COUNT: usize = 112;
pub const GLOBAL_TREE_LEAF_COUNT: usize = 128;
pub const MAX_BOUNDLESS_INPUT_BYTES: usize = 50_000_000;

#[cfg(target_os = "zkvm")]
const KECCAK_RATE_BYTES: usize = 136;

const BLOCK_LEAF_DOMAIN: u8 = 0x00;
const BLOCK_PADDING_DOMAIN: u8 = 0x01;
const BLOCK_NODE_DOMAIN: u8 = 0x02;
const CHUNK_LEAF_DOMAIN: u8 = 0x10;
const CHUNK_PADDING_DOMAIN: u8 = 0x11;
const CHUNK_NODE_DOMAIN: u8 = 0x12;

sol! {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct HistoricalChunkJournal {
        uint32 version;
        uint64 chainId;
        uint64 startBlockNumber;
        uint64 endBlockNumber;
        uint64 successorBlockNumber;
        bytes32 startBlockHash;
        bytes32 endBlockHash;
        bytes32 successorBlockHash;
        uint32 blockCount;
        bytes32 blockRoot;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoricalChunkWitness {
    pub base_headers_rlp: Vec<Bytes>,
    pub successor_header_rlp: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkBounds {
    pub index_from_newest: u16,
    pub start_block: u64,
    pub end_block: u64,
    pub successor_block: u64,
}

pub fn historical_chunk_bounds() -> Vec<ChunkBounds> {
    let mut frontier = HISTORICAL_ANCHOR_BLOCK;
    let mut chunks = Vec::with_capacity(HISTORICAL_CHUNK_COUNT);
    while frontier > HISTORICAL_START_BLOCK {
        let end_block = frontier - 1;
        let start_block = frontier
            .saturating_sub(CHUNK_SIZE as u64)
            .max(HISTORICAL_START_BLOCK);
        chunks.push(ChunkBounds {
            index_from_newest: u16::try_from(chunks.len()).expect("chunk count fits u16"),
            start_block,
            end_block,
            successor_block: frontier,
        });
        frontier = start_block;
    }
    chunks
}

pub fn validate_history_chunk(
    witness: &HistoricalChunkWitness,
) -> Result<HistoricalChunkJournal, String> {
    if witness.base_headers_rlp.is_empty() {
        return Err("missing historical headers".into());
    }
    if witness.base_headers_rlp.len() > CHUNK_SIZE {
        return Err("historical chunk exceeds 16,384 headers".into());
    }

    let mut headers = Vec::with_capacity(witness.base_headers_rlp.len());
    for encoded in &witness.base_headers_rlp {
        headers.push(decode_canonical_header(encoded)?);
    }
    let successor = decode_canonical_header(&witness.successor_header_rlp)?;
    let hashes = witness
        .base_headers_rlp
        .iter()
        .map(|encoded| keccak256(encoded.as_ref()))
        .collect::<Vec<_>>();

    let first = headers.first().expect("checked non-empty");
    let last = headers.last().expect("checked non-empty");
    if first.number < HISTORICAL_START_BLOCK || last.number > HISTORICAL_END_BLOCK {
        return Err("historical chunk is outside the supported range".into());
    }
    if last.number - first.number + 1 != headers.len() as u64 {
        return Err("historical header count does not match block range".into());
    }
    for index in 1..headers.len() {
        if headers[index].number != headers[index - 1].number + 1 {
            return Err("historical headers are not contiguous".into());
        }
        if headers[index].parent_hash != hashes[index - 1] {
            return Err("historical header parent hash mismatch".into());
        }
    }
    if successor.number != last.number + 1 {
        return Err("historical successor block number mismatch".into());
    }
    if successor.parent_hash != *hashes.last().expect("checked non-empty") {
        return Err("historical successor parent hash mismatch".into());
    }

    let block_root = block_merkle_root(first.number, &hashes)?;
    Ok(HistoricalChunkJournal {
        version: JOURNAL_VERSION,
        chainId: BASE_CHAIN_ID,
        startBlockNumber: first.number,
        endBlockNumber: last.number,
        successorBlockNumber: successor.number,
        startBlockHash: hashes[0],
        endBlockHash: *hashes.last().expect("checked non-empty"),
        successorBlockHash: keccak256(witness.successor_header_rlp.as_ref()),
        blockCount: u32::try_from(headers.len()).expect("bounded chunk length"),
        blockRoot: block_root,
    })
}

fn decode_canonical_header(encoded: &Bytes) -> Result<Header, String> {
    let mut input = encoded.as_ref();
    let header =
        Header::decode(&mut input).map_err(|error| format!("invalid Base header RLP: {error}"))?;
    if !input.is_empty() {
        return Err("trailing bytes in Base header RLP".into());
    }
    if alloy_rlp::encode(&header).as_slice() != encoded.as_ref() {
        return Err("non-canonical Base header RLP".into());
    }
    Ok(header)
}

pub fn block_leaf(block_number: u64, block_hash: B256) -> B256 {
    let mut input = [0_u8; 41];
    input[0] = BLOCK_LEAF_DOMAIN;
    input[1..9].copy_from_slice(&block_number.to_be_bytes());
    input[9..].copy_from_slice(block_hash.as_slice());
    keccak256(input)
}

pub fn block_padding_leaf(chunk_start: u64, slot: u32) -> B256 {
    let mut input = [0_u8; 13];
    input[0] = BLOCK_PADDING_DOMAIN;
    input[1..9].copy_from_slice(&chunk_start.to_be_bytes());
    input[9..].copy_from_slice(&slot.to_be_bytes());
    keccak256(input)
}

pub fn block_node(left: B256, right: B256) -> B256 {
    hash_pair(BLOCK_NODE_DOMAIN, left, right)
}

pub fn block_merkle_root(chunk_start: u64, block_hashes: &[B256]) -> Result<B256, String> {
    if block_hashes.is_empty() || block_hashes.len() > CHUNK_SIZE {
        return Err("invalid historical block leaf count".into());
    }
    let mut layer = Vec::with_capacity(CHUNK_SIZE);
    for (index, block_hash) in block_hashes.iter().copied().enumerate() {
        layer.push(block_leaf(chunk_start + index as u64, block_hash));
    }
    for slot in block_hashes.len()..CHUNK_SIZE {
        layer.push(block_padding_leaf(chunk_start, slot as u32));
    }
    merkle_root(layer, block_node)
}

pub fn block_merkle_proof(
    chunk_start: u64,
    block_hashes: &[B256],
    block_number: u64,
) -> Result<Vec<B256>, String> {
    if block_number < chunk_start {
        return Err("block predates chunk".into());
    }
    let target = usize::try_from(block_number - chunk_start).map_err(|_| "block index overflow")?;
    if target >= block_hashes.len() {
        return Err("block is outside chunk".into());
    }
    let mut layer = Vec::with_capacity(CHUNK_SIZE);
    for (index, block_hash) in block_hashes.iter().copied().enumerate() {
        layer.push(block_leaf(chunk_start + index as u64, block_hash));
    }
    for slot in block_hashes.len()..CHUNK_SIZE {
        layer.push(block_padding_leaf(chunk_start, slot as u32));
    }
    let mut proof = Vec::with_capacity(CHUNK_TREE_DEPTH);
    let mut index = target;
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
    chunk_start: u64,
    block_number: u64,
    block_hash: B256,
    siblings: &[B256],
) -> bool {
    if siblings.len() != CHUNK_TREE_DEPTH || block_number < chunk_start {
        return false;
    }
    let mut index = block_number - chunk_start;
    if index >= CHUNK_SIZE as u64 {
        return false;
    }
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

pub fn chunk_commitment(journal: &HistoricalChunkJournal) -> B256 {
    let mut input = [0_u8; 49];
    input[0] = CHUNK_LEAF_DOMAIN;
    input[1..9].copy_from_slice(&journal.startBlockNumber.to_be_bytes());
    input[9..17].copy_from_slice(&journal.endBlockNumber.to_be_bytes());
    input[17..].copy_from_slice(journal.blockRoot.as_slice());
    keccak256(input)
}

pub fn global_historical_root(
    journals_newest_first: &[HistoricalChunkJournal],
) -> Result<B256, String> {
    if journals_newest_first.len() != HISTORICAL_CHUNK_COUNT {
        return Err("historical root requires exactly 112 chunks".into());
    }
    let mut layer = Vec::with_capacity(GLOBAL_TREE_LEAF_COUNT);
    for journal in journals_newest_first {
        layer.push(chunk_commitment(journal));
    }
    for slot in journals_newest_first.len()..GLOBAL_TREE_LEAF_COUNT {
        let mut input = [0_u8; 3];
        input[0] = CHUNK_PADDING_DOMAIN;
        input[1..].copy_from_slice(&(slot as u16).to_be_bytes());
        layer.push(keccak256(input));
    }
    merkle_root(layer, |left, right| {
        hash_pair(CHUNK_NODE_DOMAIN, left, right)
    })
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

fn hash_pair(domain: u8, left: B256, right: B256) -> B256 {
    let mut input = [0_u8; 65];
    input[0] = domain;
    input[1..33].copy_from_slice(left.as_slice());
    input[33..].copy_from_slice(right.as_slice());
    keccak256(input)
}

#[cfg(not(target_os = "zkvm"))]
fn keccak256(input: impl AsRef<[u8]>) -> B256 {
    alloy_primitives::keccak256(input)
}

#[cfg(target_os = "zkvm")]
fn keccak256(input: impl AsRef<[u8]>) -> B256 {
    let input = input.as_ref();
    let mut state = [0_u64; 25];
    let mut chunks = input.chunks_exact(KECCAK_RATE_BYTES);
    for chunk in &mut chunks {
        absorb_keccak_block(&mut state, chunk);
        risc0_zkvm::guest::env::risc0_keccak_update(&mut state);
    }

    let remainder = chunks.remainder();
    absorb_keccak_block(&mut state, remainder);
    state[remainder.len() / 8] ^= 1_u64 << ((remainder.len() % 8) * 8);
    state[(KECCAK_RATE_BYTES - 1) / 8] ^= 0x80_u64 << (((KECCAK_RATE_BYTES - 1) % 8) * 8);
    risc0_zkvm::guest::env::risc0_keccak_update(&mut state);

    let mut digest = [0_u8; 32];
    for (index, output) in digest.chunks_exact_mut(8).enumerate() {
        output.copy_from_slice(&state[index].to_le_bytes());
    }
    digest.into()
}

#[cfg(target_os = "zkvm")]
fn absorb_keccak_block(state: &mut [u64; 25], block: &[u8]) {
    for (index, byte) in block.iter().copied().enumerate() {
        state[index / 8] ^= u64::from(byte) << ((index % 8) * 8);
    }
}

impl HistoricalChunkJournal {
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        Self::abi_decode(data).map_err(|error| format!("historical journal ABI: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(start: u64, count: usize) -> (Vec<Header>, Header) {
        let mut headers: Vec<Header> = Vec::with_capacity(count);
        for index in 0..=count {
            let mut header = Header {
                number: start + index as u64,
                ..Default::default()
            };
            if let Some(previous) = headers.last() {
                header.parent_hash = previous.hash_slow();
            }
            headers.push(header);
        }
        let successor = headers.pop().unwrap();
        (headers, successor)
    }

    fn witness(start: u64, count: usize) -> HistoricalChunkWitness {
        let (headers, successor) = headers(start, count);
        HistoricalChunkWitness {
            base_headers_rlp: headers
                .into_iter()
                .map(|header| alloy_rlp::encode(header).into())
                .collect(),
            successor_header_rlp: alloy_rlp::encode(successor).into(),
        }
    }

    #[test]
    fn derives_exact_historical_chunks() {
        let chunks = historical_chunk_bounds();
        assert_eq!(chunks.len(), HISTORICAL_CHUNK_COUNT);
        assert_eq!(chunks[0].end_block, HISTORICAL_END_BLOCK);
        assert_eq!(
            chunks[0].end_block - chunks[0].start_block + 1,
            CHUNK_SIZE as u64
        );
        let oldest = chunks.last().unwrap();
        assert_eq!(oldest.start_block, HISTORICAL_START_BLOCK);
        assert_eq!(oldest.end_block - oldest.start_block + 1, 14_809);
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.end_block - chunk.start_block + 1)
                .sum::<u64>(),
            HISTORICAL_BLOCK_COUNT
        );
    }

    #[test]
    fn validates_linked_chunk_and_merkle_membership() {
        let witness = witness(HISTORICAL_START_BLOCK, 3);
        let journal = validate_history_chunk(&witness).unwrap();
        let hashes = witness
            .base_headers_rlp
            .iter()
            .map(|encoded| keccak256(encoded.as_ref()))
            .collect::<Vec<_>>();
        let proof = block_merkle_proof(
            journal.startBlockNumber,
            &hashes,
            journal.startBlockNumber + 1,
        )
        .unwrap();
        assert!(verify_block_merkle_proof(
            journal.blockRoot,
            journal.startBlockNumber,
            journal.startBlockNumber + 1,
            hashes[1],
            &proof
        ));
    }

    #[test]
    fn rejects_broken_successor_link() {
        let mut witness = witness(HISTORICAL_START_BLOCK, 2);
        let successor = Header {
            number: HISTORICAL_START_BLOCK + 2,
            ..Default::default()
        };
        witness.successor_header_rlp = alloy_rlp::encode(successor).into();
        assert!(
            validate_history_chunk(&witness)
                .unwrap_err()
                .contains("successor parent")
        );
    }

    #[test]
    fn rejects_chunk_larger_than_tree() {
        let mut witness = witness(HISTORICAL_START_BLOCK, 1);
        witness.base_headers_rlp = vec![Bytes::new(); CHUNK_SIZE + 1];
        assert!(
            validate_history_chunk(&witness)
                .unwrap_err()
                .contains("16,384")
        );
    }

    #[test]
    fn rejects_headers_outside_historical_range() {
        assert!(
            validate_history_chunk(&witness(HISTORICAL_START_BLOCK - 1, 1))
                .unwrap_err()
                .contains("supported range")
        );
    }

    #[test]
    fn rejects_broken_internal_parent_link() {
        let mut witness = witness(HISTORICAL_START_BLOCK, 2);
        let second = Header {
            number: HISTORICAL_START_BLOCK + 1,
            ..Default::default()
        };
        witness.base_headers_rlp[1] = alloy_rlp::encode(second).into();
        assert!(
            validate_history_chunk(&witness)
                .unwrap_err()
                .contains("parent hash")
        );
    }

    #[test]
    fn rejects_trailing_rlp_bytes() {
        let mut witness = witness(HISTORICAL_START_BLOCK, 1);
        let mut encoded = witness.base_headers_rlp[0].to_vec();
        encoded.push(0);
        witness.base_headers_rlp[0] = encoded.into();
        assert!(
            validate_history_chunk(&witness)
                .unwrap_err()
                .contains("trailing bytes")
        );
    }

    #[test]
    fn merkle_proofs_are_positional() {
        let witness = witness(HISTORICAL_START_BLOCK, 3);
        let journal = validate_history_chunk(&witness).unwrap();
        let hashes = witness
            .base_headers_rlp
            .iter()
            .map(|encoded| keccak256(encoded.as_ref()))
            .collect::<Vec<_>>();
        let mut proof = block_merkle_proof(
            journal.startBlockNumber,
            &hashes,
            journal.startBlockNumber + 1,
        )
        .unwrap();
        proof.swap(0, 1);
        assert!(!verify_block_merkle_proof(
            journal.blockRoot,
            journal.startBlockNumber,
            journal.startBlockNumber + 1,
            hashes[1],
            &proof,
        ));
    }

    #[test]
    fn global_root_is_deterministic_and_ordered() {
        let chunks = historical_chunk_bounds();
        let journals = chunks
            .iter()
            .map(|chunk| validate_history_chunk(&witness(chunk.start_block, 1)).unwrap())
            .collect::<Vec<_>>();
        let root = global_historical_root(&journals).unwrap();
        assert_eq!(root, global_historical_root(&journals).unwrap());

        let mut reordered = journals;
        reordered.swap(0, 1);
        assert_ne!(root, global_historical_root(&reordered).unwrap());
    }

    #[test]
    fn matches_solidity_positional_merkle_fixture() {
        let chunk_start = 46_286_606;
        let block_number = chunk_start + 123;
        let block_hash = keccak256("historical-block");
        let siblings = (0_u64..14)
            .map(|index| {
                let mut input = [0_u8; 39];
                input[..7].copy_from_slice(b"sibling");
                input[31..].copy_from_slice(&index.to_be_bytes());
                keccak256(input)
            })
            .collect::<Vec<_>>();
        let root = alloy_primitives::b256!(
            "7e1834c5af9c8f513d7af729f62ee8719b32a7e7fae4757b5aaf8699eaa54f4f"
        );
        assert!(verify_block_merkle_proof(
            root,
            chunk_start,
            block_number,
            block_hash,
            &siblings,
        ));
    }
}
