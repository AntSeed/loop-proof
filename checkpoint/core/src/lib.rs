use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_rlp::Decodable;
use alloy_sol_types::{SolValue, sol};
use serde::{Deserialize, Serialize};

pub const BASE_CHAIN_ID: u64 = 8_453;
pub const ETHEREUM_CHAIN_ID: u64 = 1;
pub const AGGREGATE_GAME_TYPE: u32 = 621;
pub const INTERMEDIATE_BLOCK_INTERVAL: u64 = 30;
pub const INTERMEDIATE_ROOT_COUNT: u8 = 20;
pub const AGGREGATE_VERIFIER_START_BLOCK: u64 = 46_302_960;
pub const ANCHOR_STATE_REGISTRY: Address = address!("909f6cf47ed12f010A796527f562bFc26C7F4E72");
pub const DISPUTE_GAME_FACTORY: Address = address!("43edB88C4B80fDD2AdFF2412A7BebF9dF42cB40e");
pub const MESSAGE_PASSER: Address = address!("4200000000000000000000000000000000000016");
pub const ETHEREUM_MAINNET_CONFIG_ID: B256 =
    alloy_primitives::b256!("47dc59f84afd2e9e7a48c4012004ab7c77fbd9acf822bf1143b8442c6c8851d4");

sol! {
    interface IAnchorStateRegistry {
        function isGameClaimValid(address game) external view returns (bool);
    }

    interface IAggregateVerifier {
        function gameType() external view returns (uint32);
        function startingBlockNumber() external view returns (uint256);
        function INTERMEDIATE_BLOCK_INTERVAL() external view returns (uint256);
        function intermediateOutputRoot(uint256 index) external view returns (bytes32);
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct SteelCommitment {
        uint256 id;
        bytes32 digest;
        bytes32 configID;
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct CanonicalBlockRef {
        uint64 number;
        bytes32 blockHash;
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct CheckpointJournal {
        SteelCommitment ethereumCommitment;
        uint64 chainId;
        address anchorStateRegistry;
        address game;
        uint8 intermediateRootIndex;
        uint64 checkpointBlockNumber;
        bytes32 checkpointBlockHash;
        bytes32 outputRoot;
        CanonicalBlockRef[] canonicalBlocks;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointWitness {
    pub game: Address,
    pub intermediate_root_index: u8,
    pub message_passer_storage_root: B256,
    /// RLP-encoded contiguous Base headers ordered oldest through checkpoint.
    pub base_headers_rlp: Vec<Bytes>,
    /// Sorted, unique target block numbers. The checkpoint itself is added to the journal.
    pub target_block_numbers: Vec<u64>,
}

pub fn output_root(
    state_root: B256,
    message_passer_storage_root: B256,
    checkpoint_block_hash: B256,
) -> B256 {
    keccak256(
        (
            B256::ZERO,
            state_root,
            message_passer_storage_root,
            checkpoint_block_hash,
        )
            .abi_encode(),
    )
}

pub fn checkpoint_block_number(starting_block_number: U256, index: u8) -> Result<u64, String> {
    if index >= INTERMEDIATE_ROOT_COUNT {
        return Err("intermediate root index out of range".into());
    }
    let start =
        u64::try_from(starting_block_number).map_err(|_| "starting block does not fit u64")?;
    start
        .checked_add(INTERMEDIATE_BLOCK_INTERVAL * (u64::from(index) + 1))
        .ok_or_else(|| "checkpoint block overflow".into())
}

pub fn validate_header_chain(
    witness: &CheckpointWitness,
    checkpoint_number: u64,
    expected_output_root: B256,
) -> Result<Vec<CanonicalBlockRef>, String> {
    if witness.base_headers_rlp.is_empty() {
        return Err("missing Base headers".into());
    }
    if witness.target_block_numbers.is_empty() {
        return Err("missing target blocks".into());
    }

    let mut base_headers = Vec::with_capacity(witness.base_headers_rlp.len());
    for encoded in &witness.base_headers_rlp {
        let mut input = encoded.as_ref();
        let header = Header::decode(&mut input)
            .map_err(|error| format!("invalid Base header RLP: {error}"))?;
        if !input.is_empty() {
            return Err("trailing bytes in Base header RLP".into());
        }
        base_headers.push(header);
    }

    let checkpoint = base_headers.last().expect("checked non-empty");
    if checkpoint.number != checkpoint_number {
        return Err("last header is not the checkpoint block".into());
    }
    if checkpoint.number < AGGREGATE_VERIFIER_START_BLOCK {
        return Err("checkpoint predates AggregateVerifier coverage".into());
    }

    for pair in base_headers.windows(2) {
        let older = &pair[0];
        let newer = &pair[1];
        if newer.number != older.number + 1 {
            return Err("Base headers are not contiguous".into());
        }
        if newer.parent_hash != older.hash_slow() {
            return Err("Base header parent hash mismatch".into());
        }
    }

    let checkpoint_hash = checkpoint.hash_slow();
    let calculated_output_root = output_root(
        checkpoint.state_root,
        witness.message_passer_storage_root,
        checkpoint_hash,
    );
    if calculated_output_root != expected_output_root {
        return Err("checkpoint output root mismatch".into());
    }

    let oldest_allowed = checkpoint_number.saturating_sub(INTERMEDIATE_BLOCK_INTERVAL - 1);
    let mut previous_target = None;
    let mut canonical_blocks = Vec::with_capacity(witness.target_block_numbers.len() + 1);
    for target in &witness.target_block_numbers {
        if *target < oldest_allowed || *target > checkpoint_number {
            return Err("target is outside the checkpoint window".into());
        }
        if previous_target.is_some_and(|previous| *target <= previous) {
            return Err("target block numbers must be sorted and unique".into());
        }
        let header = witness
            .base_headers_rlp
            .iter()
            .zip(&base_headers)
            .map(|(_, header)| header)
            .find(|header| header.number == *target)
            .ok_or_else(|| "target header missing from ancestry chain".to_string())?;
        canonical_blocks.push(CanonicalBlockRef {
            number: *target,
            blockHash: header.hash_slow(),
        });
        previous_target = Some(*target);
    }

    if canonical_blocks
        .last()
        .is_none_or(|block_ref| block_ref.number != checkpoint_number)
    {
        canonical_blocks.push(CanonicalBlockRef {
            number: checkpoint_number,
            blockHash: checkpoint_hash,
        });
    }
    Ok(canonical_blocks)
}

impl CheckpointJournal {
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        Self::abi_decode(data).map_err(|error| format!("checkpoint journal ABI: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness_with_headers(headers: &[Header], targets: Vec<u64>) -> CheckpointWitness {
        CheckpointWitness {
            game: Address::ZERO,
            intermediate_root_index: 0,
            message_passer_storage_root: B256::ZERO,
            base_headers_rlp: headers
                .iter()
                .map(alloy_rlp::encode)
                .map(Into::into)
                .collect(),
            target_block_numbers: targets,
        }
    }

    #[test]
    fn computes_checkpoint_number() {
        assert_eq!(
            checkpoint_block_number(U256::from(49_934_160), 19).unwrap(),
            49_934_760
        );
    }

    #[test]
    fn output_root_matches_live_base_checkpoint() {
        let state_root = alloy_primitives::b256!(
            "1d109dd22bd836a5c43f5eb27ca0954e3603e572c2b57cff44e68eb95fbb9fd8"
        );
        let storage_root = alloy_primitives::b256!(
            "71e2045e5ab04a138afadf753237ddedb825336c1f1dc4a95e4a634158f20874"
        );
        let block_hash = alloy_primitives::b256!(
            "e48cfd964bca19ba9b265a328b6557dad192a3950c69003dc8fa422da4f7c8d0"
        );
        assert_eq!(
            output_root(state_root, storage_root, block_hash),
            alloy_primitives::b256!(
                "8f641efa6c3c2b91d6d543af527c0a24176d32abb03f3f42b498d0165627c5ff"
            )
        );
    }

    #[test]
    fn validates_contiguous_header_ancestry() {
        let older = Header {
            number: AGGREGATE_VERIFIER_START_BLOCK,
            ..Default::default()
        };
        let checkpoint = Header {
            number: older.number + 1,
            parent_hash: older.hash_slow(),
            ..Default::default()
        };
        let expected_root = output_root(checkpoint.state_root, B256::ZERO, checkpoint.hash_slow());
        let witness = witness_with_headers(&[older.clone(), checkpoint], vec![older.number]);

        let blocks = validate_header_chain(&witness, older.number + 1, expected_root).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].number, older.number);
        assert_eq!(blocks[1].number, older.number + 1);
    }

    #[test]
    fn rejects_broken_header_ancestry() {
        let older = Header {
            number: AGGREGATE_VERIFIER_START_BLOCK,
            ..Default::default()
        };
        let checkpoint = Header {
            number: older.number + 1,
            ..Default::default()
        };
        let expected_root = output_root(checkpoint.state_root, B256::ZERO, checkpoint.hash_slow());
        let witness = witness_with_headers(&[older.clone(), checkpoint], vec![older.number]);

        assert_eq!(
            validate_header_chain(&witness, older.number + 1, expected_root).unwrap_err(),
            "Base header parent hash mismatch"
        );
    }
}
