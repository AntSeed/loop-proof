use alloy::{
    eips::BlockId,
    primitives::{Address, B256, Bytes, U256, address},
    providers::{Provider, ProviderBuilder},
    sol,
};
use anyhow::{Context, Result, ensure};
use clap::Parser;
use futures::{StreamExt, TryStreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
use url::Url;

const BASE_CHAIN_ID: u64 = 8_453;
const AGGREGATE_GAME_TYPE: u32 = 621;
const AGGREGATE_VERIFIER_START_BLOCK: u64 = 46_302_960;
const GAME_BLOCK_INTERVAL: u64 = 600;
const CHECKPOINT_WINDOW_BLOCKS: u64 = 30;
const DISPUTE_GAME_FACTORY: Address = address!("43edB88C4B80fDD2AdFF2412A7BebF9dF42cB40e");
const ANCHOR_STATE_REGISTRY: Address = address!("909f6cf47ed12f010A796527f562bFc26C7F4E72");
const PAGE_SIZE: u64 = 100;

sol! {
    #[sol(rpc)]
    interface IDisputeGameFactoryCatalog {
        struct GameSearchResult {
            uint256 index;
            bytes32 metadata;
            uint64 timestamp;
            bytes32 rootClaim;
            bytes extraData;
        }

        function gameCount() external view returns (uint256);
        function findLatestGames(uint32 gameType, uint256 start, uint256 count)
            external
            view
            returns (GameSearchResult[] memory);
    }

    #[sol(rpc)]
    interface IAnchorStateRegistryCatalog {
        function isGameClaimValid(address game) external view returns (bool);
    }

    #[sol(rpc)]
    interface IAggregateVerifierCatalog {
        function gameType() external view returns (uint32);
        function startingBlockNumber() external view returns (uint256);
        function BLOCK_INTERVAL() external view returns (uint256);
        function INTERMEDIATE_BLOCK_INTERVAL() external view returns (uint256);
    }
}

#[derive(Parser, Debug)]
#[command(about = "Resolve selected Base evidence windows to finalized ASR-valid games")]
struct Args {
    #[arg(
        long,
        env = "L1_RPC_URL",
        default_value = "https://ethereum-rpc.publicnode.com"
    )]
    l1_rpc_url: Url,

    #[arg(long)]
    selection: PathBuf,

    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SelectionManifest {
    version: u32,
    chain_id: u64,
    start_block: u64,
    end_block_exclusive: u64,
    aggregate_verifier_start_block: u64,
    selected_block_numbers: Vec<u64>,
    checkpoint_windows: Vec<SelectedCheckpointWindow>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SelectedCheckpointWindow {
    checkpoint_block_number: u64,
    target_blocks: Vec<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct CheckpointPlan {
    version: u32,
    selection_version: u32,
    chain_id: u64,
    start_block: u64,
    end_block_exclusive: u64,
    ethereum_finalized_block_number: u64,
    ethereum_finalized_block_hash: B256,
    game_type: u32,
    game_block_interval: u64,
    checkpoint_window_blocks: u64,
    proofs: Vec<CheckpointProofPlan>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct CheckpointProofPlan {
    game: Address,
    game_start_block: u64,
    intermediate_root_index: u8,
    checkpoint_block_number: u64,
    target_blocks: Vec<u64>,
}

#[derive(Clone, Debug)]
struct CatalogGame {
    address: Address,
    starting_block_number: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    dotenvy::from_filename("../.env").ok();
    let args = Args::parse();
    let selection: SelectionManifest = serde_json::from_slice(&std::fs::read(&args.selection)?)?;
    let required_windows = validate_selection(&selection)?;

    let provider = ProviderBuilder::new().connect_http(args.l1_rpc_url);
    let finalized_block = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Finalized)
        .hashes()
        .await?
        .context("finalized Ethereum block unavailable")?;
    let finalized_number = finalized_block.header.number;
    let finalized_hash = finalized_block.header.hash;
    let block_id = BlockId::number(finalized_number);

    let minimum_game_start = *required_windows
        .keys()
        .next()
        .context("selection contains no checkpoint windows")?;
    let maximum_game_start = *required_windows.keys().next_back().unwrap();
    let catalog =
        discover_games(&provider, block_id, minimum_game_start, maximum_game_start).await?;

    let proofs = stream::iter(required_windows.into_iter())
        .map(|(game_start, windows)| {
            let provider = &provider;
            let catalog_game = catalog.get(&game_start).cloned();
            async move {
                let catalog_game = catalog_game.with_context(|| {
                    format!("no type-{AGGREGATE_GAME_TYPE} game covers Base block {game_start}")
                })?;
                validate_game(provider, block_id, &catalog_game).await?;
                Ok::<_, anyhow::Error>(
                    windows
                        .into_iter()
                        .map(|window| CheckpointProofPlan {
                            game: catalog_game.address,
                            game_start_block: game_start,
                            intermediate_root_index: intermediate_root_index(
                                game_start,
                                window.checkpoint_block_number,
                            )
                            .expect("selection was already validated"),
                            checkpoint_block_number: window.checkpoint_block_number,
                            target_blocks: window.target_blocks,
                        })
                        .collect::<Vec<_>>(),
                )
            }
        })
        .buffer_unordered(16)
        .try_collect::<Vec<_>>()
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let mut proofs = proofs;
    proofs.sort_by_key(|proof| proof.checkpoint_block_number);

    let plan = CheckpointPlan {
        version: 1,
        selection_version: selection.version,
        chain_id: selection.chain_id,
        start_block: selection.start_block,
        end_block_exclusive: selection.end_block_exclusive,
        ethereum_finalized_block_number: finalized_number,
        ethereum_finalized_block_hash: finalized_hash,
        game_type: AGGREGATE_GAME_TYPE,
        game_block_interval: GAME_BLOCK_INTERVAL,
        checkpoint_window_blocks: CHECKPOINT_WINDOW_BLOCKS,
        proofs,
    };
    std::fs::write(&args.out, serde_json::to_vec_pretty(&plan)?)?;
    println!("finalized Ethereum block: {finalized_number} {finalized_hash}");
    println!("checkpoint proofs planned: {}", plan.proofs.len());
    println!("checkpoint plan written: {}", args.out.display());
    Ok(())
}

fn validate_selection(
    selection: &SelectionManifest,
) -> Result<BTreeMap<u64, Vec<SelectedCheckpointWindow>>> {
    ensure!(
        selection.version == 1,
        "unsupported selection manifest version"
    );
    ensure!(
        selection.chain_id == BASE_CHAIN_ID,
        "selection is not for Base mainnet"
    );
    ensure!(
        selection.aggregate_verifier_start_block == AGGREGATE_VERIFIER_START_BLOCK,
        "selection uses an unexpected AggregateVerifier start block"
    );
    ensure!(
        selection.start_block < selection.end_block_exclusive,
        "invalid selection period"
    );
    ensure!(
        !selection.checkpoint_windows.is_empty(),
        "selection has no checkpoint windows"
    );

    let selected_blocks = selection
        .selected_block_numbers
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        selected_blocks.len() == selection.selected_block_numbers.len(),
        "selection contains duplicate block numbers"
    );
    ensure!(
        selected_blocks
            .iter()
            .copied()
            .eq(selection.selected_block_numbers.iter().copied()),
        "selected block numbers are not sorted"
    );
    let mut planned_blocks = std::collections::BTreeSet::new();
    let mut planned_checkpoints = std::collections::BTreeSet::new();
    let mut required_windows = BTreeMap::<u64, Vec<SelectedCheckpointWindow>>::new();
    let mut previous_checkpoint = None;

    for window in &selection.checkpoint_windows {
        ensure!(
            planned_checkpoints.insert(window.checkpoint_block_number),
            "duplicate checkpoint window {}",
            window.checkpoint_block_number
        );
        ensure!(
            previous_checkpoint.is_none_or(|previous| window.checkpoint_block_number > previous),
            "checkpoint windows are not sorted"
        );
        previous_checkpoint = Some(window.checkpoint_block_number);
        ensure!(
            !window.target_blocks.is_empty(),
            "checkpoint window has no targets"
        );
        ensure!(
            window.target_blocks.len() <= CHECKPOINT_WINDOW_BLOCKS as usize,
            "checkpoint window has too many targets"
        );
        let game_start = game_start_block(window.checkpoint_block_number)?;
        intermediate_root_index(game_start, window.checkpoint_block_number)?;
        let oldest_allowed = window.checkpoint_block_number - (CHECKPOINT_WINDOW_BLOCKS - 1);
        let mut previous = None;
        for block_number in &window.target_blocks {
            ensure!(
                *block_number >= selection.start_block
                    && *block_number < selection.end_block_exclusive,
                "target block {block_number} is outside the selection period"
            );
            ensure!(
                *block_number >= oldest_allowed && *block_number <= window.checkpoint_block_number,
                "target block {block_number} is outside checkpoint {}",
                window.checkpoint_block_number
            );
            ensure!(
                previous.is_none_or(|previous_block| *block_number > previous_block),
                "checkpoint targets are not sorted and unique"
            );
            ensure!(
                planned_blocks.insert(*block_number),
                "target block {block_number} appears in multiple windows"
            );
            previous = Some(*block_number);
        }
        required_windows
            .entry(game_start)
            .or_default()
            .push(window.clone());
    }
    ensure!(
        planned_blocks == selected_blocks,
        "checkpoint targets do not exactly match selected block numbers"
    );
    Ok(required_windows)
}

fn game_start_block(checkpoint_block_number: u64) -> Result<u64> {
    ensure!(
        checkpoint_block_number > AGGREGATE_VERIFIER_START_BLOCK,
        "checkpoint predates AggregateVerifier coverage"
    );
    let offset = checkpoint_block_number - AGGREGATE_VERIFIER_START_BLOCK;
    ensure!(
        offset.is_multiple_of(CHECKPOINT_WINDOW_BLOCKS),
        "checkpoint block is not aligned to a 30-block intermediate root"
    );
    Ok(AGGREGATE_VERIFIER_START_BLOCK + ((offset - 1) / GAME_BLOCK_INTERVAL) * GAME_BLOCK_INTERVAL)
}

fn intermediate_root_index(game_start: u64, checkpoint_block_number: u64) -> Result<u8> {
    let offset = checkpoint_block_number
        .checked_sub(game_start)
        .context("checkpoint is before game start")?;
    ensure!(
        (CHECKPOINT_WINDOW_BLOCKS..=GAME_BLOCK_INTERVAL).contains(&offset)
            && offset.is_multiple_of(CHECKPOINT_WINDOW_BLOCKS),
        "checkpoint does not belong to the selected game"
    );
    Ok(u8::try_from(offset / CHECKPOINT_WINDOW_BLOCKS - 1)?)
}

async fn discover_games<P: Provider>(
    provider: &P,
    block_id: BlockId,
    minimum_start: u64,
    maximum_start: u64,
) -> Result<BTreeMap<u64, CatalogGame>> {
    let factory = IDisputeGameFactoryCatalog::new(DISPUTE_GAME_FACTORY, provider);
    let game_count = factory.gameCount().block(block_id).call().await?;
    ensure!(game_count > U256::ZERO, "dispute game factory is empty");
    let mut search_index = game_count - U256::from(1);
    let mut catalog = BTreeMap::new();

    loop {
        let games = factory
            .findLatestGames(AGGREGATE_GAME_TYPE, search_index, U256::from(PAGE_SIZE))
            .block(block_id)
            .call()
            .await?;
        if games.is_empty() {
            break;
        }
        let oldest_index = games.last().unwrap().index;
        let mut reached_earlier_game = false;
        for game in games {
            let starting_block_number = starting_block_from_extra_data(&game.extraData)?;
            if starting_block_number < minimum_start {
                reached_earlier_game = true;
                continue;
            }
            if starting_block_number > maximum_start {
                continue;
            }
            let address = Address::from_slice(&game.metadata.as_slice()[12..]);
            let replaced = catalog.insert(
                starting_block_number,
                CatalogGame {
                    address,
                    starting_block_number,
                },
            );
            ensure!(
                replaced.is_none(),
                "multiple type-621 games share start {starting_block_number}"
            );
        }
        if reached_earlier_game || oldest_index == U256::ZERO {
            break;
        }
        search_index = oldest_index - U256::from(1);
    }
    Ok(catalog)
}

fn starting_block_from_extra_data(extra_data: &Bytes) -> Result<u64> {
    ensure!(
        extra_data.len() >= 32,
        "AggregateVerifier extraData is too short"
    );
    let ending_block = u64::try_from(U256::from_be_slice(&extra_data[..32]))
        .context("AggregateVerifier ending block does not fit u64")?;
    ending_block
        .checked_sub(GAME_BLOCK_INTERVAL)
        .context("AggregateVerifier ending block predates one game interval")
}

async fn validate_game<P: Provider>(
    provider: &P,
    block_id: BlockId,
    game: &CatalogGame,
) -> Result<()> {
    let verifier = IAggregateVerifierCatalog::new(game.address, provider);
    let registry = IAnchorStateRegistryCatalog::new(ANCHOR_STATE_REGISTRY, provider);
    let valid_call = registry.isGameClaimValid(game.address).block(block_id);
    let game_type_call = verifier.gameType().block(block_id);
    let starting_block_call = verifier.startingBlockNumber().block(block_id);
    let block_interval_call = verifier.BLOCK_INTERVAL().block(block_id);
    let intermediate_interval_call = verifier.INTERMEDIATE_BLOCK_INTERVAL().block(block_id);
    let (valid, game_type, starting_block, block_interval, intermediate_interval) = tokio::try_join!(
        valid_call.call(),
        game_type_call.call(),
        starting_block_call.call(),
        block_interval_call.call(),
        intermediate_interval_call.call(),
    )?;
    ensure!(
        valid,
        "game {} is not ASR-valid at finalized state",
        game.address
    );
    ensure!(
        game_type == AGGREGATE_GAME_TYPE,
        "game {} has wrong type",
        game.address
    );
    ensure!(
        starting_block == U256::from(game.starting_block_number),
        "game {} starting block mismatch",
        game.address
    );
    ensure!(
        block_interval == U256::from(GAME_BLOCK_INTERVAL),
        "game {} has wrong block interval",
        game.address
    );
    ensure!(
        intermediate_interval == U256::from(CHECKPOINT_WINDOW_BLOCKS),
        "game {} has wrong intermediate interval",
        game.address
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection(windows: Vec<SelectedCheckpointWindow>) -> SelectionManifest {
        let selected_block_numbers = windows
            .iter()
            .flat_map(|window| window.target_blocks.iter().copied())
            .collect();
        SelectionManifest {
            version: 1,
            chain_id: BASE_CHAIN_ID,
            start_block: AGGREGATE_VERIFIER_START_BLOCK + 1,
            end_block_exclusive: AGGREGATE_VERIFIER_START_BLOCK + 1_000,
            aggregate_verifier_start_block: AGGREGATE_VERIFIER_START_BLOCK,
            selected_block_numbers,
            checkpoint_windows: windows,
        }
    }

    #[test]
    fn maps_checkpoint_to_game_and_intermediate_index() {
        let checkpoint = AGGREGATE_VERIFIER_START_BLOCK + 630;
        let game_start = game_start_block(checkpoint).unwrap();
        assert_eq!(game_start, AGGREGATE_VERIFIER_START_BLOCK + 600);
        assert_eq!(intermediate_root_index(game_start, checkpoint).unwrap(), 0);
    }

    #[test]
    fn validates_exact_selected_block_union() {
        let manifest = selection(vec![SelectedCheckpointWindow {
            checkpoint_block_number: AGGREGATE_VERIFIER_START_BLOCK + 30,
            target_blocks: vec![
                AGGREGATE_VERIFIER_START_BLOCK + 1,
                AGGREGATE_VERIFIER_START_BLOCK + 30,
            ],
        }]);
        assert_eq!(validate_selection(&manifest).unwrap().len(), 1);
    }

    #[test]
    fn rejects_targets_outside_checkpoint_window() {
        let manifest = selection(vec![SelectedCheckpointWindow {
            checkpoint_block_number: AGGREGATE_VERIFIER_START_BLOCK + 60,
            target_blocks: vec![AGGREGATE_VERIFIER_START_BLOCK + 1],
        }]);
        assert!(
            validate_selection(&manifest)
                .unwrap_err()
                .to_string()
                .contains("outside checkpoint")
        );
    }

    #[test]
    fn rejects_duplicate_checkpoint_windows() {
        let checkpoint = AGGREGATE_VERIFIER_START_BLOCK + 30;
        let manifest = selection(vec![
            SelectedCheckpointWindow {
                checkpoint_block_number: checkpoint,
                target_blocks: vec![AGGREGATE_VERIFIER_START_BLOCK + 1],
            },
            SelectedCheckpointWindow {
                checkpoint_block_number: checkpoint,
                target_blocks: vec![AGGREGATE_VERIFIER_START_BLOCK + 2],
            },
        ]);
        assert!(
            validate_selection(&manifest)
                .unwrap_err()
                .to_string()
                .contains("duplicate checkpoint")
        );
    }

    #[test]
    fn decodes_starting_block_from_extra_data() {
        let mut bytes = vec![0_u8; 64];
        bytes[24..32].copy_from_slice(&49_934_160_u64.to_be_bytes());
        assert_eq!(
            starting_block_from_extra_data(&Bytes::from(bytes)).unwrap(),
            49_933_560
        );
    }
}
