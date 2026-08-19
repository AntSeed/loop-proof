#![no_main]

use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use checkpoint_core::{
    AGGREGATE_GAME_TYPE, ANCHOR_STATE_REGISTRY, BASE_CHAIN_ID, CheckpointJournal,
    CheckpointWitness, ETHEREUM_MAINNET_CONFIG_ID, IAggregateVerifier, IAnchorStateRegistry,
    INTERMEDIATE_BLOCK_INTERVAL, SteelCommitment, checkpoint_block_number, validate_header_chain,
};
use risc0_steel::{Contract, ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmInput}};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let (ethereum_input, witness): (EthEvmInput, CheckpointWitness) = env::read();

    let ethereum_env = ethereum_input.into_env(&ETH_MAINNET_CHAIN_SPEC);
    let steel_commitment = ethereum_env.commitment();
    assert_eq!(steel_commitment.configID, ETHEREUM_MAINNET_CONFIG_ID, "wrong Ethereum config ID");

    let anchor_state_registry = Contract::new(ANCHOR_STATE_REGISTRY, &ethereum_env);
    let valid_game = anchor_state_registry
        .call_builder(&IAnchorStateRegistry::isGameClaimValidCall { game: witness.game })
        .call();
    assert!(valid_game, "AggregateVerifier game is not valid in the AnchorStateRegistry");

    let game = Contract::new(witness.game, &ethereum_env);
    let game_type = game.call_builder(&IAggregateVerifier::gameTypeCall {}).call();
    assert_eq!(game_type, AGGREGATE_GAME_TYPE, "wrong dispute game type");

    let starting_block_number = game
        .call_builder(&IAggregateVerifier::startingBlockNumberCall {})
        .call();
    let interval = game
        .call_builder(&IAggregateVerifier::INTERMEDIATE_BLOCK_INTERVALCall {})
        .call();
    assert_eq!(interval, U256::from(INTERMEDIATE_BLOCK_INTERVAL), "wrong intermediate interval");

    let expected_output_root = game
        .call_builder(&IAggregateVerifier::intermediateOutputRootCall {
            index: U256::from(witness.intermediate_root_index),
        })
        .call();
    let checkpoint_number = checkpoint_block_number(starting_block_number, witness.intermediate_root_index)
        .expect("invalid checkpoint number");
    let canonical_blocks = validate_header_chain(&witness, checkpoint_number, expected_output_root)
        .expect("invalid Base header chain");
    let checkpoint = canonical_blocks.last().expect("checkpoint block missing");

    let journal = CheckpointJournal {
        ethereumCommitment: SteelCommitment {
            id: steel_commitment.id,
            digest: steel_commitment.digest,
            configID: steel_commitment.configID,
        },
        chainId: BASE_CHAIN_ID,
        anchorStateRegistry: ANCHOR_STATE_REGISTRY,
        game: witness.game,
        intermediateRootIndex: witness.intermediate_root_index,
        checkpointBlockNumber: checkpoint.number,
        checkpointBlockHash: checkpoint.blockHash,
        outputRoot: expected_output_root,
        canonicalBlocks: canonical_blocks,
    };
    env::commit_slice(&journal.abi_encode());
}
