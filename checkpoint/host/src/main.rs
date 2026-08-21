use alloy::providers::{Provider, ProviderBuilder};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, U256, address};
use anyhow::{Context, Result, bail, ensure};
use checkpoint_core::{
    AGGREGATE_GAME_TYPE, ANCHOR_STATE_REGISTRY, CheckpointJournal, CheckpointWitness,
    IAggregateVerifier, IAnchorStateRegistry, INTERMEDIATE_BLOCK_INTERVAL, MESSAGE_PASSER,
    checkpoint_block_number, output_root, validate_header_chain,
};
use checkpoint_methods::{CHECKPOINT_GUEST_ELF, CHECKPOINT_GUEST_ID};
use clap::Parser;
use risc0_op_steel::{
    Contract,
    ethereum::{ETH_MAINNET_CHAIN_SPEC, EthEvmEnv},
    host::BlockNumberOrTag,
    l1,
};
use risc0_zkvm::{ExecutorEnv, ProverOpts, VerifierContext, default_executor, default_prover};
use sha2::Digest as _;
use std::{path::PathBuf, time::Instant};
use tracing_subscriber::EnvFilter;
use url::Url;

const DEFAULT_GAME: Address = address!("b7f2F804592cbF215112619a0ea6E4dE1280Bd75");

#[derive(Parser, Debug)]
#[command(
    about = "Authenticate Base block hashes from an ASR-approved AggregateVerifier checkpoint"
)]
struct Args {
    #[arg(
        long,
        env = "L1_RPC_URL",
        default_value = "https://ethereum-rpc.publicnode.com"
    )]
    l1_rpc_url: Url,

    #[arg(long, env = "BASE_RPC_URL")]
    base_rpc_url: Url,

    #[arg(
        long,
        env = "BEACON_API_URL",
        default_value = "https://ethereum-beacon-api.publicnode.com"
    )]
    beacon_api_url: Url,

    #[arg(long, requires = "expected_l1_block_hash")]
    l1_block_number: Option<u64>,

    #[arg(long, requires = "l1_block_number")]
    expected_l1_block_hash: Option<B256>,

    #[arg(long, default_value_t = DEFAULT_GAME)]
    game: Address,

    #[arg(long, default_value_t = 19)]
    intermediate_root_index: u8,

    /// Target Base blocks, comma-delimited. Defaults to checkpoint - 28.
    #[arg(long, value_delimiter = ',')]
    target_blocks: Vec<u64>,

    /// Produce a Groth16 receipt instead of execution-only dry run.
    #[arg(long)]
    prove: bool,

    /// Write journal calldata as a 0x-prefixed hex file.
    #[arg(long)]
    journal_out: Option<PathBuf>,

    /// Write verifier seal calldata as a 0x-prefixed hex file. Requires --prove.
    #[arg(long, requires = "prove")]
    seal_out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    dotenvy::from_filename("../.env").ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let l1_block = if let Some(block_number) = args.l1_block_number {
        let provider = ProviderBuilder::new().connect_http(args.l1_rpc_url.clone());
        let block = provider
            .get_block_by_number(block_number.into())
            .hashes()
            .await?
            .with_context(|| format!("Ethereum block {block_number} not found"))?;
        ensure!(
            Some(block.header.hash) == args.expected_l1_block_hash,
            "finalized Ethereum block hash differs from checkpoint plan"
        );
        BlockNumberOrTag::Number(block_number)
    } else {
        BlockNumberOrTag::Finalized
    };

    let mut ethereum_env = EthEvmEnv::builder()
        .rpc(args.l1_rpc_url)
        .block_number_or_tag(l1_block)
        .beacon_api(args.beacon_api_url)
        .chain_spec(&ETH_MAINNET_CHAIN_SPEC)
        .build()
        .await?;

    let mut anchor_state_registry = Contract::preflight(ANCHOR_STATE_REGISTRY, &mut ethereum_env);
    let valid_game = anchor_state_registry
        .call_builder(&IAnchorStateRegistry::isGameClaimValidCall { game: args.game })
        .call()
        .await?;
    ensure!(valid_game, "game is not valid in Base AnchorStateRegistry");

    let mut game = Contract::preflight(args.game, &mut ethereum_env);
    let game_type = game
        .call_builder(&IAggregateVerifier::gameTypeCall {})
        .call()
        .await?;
    ensure!(
        game_type == AGGREGATE_GAME_TYPE,
        "expected game type {AGGREGATE_GAME_TYPE}, got {game_type}"
    );
    let starting_block_number = game
        .call_builder(&IAggregateVerifier::startingBlockNumberCall {})
        .call()
        .await?;
    let interval = game
        .call_builder(&IAggregateVerifier::INTERMEDIATE_BLOCK_INTERVALCall {})
        .call()
        .await?;
    ensure!(
        interval == U256::from(INTERMEDIATE_BLOCK_INTERVAL),
        "unexpected intermediate interval {interval}"
    );
    let expected_output_root = game
        .call_builder(&IAggregateVerifier::intermediateOutputRootCall {
            index: U256::from(args.intermediate_root_index),
        })
        .call()
        .await?;
    let checkpoint_number =
        checkpoint_block_number(starting_block_number, args.intermediate_root_index)
            .map_err(anyhow::Error::msg)?;

    let mut target_blocks = args.target_blocks;
    if target_blocks.is_empty() {
        target_blocks.push(checkpoint_number.saturating_sub(INTERMEDIATE_BLOCK_INTERVAL - 2));
    }
    target_blocks.sort_unstable();
    target_blocks.dedup();
    let oldest_target = *target_blocks.first().context("missing target block")?;
    if oldest_target > checkpoint_number {
        bail!("target block {oldest_target} is after checkpoint {checkpoint_number}");
    }

    let base_provider = ProviderBuilder::new().connect_http(args.base_rpc_url.clone());
    let mut base_headers = Vec::with_capacity((checkpoint_number - oldest_target + 1) as usize);
    for block_number in oldest_target..=checkpoint_number {
        let block = base_provider
            .get_block_by_number(block_number.into())
            .hashes()
            .await?
            .with_context(|| format!("Base block {block_number} not found"))?;
        let header: Header = block.header.inner;
        ensure!(
            header.number == block_number,
            "Base RPC returned wrong block number"
        );
        base_headers.push(header);
    }

    let checkpoint_hash = base_headers.last().expect("headers non-empty").hash_slow();
    let message_passer_proof = base_provider
        .get_proof(MESSAGE_PASSER, Vec::new())
        .hash(checkpoint_hash)
        .await
        .context("eth_getProof for L2ToL1MessagePasser failed")?;
    let message_passer_storage_root: B256 = message_passer_proof.storage_hash;

    let witness = CheckpointWitness {
        game: args.game,
        intermediate_root_index: args.intermediate_root_index,
        message_passer_storage_root,
        base_headers_rlp: base_headers
            .iter()
            .map(alloy_rlp::encode)
            .map(Into::into)
            .collect(),
        target_block_numbers: target_blocks,
    };
    let native_blocks = validate_header_chain(&witness, checkpoint_number, expected_output_root)
        .map_err(anyhow::Error::msg)?;
    let checkpoint_header = base_headers.last().expect("headers non-empty");
    ensure!(
        output_root(
            checkpoint_header.state_root,
            message_passer_storage_root,
            checkpoint_hash
        ) == expected_output_root,
        "Base checkpoint preimage does not match AggregateVerifier root"
    );
    println!("ASR game valid:       {}", args.game);
    println!(
        "checkpoint:           {} {}",
        checkpoint_number, checkpoint_hash
    );
    println!("output root:          {}", expected_output_root);
    println!("authenticated blocks: {}", native_blocks.len());

    let ethereum_input = ethereum_env.into_input().await?;
    let ethereum_input = l1::into_beacon_input(ethereum_input, args.base_rpc_url).await?;
    let guest_input = (ethereum_input, witness.clone());
    let executor_env = ExecutorEnv::builder().write(&guest_input)?.build()?;

    let start = Instant::now();
    let (journal_bytes, seal) = if args.prove {
        let info = default_prover().prove_with_ctx(
            executor_env,
            &VerifierContext::default(),
            CHECKPOINT_GUEST_ELF,
            &ProverOpts::groth16(),
        )?;
        info.receipt.verify(CHECKPOINT_GUEST_ID)?;
        println!("proof verified in {:?}", start.elapsed());
        println!(
            "cycles: user={} total={} segments={}",
            info.stats.user_cycles, info.stats.total_cycles, info.stats.segments
        );
        let seal = risc0_ethereum_contracts::encode_seal(&info.receipt)
            .context("failed to encode the onchain verifier seal")?;
        (info.receipt.journal.bytes, Some(seal))
    } else {
        let session = default_executor().execute(executor_env, CHECKPOINT_GUEST_ELF)?;
        let user_cycles = session.cycles();
        let total_cycles: u64 = session
            .segments
            .iter()
            .map(|segment| 1_u64 << segment.po2)
            .sum();
        println!("dry run executed in {:?}", start.elapsed());
        println!(
            "cycles: user={} total={} segments={}",
            user_cycles,
            total_cycles,
            session.segments.len()
        );
        (session.journal.bytes, None)
    };

    let journal = CheckpointJournal::decode(&journal_bytes).map_err(anyhow::Error::msg)?;
    ensure!(
        journal.canonicalBlocks == native_blocks,
        "guest journal differs from native validation"
    );
    let journal_digest = sha2::Sha256::digest(&journal_bytes);
    println!(
        "image ID:             {}",
        risc0_zkvm::Digest::from(CHECKPOINT_GUEST_ID)
    );
    println!(
        "journal sha256:       0x{}",
        alloy_primitives::hex::encode(journal_digest)
    );
    println!("Steel commitment ID:  {}", journal.ethereumCommitment.id);
    println!(
        "Steel beacon root:    {}",
        journal.ethereumCommitment.digest
    );
    println!(
        "archive timestamp:    {}",
        u64::try_from(journal.ethereumCommitment.id & U256::from(u64::MAX))?
    );

    if let Some(path) = args.journal_out {
        std::fs::write(
            &path,
            format!("0x{}", alloy_primitives::hex::encode(&journal_bytes)),
        )?;
        println!("journal written:      {}", path.display());
    }
    if let (Some(path), Some(seal)) = (args.seal_out, seal) {
        std::fs::write(&path, format!("0x{}", alloy_primitives::hex::encode(seal)))?;
        println!("seal written:         {}", path.display());
    }
    Ok(())
}
