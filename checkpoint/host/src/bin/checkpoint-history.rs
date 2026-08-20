use alloy::{
    consensus::Header,
    primitives::{Address, B256, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    sol_types::{SolCall, SolValue, sol},
};
use alloy_rlp::Decodable;
use anyhow::{Context, Result, bail, ensure};
use boundless_market::{
    Client, Deployment, GuestEnv, StorageUploaderConfig,
    alloy::signers::local::PrivateKeySigner as BoundlessPrivateKeySigner,
    request_builder::OfferParams,
};
use clap::{Args, Parser, Subcommand};
use futures::{StreamExt, TryStreamExt, stream};
use history_core::{
    BASE_CHAIN_ID, CHUNK_SIZE, CHUNK_TREE_DEPTH, HISTORICAL_ANCHOR_BLOCK, HISTORICAL_BLOCK_COUNT,
    HISTORICAL_CHUNK_COUNT, HISTORICAL_START_BLOCK, HistoricalChunkJournal, HistoricalChunkWitness,
    MAX_BOUNDLESS_INPUT_BYTES, block_merkle_proof, global_historical_root, historical_chunk_bounds,
    validate_history_chunk,
};
use history_methods::{HISTORICAL_CHUNK_GUEST_ELF, HISTORICAL_CHUNK_IMAGE_ID};
use risc0_zkvm::{ExecutorEnv, default_executor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;
use url::Url;

const MANIFEST_VERSION: u32 = 1;
const MAX_PADDED_CYCLES: u64 = 1_000_000_000;

sol! {
    struct HistoricalBlockProof {
        uint64 blockNumber;
        bytes32 blockHash;
        bytes32[14] siblings;
    }

    interface IHistoricalCheckpointOracle {
        function beginHistoricalBackfill();
        function submitHistoricalChunk(bytes seal, bytes journalData);
        function materializeHistoricalBlocks(HistoricalBlockProof[] proofs);
    }
}

#[derive(Parser, Debug)]
#[command(about = "Fetch, execute, prove, and plan the historical Base header backfill")]
struct Cli {
    #[arg(long, default_value = "history-artifacts")]
    artifact_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Fetch(FetchArgs),
    DryRun(ChunkSelection),
    Prove(Box<ProveArgs>),
    TxPlan(TxPlanArgs),
    MaterializePlan(MaterializePlanArgs),
}

#[derive(Args, Clone, Debug)]
struct ChunkSelection {
    /// Chunk indexes, newest-first. Empty means all 112 chunks.
    #[arg(long, value_delimiter = ',')]
    chunks: Vec<u16>,
}

#[derive(Args, Debug)]
struct FetchArgs {
    #[arg(long, env = "BASE_RPC_URL")]
    base_rpc_url: Url,

    #[arg(long, default_value_t = 4)]
    concurrency: usize,

    /// Number of headers persisted atomically after each completed RPC page.
    #[arg(long, default_value_t = 512)]
    page_size: usize,

    /// Minimum delay between JSON-RPC request starts. Increase this after HTTP 429 responses.
    #[arg(long, default_value_t = 250)]
    request_interval_ms: u64,

    #[command(flatten)]
    selection: ChunkSelection,
}

#[derive(Args, Debug)]
struct ProveArgs {
    #[arg(
        long,
        env = "BOUNDLESS_RPC_URL",
        default_value = "https://mainnet.base.org"
    )]
    rpc_url: Url,

    #[arg(long, env = "BOUNDLESS_REQUESTOR_KEY")]
    requestor_key: BoundlessPrivateKeySigner,

    #[command(flatten)]
    storage: StorageUploaderConfig,

    #[command(flatten)]
    deployment: Option<Deployment>,

    #[command(flatten, next_help_heading = "Offer")]
    offer: OfferParams,

    #[command(flatten)]
    selection: ChunkSelection,

    #[arg(long)]
    confirm_paid_proving: bool,
}

#[derive(Args, Debug)]
struct TxPlanArgs {
    #[arg(long)]
    oracle: Address,

    #[arg(long, default_value = "historical-backfill-transactions.json")]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct MaterializePlanArgs {
    #[arg(long)]
    oracle: Address,

    /// Seller fixture JSON files. Historical block numbers are read from blocks[].header.number.
    #[arg(long, required = true)]
    seller_fixture: Vec<PathBuf>,

    #[arg(long, default_value_t = 32)]
    batch_size: usize,

    #[arg(long, default_value = "historical-materialization-transactions.json")]
    out: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ChunkStatus {
    Planned,
    Fetched,
    DryRunComplete,
    ProvingPending,
    Proven,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChunkArtifact {
    index_from_newest: u16,
    start_block: u64,
    end_block: u64,
    successor_block: u64,
    header_cache_file: String,
    witness_file: String,
    input_file: String,
    expected_journal_file: String,
    journal_file: String,
    seal_file: String,
    input_sha256: Option<String>,
    input_bytes: Option<usize>,
    expected_journal_digest: Option<String>,
    block_root: Option<B256>,
    status: ChunkStatus,
    user_cycles: Option<u64>,
    padded_cycles: Option<u64>,
    segments: Option<usize>,
    boundless_request_id: Option<String>,
    boundless_expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedHeader {
    number: u64,
    rlp: alloy::primitives::Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HeaderCache {
    start_block: u64,
    successor_block: u64,
    headers: Vec<CachedHeader>,
}

#[derive(Debug)]
struct RequestPacer {
    interval: Duration,
    next_request_at: Mutex<Instant>,
}

impl RequestPacer {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            next_request_at: Mutex::new(Instant::now()),
        }
    }

    async fn wait(&self) {
        if self.interval.is_zero() {
            return;
        }
        let mut next_request_at = self.next_request_at.lock().await;
        let now = Instant::now();
        if *next_request_at > now {
            tokio::time::sleep(*next_request_at - now).await;
        }
        *next_request_at = Instant::now() + self.interval;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HistoryManifest {
    version: u32,
    chain_id: u64,
    historical_start_block: u64,
    historical_anchor_block: u64,
    historical_block_count: u64,
    chunk_size: usize,
    chunk_tree_depth: usize,
    chunk_count: usize,
    image_id: String,
    historical_root: Option<B256>,
    chunks: Vec<ChunkArtifact>,
}

#[derive(Clone, Debug, Serialize)]
struct UnsignedTransaction {
    order: usize,
    purpose: String,
    to: Address,
    value: String,
    data: String,
}

#[derive(Clone, Debug, Serialize)]
struct TransactionPlan {
    chain_id: u64,
    oracle: Address,
    historical_start_block: u64,
    historical_anchor_block: u64,
    transactions: Vec<UnsignedTransaction>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    dotenvy::from_filename("../.env").ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    fs::create_dir_all(&cli.artifact_dir)?;
    match cli.command {
        Command::Fetch(args) => fetch(&cli.artifact_dir, args).await,
        Command::DryRun(args) => dry_run(&cli.artifact_dir, args),
        Command::Prove(args) => prove(&cli.artifact_dir, *args).await,
        Command::TxPlan(args) => tx_plan(&cli.artifact_dir, args),
        Command::MaterializePlan(args) => materialize_plan(&cli.artifact_dir, args),
    }
}

async fn fetch(artifact_dir: &Path, args: FetchArgs) -> Result<()> {
    ensure!(args.concurrency > 0, "concurrency must be non-zero");
    ensure!(args.page_size > 0, "page size must be non-zero");
    let mut manifest = load_or_initialize_manifest(artifact_dir)?;
    let selected = selected_chunk_indexes(&args.selection)?;
    let provider = ProviderBuilder::new().connect_http(args.base_rpc_url);
    let pacer = Arc::new(RequestPacer::new(Duration::from_millis(
        args.request_interval_ms,
    )));

    for index in selected {
        let artifact = &manifest.chunks[index];
        if artifact.status != ChunkStatus::Planned {
            validate_artifact_files(artifact_dir, artifact)?;
            println!("chunk {index:03}: already {:?}", artifact.status);
            continue;
        }

        let start = artifact.start_block;
        let successor = artifact.successor_block;
        let cache_path = artifact_dir.join(&artifact.header_cache_file);
        let mut cache = load_header_cache(&cache_path, start, successor)?;
        println!(
            "chunk {index:03}: cached {}/{} headers; fetching {start}..={successor}",
            cache.headers.len(),
            successor - start + 1
        );
        while let Some((page_start, page_end)) =
            next_page_bounds(start, successor, cache.headers.len(), args.page_size)?
        {
            let headers = fetch_header_page(
                &provider,
                Arc::clone(&pacer),
                page_start,
                page_end,
                args.concurrency,
            )
            .await?;
            cache
                .headers
                .extend(headers.into_iter().map(|(number, header)| CachedHeader {
                    number,
                    rlp: alloy_rlp::encode(header).into(),
                }));
            validate_header_cache(&cache, start, successor)?;
            write_json_atomic(&cache_path, &cache)?;
            println!(
                "chunk {index:03}: cached through block {page_end} ({}/{})",
                cache.headers.len(),
                successor - start + 1
            );
        }

        let mut headers = cache
            .headers
            .iter()
            .map(decode_cached_header)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            headers.len() == (successor - start + 1) as usize,
            "RPC returned incomplete chunk"
        );

        let successor_header = headers.pop().expect("range includes successor");
        let witness = HistoricalChunkWitness {
            base_headers_rlp: headers
                .into_iter()
                .map(|header| alloy_rlp::encode(header).into())
                .collect(),
            successor_header_rlp: alloy_rlp::encode(successor_header).into(),
        };
        let journal = validate_history_chunk(&witness).map_err(anyhow::Error::msg)?;
        ensure!(
            journal.startBlockNumber == start && journal.successorBlockNumber == successor,
            "native validation produced unexpected bounds"
        );

        let stdin = guest_stdin(&witness)?;
        ensure!(
            stdin.len() <= MAX_BOUNDLESS_INPUT_BYTES,
            "chunk input is {} bytes, above the 50 MB Boundless limit",
            stdin.len()
        );
        let expected_journal = journal.abi_encode();
        let input_sha256 = sha256_hex(&stdin);
        let expected_journal_digest = sha256_hex(&expected_journal);

        let artifact = &mut manifest.chunks[index];
        write_json(artifact_dir.join(&artifact.witness_file), &witness)?;
        fs::write(artifact_dir.join(&artifact.input_file), &stdin)?;
        fs::write(
            artifact_dir.join(&artifact.expected_journal_file),
            &expected_journal,
        )?;
        artifact.input_sha256 = Some(input_sha256);
        artifact.input_bytes = Some(stdin.len());
        artifact.expected_journal_digest = Some(expected_journal_digest);
        artifact.block_root = Some(journal.blockRoot);
        artifact.status = ChunkStatus::Fetched;
        save_manifest(artifact_dir, &manifest)?;
        println!(
            "chunk {index:03}: fetched {} headers, {} input bytes",
            journal.blockCount,
            stdin.len()
        );
    }
    Ok(())
}

async fn fetch_header_page<P>(
    provider: &P,
    pacer: Arc<RequestPacer>,
    start: u64,
    end: u64,
    concurrency: usize,
) -> Result<Vec<(u64, Header)>>
where
    P: Provider + Clone,
{
    let mut headers = stream::iter(start..=end)
        .map(|number| {
            let provider = provider.clone();
            let pacer = Arc::clone(&pacer);
            async move {
                let mut delay = Duration::from_millis(250);
                let block = loop {
                    pacer.wait().await;
                    match provider.get_block_by_number(number.into()).hashes().await {
                        Ok(Some(block)) => break block,
                        Ok(None) => bail!("Base block {number} not found"),
                        Err(error) if delay <= Duration::from_secs(8) => {
                            eprintln!("Base block {number} RPC failed ({error}); retrying");
                            tokio::time::sleep(delay).await;
                            delay *= 2;
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                let header: Header = block.header.inner;
                ensure!(
                    header.number == number,
                    "Base RPC returned block {} for {number}",
                    header.number
                );
                Ok::<_, anyhow::Error>((number, header))
            }
        })
        .buffer_unordered(concurrency)
        .try_collect::<Vec<_>>()
        .await?;
    headers.sort_unstable_by_key(|(number, _)| *number);
    ensure!(
        headers.len() == (end - start + 1) as usize,
        "RPC returned incomplete page"
    );
    ensure!(
        headers
            .iter()
            .enumerate()
            .all(|(offset, (number, _))| *number == start + offset as u64),
        "RPC returned a gap or duplicate"
    );
    Ok(headers)
}

fn load_header_cache(path: &Path, start: u64, successor: u64) -> Result<HeaderCache> {
    let cache = if path.exists() {
        read_json(path)?
    } else {
        HeaderCache {
            start_block: start,
            successor_block: successor,
            headers: Vec::new(),
        }
    };
    validate_header_cache(&cache, start, successor)?;
    Ok(cache)
}

fn validate_header_cache(cache: &HeaderCache, start: u64, successor: u64) -> Result<()> {
    ensure!(
        cache.start_block == start && cache.successor_block == successor,
        "header cache bounds do not match the chunk"
    );
    ensure!(
        cache.headers.len() <= (successor - start + 1) as usize,
        "header cache exceeds the chunk range"
    );
    let mut previous_hash = None;
    for (offset, cached) in cache.headers.iter().enumerate() {
        let expected_number = start + offset as u64;
        ensure!(
            cached.number == expected_number,
            "header cache expected block {expected_number}, found {}",
            cached.number
        );
        let header = decode_cached_header(cached)?;
        ensure!(
            header.number == cached.number,
            "cached RLP block number differs from cache metadata"
        );
        if let Some(parent_hash) = previous_hash {
            ensure!(
                header.parent_hash == parent_hash,
                "cached header parent hash mismatch at block {}",
                cached.number
            );
        }
        previous_hash = Some(keccak256(cached.rlp.as_ref()));
    }
    Ok(())
}

fn decode_cached_header(cached: &CachedHeader) -> Result<Header> {
    let mut input = cached.rlp.as_ref();
    let header = Header::decode(&mut input).context("invalid cached Base header RLP")?;
    ensure!(
        input.is_empty(),
        "cached Base header RLP has trailing bytes"
    );
    ensure!(
        alloy_rlp::encode(&header).as_slice() == cached.rlp.as_ref(),
        "cached Base header RLP is not canonical"
    );
    Ok(header)
}

fn next_page_bounds(
    start: u64,
    successor: u64,
    cached_count: usize,
    page_size: usize,
) -> Result<Option<(u64, u64)>> {
    ensure!(page_size > 0, "page size must be non-zero");
    let total = usize::try_from(successor - start + 1)?;
    ensure!(cached_count <= total, "cached header count exceeds chunk");
    if cached_count == total {
        return Ok(None);
    }
    let page_start = start + u64::try_from(cached_count)?;
    let remaining = total - cached_count;
    let page_len = remaining.min(page_size);
    let page_end = page_start + u64::try_from(page_len)? - 1;
    Ok(Some((page_start, page_end)))
}

fn dry_run(artifact_dir: &Path, selection: ChunkSelection) -> Result<()> {
    let mut manifest = load_manifest(artifact_dir)?;
    for index in selected_chunk_indexes(&selection)? {
        let artifact = &manifest.chunks[index];
        ensure!(
            artifact.status != ChunkStatus::Planned,
            "chunk {index} has not been fetched"
        );
        validate_artifact_files(artifact_dir, artifact)?;
        let stdin = fs::read(artifact_dir.join(&artifact.input_file))?;
        let expected_journal = fs::read(artifact_dir.join(&artifact.expected_journal_file))?;
        let env = ExecutorEnv::builder().write_slice(&stdin).build()?;
        let start = Instant::now();
        let session = default_executor().execute(env, HISTORICAL_CHUNK_GUEST_ELF)?;
        let padded_cycles: u64 = session
            .segments
            .iter()
            .map(|segment| 1_u64 << segment.po2)
            .sum();
        ensure!(
            padded_cycles <= MAX_PADDED_CYCLES,
            "chunk {index} requires {padded_cycles} padded cycles, above the 1 billion limit"
        );
        ensure!(
            session.journal.bytes == expected_journal,
            "chunk {index} guest journal differs from native preflight"
        );

        let artifact = &mut manifest.chunks[index];
        fs::write(
            artifact_dir.join(&artifact.journal_file),
            &session.journal.bytes,
        )?;
        artifact.user_cycles = Some(session.cycles());
        artifact.padded_cycles = Some(padded_cycles);
        artifact.segments = Some(session.segments.len());
        if artifact.status != ChunkStatus::Proven {
            artifact.status = ChunkStatus::DryRunComplete;
        }
        save_manifest(artifact_dir, &manifest)?;
        println!(
            "chunk {index:03}: user={} padded={} segments={} elapsed={:?}",
            session.cycles(),
            padded_cycles,
            session.segments.len(),
            start.elapsed()
        );
    }
    Ok(())
}

async fn prove(artifact_dir: &Path, args: ProveArgs) -> Result<()> {
    ensure!(
        args.confirm_paid_proving,
        "paid proving requires --confirm-paid-proving"
    );
    ensure!(
        args.offer.max_price.is_some(),
        "paid proving requires an explicit --max-price"
    );
    let mut manifest = load_manifest(artifact_dir)?;
    let client = Client::builder()
        .with_rpc_url(args.rpc_url)
        .with_deployment(args.deployment)
        .with_uploader_config(&args.storage)
        .await?
        .with_private_key(args.requestor_key)
        .build()
        .await?;

    for index in selected_chunk_indexes(&args.selection)? {
        let artifact = &manifest.chunks[index];
        ensure!(
            artifact.status != ChunkStatus::Planned && artifact.status != ChunkStatus::Fetched,
            "chunk {index} requires a successful dry-run before paid proving"
        );
        if artifact.status == ChunkStatus::Proven {
            validate_artifact_files(artifact_dir, artifact)?;
            println!("chunk {index:03}: already proven");
            continue;
        }
        let stdin = fs::read(artifact_dir.join(&artifact.input_file))?;
        let expected_journal = fs::read(artifact_dir.join(&artifact.expected_journal_file))?;
        let (request_id, expires_at) = if let (Some(request_id), Some(expires_at)) = (
            artifact.boundless_request_id.as_deref(),
            artifact.boundless_expires_at,
        ) {
            (parse_u256(request_id)?, expires_at)
        } else {
            let request = client
                .new_request()
                .with_program(HISTORICAL_CHUNK_GUEST_ELF)
                .with_stdin(stdin)
                .with_cycles(artifact.padded_cycles.context("missing dry-run cycles")?)
                .with_journal(risc0_zkvm::Journal::new(expected_journal.clone()))
                .with_offer(args.offer.clone());
            let (request_id, expires_at) = client.submit(request).await?;
            let artifact = &mut manifest.chunks[index];
            artifact.boundless_request_id = Some(format!("0x{request_id:x}"));
            artifact.boundless_expires_at = Some(expires_at);
            artifact.status = ChunkStatus::ProvingPending;
            save_manifest(artifact_dir, &manifest)?;
            println!("chunk {index:03}: submitted request 0x{request_id:x}");
            (request_id, expires_at)
        };

        let fulfillment = client
            .wait_for_request_fulfillment(request_id, Duration::from_secs(5), expires_at)
            .await?;
        let data = fulfillment.data()?;
        let journal = data
            .journal()
            .context("Boundless fulfillment omitted journal")?;
        ensure!(
            journal.as_ref() == expected_journal,
            "Boundless journal differs from local preflight"
        );
        let image_id = data
            .image_id()
            .context("Boundless fulfillment omitted image ID")?;
        ensure!(
            image_id == risc0_zkvm::Digest::from(HISTORICAL_CHUNK_IMAGE_ID),
            "Boundless fulfillment used wrong image ID"
        );

        let artifact = &mut manifest.chunks[index];
        fs::write(artifact_dir.join(&artifact.journal_file), journal)?;
        fs::write(artifact_dir.join(&artifact.seal_file), &fulfillment.seal)?;
        artifact.status = ChunkStatus::Proven;
        save_manifest(artifact_dir, &manifest)?;
        println!("chunk {index:03}: proof fulfilled");
    }
    Ok(())
}

fn tx_plan(artifact_dir: &Path, args: TxPlanArgs) -> Result<()> {
    let manifest = load_manifest(artifact_dir)?;
    ensure!(
        manifest
            .chunks
            .iter()
            .all(|chunk| chunk.status == ChunkStatus::Proven),
        "all 112 chunks must be proven before creating the complete transaction plan"
    );

    let mut transactions = vec![unsigned_transaction(
        0,
        "begin historical backfill".into(),
        args.oracle,
        IHistoricalCheckpointOracle::beginHistoricalBackfillCall {}.abi_encode(),
    )];
    for (index, artifact) in manifest.chunks.iter().enumerate() {
        let seal = fs::read(artifact_dir.join(&artifact.seal_file))?;
        let journal = fs::read(artifact_dir.join(&artifact.journal_file))?;
        let data = IHistoricalCheckpointOracle::submitHistoricalChunkCall {
            seal: seal.into(),
            journalData: journal.into(),
        }
        .abi_encode();
        transactions.push(unsigned_transaction(
            index + 1,
            format!(
                "submit historical chunk {} ({}-{})",
                artifact.index_from_newest, artifact.start_block, artifact.end_block
            ),
            args.oracle,
            data,
        ));
    }
    let plan = TransactionPlan {
        chain_id: BASE_CHAIN_ID,
        oracle: args.oracle,
        historical_start_block: HISTORICAL_START_BLOCK,
        historical_anchor_block: HISTORICAL_ANCHOR_BLOCK,
        transactions,
    };
    write_json(&args.out, &plan)?;
    println!(
        "wrote {} unsigned transactions to {}",
        plan.transactions.len(),
        args.out.display()
    );
    Ok(())
}

fn materialize_plan(artifact_dir: &Path, args: MaterializePlanArgs) -> Result<()> {
    ensure!(args.batch_size > 0, "batch size must be non-zero");
    let manifest = load_manifest(artifact_dir)?;
    let mut block_numbers = BTreeSet::new();
    for fixture in &args.seller_fixture {
        collect_historical_fixture_blocks(fixture, &mut block_numbers)?;
    }
    ensure!(
        !block_numbers.is_empty(),
        "fixtures contain no historical block references"
    );

    let mut proofs = Vec::with_capacity(block_numbers.len());
    for block_number in block_numbers {
        let index = chunk_index_for_block(&manifest, block_number)?;
        let artifact = &manifest.chunks[index];
        ensure!(
            artifact.status != ChunkStatus::Planned,
            "chunk {index} has not been fetched"
        );
        let witness: HistoricalChunkWitness = read_json(artifact_dir.join(&artifact.witness_file))?;
        let offset = usize::try_from(block_number - artifact.start_block)?;
        let encoded = witness
            .base_headers_rlp
            .get(offset)
            .context("fixture block missing from chunk witness")?;
        let block_hash = keccak256(encoded.as_ref());
        let hashes = witness
            .base_headers_rlp
            .iter()
            .map(|header| keccak256(header.as_ref()))
            .collect::<Vec<_>>();
        let siblings = block_merkle_proof(artifact.start_block, &hashes, block_number)
            .map_err(anyhow::Error::msg)?;
        let siblings: [B256; CHUNK_TREE_DEPTH] = siblings
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong proof depth"))?;
        proofs.push(HistoricalBlockProof {
            blockNumber: block_number,
            blockHash: block_hash,
            siblings,
        });
    }

    let transactions = proofs
        .chunks(args.batch_size)
        .enumerate()
        .map(|(index, batch)| {
            unsigned_transaction(
                index,
                format!("materialize {} historical Base blocks", batch.len()),
                args.oracle,
                IHistoricalCheckpointOracle::materializeHistoricalBlocksCall {
                    proofs: batch.to_vec(),
                }
                .abi_encode(),
            )
        })
        .collect::<Vec<_>>();
    let plan = TransactionPlan {
        chain_id: BASE_CHAIN_ID,
        oracle: args.oracle,
        historical_start_block: HISTORICAL_START_BLOCK,
        historical_anchor_block: HISTORICAL_ANCHOR_BLOCK,
        transactions,
    };
    write_json(&args.out, &plan)?;
    println!(
        "wrote {} materialization transactions to {}",
        plan.transactions.len(),
        args.out.display()
    );
    Ok(())
}

fn load_or_initialize_manifest(artifact_dir: &Path) -> Result<HistoryManifest> {
    let path = manifest_path(artifact_dir);
    if path.exists() {
        return load_manifest(artifact_dir);
    }
    let chunks = historical_chunk_bounds()
        .into_iter()
        .map(|bounds| {
            let stem = format!(
                "chunk-{:03}-{}-{}",
                bounds.index_from_newest, bounds.start_block, bounds.end_block
            );
            ChunkArtifact {
                index_from_newest: bounds.index_from_newest,
                start_block: bounds.start_block,
                end_block: bounds.end_block,
                successor_block: bounds.successor_block,
                header_cache_file: format!("{stem}.headers.json"),
                witness_file: format!("{stem}.witness.json"),
                input_file: format!("{stem}.input.bin"),
                expected_journal_file: format!("{stem}.expected-journal.bin"),
                journal_file: format!("{stem}.journal.bin"),
                seal_file: format!("{stem}.seal.bin"),
                input_sha256: None,
                input_bytes: None,
                expected_journal_digest: None,
                block_root: None,
                status: ChunkStatus::Planned,
                user_cycles: None,
                padded_cycles: None,
                segments: None,
                boundless_request_id: None,
                boundless_expires_at: None,
            }
        })
        .collect();
    let manifest = HistoryManifest {
        version: MANIFEST_VERSION,
        chain_id: BASE_CHAIN_ID,
        historical_start_block: HISTORICAL_START_BLOCK,
        historical_anchor_block: HISTORICAL_ANCHOR_BLOCK,
        historical_block_count: HISTORICAL_BLOCK_COUNT,
        chunk_size: CHUNK_SIZE,
        chunk_tree_depth: CHUNK_TREE_DEPTH,
        chunk_count: HISTORICAL_CHUNK_COUNT,
        image_id: image_id_hex(),
        historical_root: None,
        chunks,
    };
    save_manifest(artifact_dir, &manifest)?;
    Ok(manifest)
}

fn load_manifest(artifact_dir: &Path) -> Result<HistoryManifest> {
    let manifest: HistoryManifest = read_json(manifest_path(artifact_dir))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &HistoryManifest) -> Result<()> {
    ensure!(
        manifest.version == MANIFEST_VERSION,
        "unsupported history manifest version"
    );
    ensure!(
        manifest.chain_id == BASE_CHAIN_ID,
        "history manifest is not Base mainnet"
    );
    ensure!(
        manifest.historical_start_block == HISTORICAL_START_BLOCK
            && manifest.historical_anchor_block == HISTORICAL_ANCHOR_BLOCK,
        "history manifest uses unexpected bounds"
    );
    ensure!(
        manifest.chunk_size == CHUNK_SIZE && manifest.chunk_tree_depth == CHUNK_TREE_DEPTH,
        "history manifest uses unexpected Merkle parameters"
    );
    ensure!(
        manifest.chunk_count == HISTORICAL_CHUNK_COUNT
            && manifest.chunks.len() == HISTORICAL_CHUNK_COUNT,
        "history manifest must contain exactly 112 chunks"
    );
    ensure!(
        manifest.image_id == image_id_hex(),
        "history manifest image ID differs from this build"
    );
    let expected = historical_chunk_bounds();
    for (artifact, bounds) in manifest.chunks.iter().zip(expected) {
        ensure!(
            artifact.index_from_newest == bounds.index_from_newest
                && artifact.start_block == bounds.start_block
                && artifact.end_block == bounds.end_block
                && artifact.successor_block == bounds.successor_block,
            "history manifest chunk layout mismatch"
        );
    }
    Ok(())
}

fn save_manifest(artifact_dir: &Path, manifest: &HistoryManifest) -> Result<()> {
    let mut manifest = manifest.clone();
    let journals = manifest
        .chunks
        .iter()
        .map(|chunk| {
            let path = artifact_dir.join(&chunk.expected_journal_file);
            if !path.exists() {
                return Ok(None);
            }
            let bytes = fs::read(path)?;
            Ok(Some(
                HistoricalChunkJournal::decode(&bytes).map_err(anyhow::Error::msg)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    for pair in journals.windows(2) {
        if let (Some(newer), Some(older)) = (&pair[0], &pair[1]) {
            ensure!(
                older.successorBlockNumber == newer.startBlockNumber
                    && older.successorBlockHash == newer.startBlockHash,
                "historical chunk artifacts contain a cross-chunk RPC conflict"
            );
        }
    }
    manifest.historical_root = if journals.iter().all(Option::is_some) {
        Some(
            global_historical_root(&journals.into_iter().flatten().collect::<Vec<_>>())
                .map_err(anyhow::Error::msg)?,
        )
    } else {
        None
    };
    let path = manifest_path(artifact_dir);
    let temp = path.with_extension("json.tmp");
    write_json(&temp, &manifest)?;
    fs::rename(temp, path)?;
    Ok(())
}

fn validate_artifact_files(artifact_dir: &Path, artifact: &ChunkArtifact) -> Result<()> {
    let input = fs::read(artifact_dir.join(&artifact.input_file))?;
    ensure!(
        Some(input.len()) == artifact.input_bytes,
        "chunk {} input size changed",
        artifact.index_from_newest
    );
    ensure!(
        artifact.input_sha256.as_deref() == Some(&sha256_hex(&input)),
        "chunk {} input digest changed",
        artifact.index_from_newest
    );
    let journal = fs::read(artifact_dir.join(&artifact.expected_journal_file))?;
    ensure!(
        artifact.expected_journal_digest.as_deref() == Some(&sha256_hex(&journal)),
        "chunk {} expected journal changed",
        artifact.index_from_newest
    );
    Ok(())
}

fn selected_chunk_indexes(selection: &ChunkSelection) -> Result<Vec<usize>> {
    if selection.chunks.is_empty() {
        return Ok((0..HISTORICAL_CHUNK_COUNT).collect());
    }
    let indexes = selection.chunks.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        indexes
            .iter()
            .all(|index| usize::from(*index) < HISTORICAL_CHUNK_COUNT),
        "chunk index must be between 0 and 111"
    );
    Ok(indexes.iter().map(|index| usize::from(*index)).collect())
}

fn chunk_index_for_block(manifest: &HistoryManifest, block_number: u64) -> Result<usize> {
    ensure!(
        (HISTORICAL_START_BLOCK..HISTORICAL_ANCHOR_BLOCK).contains(&block_number),
        "block {block_number} is outside the historical range"
    );
    manifest
        .chunks
        .iter()
        .position(|chunk| (chunk.start_block..=chunk.end_block).contains(&block_number))
        .context("historical block has no chunk")
}

fn collect_historical_fixture_blocks(path: &Path, blocks: &mut BTreeSet<u64>) -> Result<()> {
    let value: Value = read_json(path)?;
    let fixture_blocks = value
        .get("blocks")
        .and_then(Value::as_array)
        .context("seller fixture has no blocks array")?;
    for block in fixture_blocks {
        let number = block
            .get("header")
            .and_then(|header| header.get("number"))
            .context("fixture block has no header number")?;
        let number = parse_json_u64(number)?;
        if (HISTORICAL_START_BLOCK..HISTORICAL_ANCHOR_BLOCK).contains(&number) {
            blocks.insert(number);
        }
    }
    Ok(())
}

fn parse_json_u64(value: &Value) -> Result<u64> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    let string = value
        .as_str()
        .context("block number is neither integer nor string")?;
    if let Some(hex) = string.strip_prefix("0x") {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(string.parse()?)
    }
}

fn guest_stdin(witness: &HistoricalChunkWitness) -> Result<Vec<u8>> {
    Ok(GuestEnv::builder().write(witness)?.build_env().stdin)
}

fn unsigned_transaction(
    order: usize,
    purpose: String,
    to: Address,
    data: Vec<u8>,
) -> UnsignedTransaction {
    UnsignedTransaction {
        order,
        purpose,
        to,
        value: "0x0".into(),
        data: format!("0x{}", alloy::hex::encode(data)),
    }
}

fn parse_u256(value: &str) -> Result<U256> {
    if let Some(hex) = value.strip_prefix("0x") {
        U256::from_str_radix(hex, 16).map_err(Into::into)
    } else {
        U256::from_str(value).map_err(Into::into)
    }
}

fn image_id_hex() -> String {
    let digest = risc0_zkvm::Digest::from(HISTORICAL_CHUNK_IMAGE_ID);
    format!("0x{}", alloy::hex::encode(digest.as_bytes()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(Sha256::digest(bytes)))
}

fn manifest_path(artifact_dir: &Path) -> PathBuf {
    artifact_dir.join("manifest.json")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> Result<T> {
    let path = path.as_ref();
    serde_json::from_slice(
        &fs::read(path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to decode {}", path.display()))
}

fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn write_json_atomic(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("json");
    let temp = path.with_extension(format!("{extension}.tmp"));
    write_json(&temp, value)?;
    fs::rename(&temp, path).with_context(|| {
        format!(
            "failed to atomically replace {} with {}",
            path.display(),
            temp.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cached_chain(start: u64, count: usize) -> HeaderCache {
        let mut headers = Vec::with_capacity(count);
        let mut parent_hash = B256::ZERO;
        for offset in 0..count {
            let header = Header {
                number: start + offset as u64,
                parent_hash,
                ..Default::default()
            };
            let rlp: alloy::primitives::Bytes = alloy_rlp::encode(header).into();
            parent_hash = keccak256(rlp.as_ref());
            headers.push(CachedHeader {
                number: start + offset as u64,
                rlp,
            });
        }
        HeaderCache {
            start_block: start,
            successor_block: start + 4,
            headers,
        }
    }

    #[test]
    fn page_bounds_resume_from_cached_prefix() {
        assert_eq!(next_page_bounds(100, 104, 0, 2).unwrap(), Some((100, 101)));
        assert_eq!(next_page_bounds(100, 104, 2, 2).unwrap(), Some((102, 103)));
        assert_eq!(next_page_bounds(100, 104, 4, 2).unwrap(), Some((104, 104)));
        assert_eq!(next_page_bounds(100, 104, 5, 2).unwrap(), None);
    }

    #[test]
    fn cached_header_prefix_is_canonical_and_linked() {
        let cache = cached_chain(100, 4);
        validate_header_cache(&cache, 100, 104).unwrap();
    }

    #[test]
    fn cached_header_gap_is_rejected() {
        let mut cache = cached_chain(100, 4);
        cache.headers[2].number = 103;
        let error = validate_header_cache(&cache, 100, 104).unwrap_err();
        assert!(error.to_string().contains("expected block 102"));
    }

    #[test]
    fn cached_header_parent_conflict_is_rejected() {
        let mut cache = cached_chain(100, 4);
        let mut header = decode_cached_header(&cache.headers[2]).unwrap();
        header.parent_hash = B256::repeat_byte(0x42);
        cache.headers[2].rlp = alloy_rlp::encode(header).into();
        let error = validate_header_cache(&cache, 100, 104).unwrap_err();
        assert!(error.to_string().contains("parent hash mismatch"));
    }

    #[test]
    fn cached_header_trailing_rlp_is_rejected() {
        let mut cache = cached_chain(100, 1);
        cache.headers[0].rlp = [cache.headers[0].rlp.as_ref(), &[0]].concat().into();
        let error = validate_header_cache(&cache, 100, 104).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"));
    }
}
