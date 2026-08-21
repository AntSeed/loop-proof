use alloy::{
    providers::{Provider, ProviderBuilder},
    sol,
};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_sol_types::{SolCall, SolValue};
use anyhow::{Context, Result, bail, ensure};
use checkpoint_host::state_plan::{StatePlan, check, entry};
use checkpoint_methods::{ACCUMULATOR_GUEST_ELF, ACCUMULATOR_IMAGE_ID};
use clap::{Parser, Subcommand};
use futures::{StreamExt, TryStreamExt, stream};
use history_core::{
    AccumulatorInput, AccumulatorJournal, EIP2935_WINDOW, EPOCH_SIZE, EpochJournal, EpochWitness,
    HISTORICAL_START_BLOCK, MmrProof, REQUIRED_COVERAGE_END_BLOCK, block_merkle_proof,
    epoch_commitment, epoch_end, epoch_start, mmr_proof, validate_accumulator, validate_epoch,
};
use history_methods::{EPOCH_GUEST_ELF, EPOCH_IMAGE_ID};
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::{
    Digest, ExecutorEnv, FakeReceipt, InnerReceipt, ProverOpts, Receipt, ReceiptClaim,
    VerifierContext, default_prover,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use url::Url;

sol! {
    struct HistoricalBlockProof {
        uint64 blockNumber;
        bytes32 blockHash;
        bytes32[14] blockSiblings;
        bytes32 epochFirstParentHash;
        bytes32 epochEndBlockHash;
        bytes32[] mountainSiblings;
        bytes32[] peaks;
        uint32 targetPeakIndex;
    }
    interface IAccumulatorOracle {
        function submitHistoricalAccumulator(bytes seal, bytes journalData);
        function materializeHistoricalBlocks(HistoricalBlockProof[] proofs) returns (uint256 stored);
        function historicalCoverageComplete() view returns (bool);
        function historicalEndBlock() view returns (uint64);
        function historicalEpochCount() view returns (uint32);
        function historicalMmrRoot() view returns (bytes32);
        function historicalJournalDigest() view returns (bytes32);
        function canonicalBlockHashes(uint64 blockNumber) view returns (bytes32);
    }
}

#[derive(Parser)]
#[command(about = "Build and submit the EIP-2935-anchored Base history accumulator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Plan {
        #[arg(long, env = "BASE_RPC_URL")]
        rpc_url: Url,
        #[arg(long)]
        out: PathBuf,
    },
    Fetch {
        #[arg(long, env = "BASE_RPC_URL")]
        rpc_url: Url,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long, default_value_t = 32)]
        concurrency: usize,
    },
    ProveEpochs {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        groth16: bool,
    },
    Aggregate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        groth16: bool,
    },
    StatePlan {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        oracle: Address,
        #[arg(long, value_delimiter = ',')]
        blocks: Vec<u64>,
        #[arg(long, default_value_t = 16)]
        batch_size: usize,
        #[arg(long)]
        out: PathBuf,
    },
    DevE2e {
        #[arg(long)]
        artifact_dir: PathBuf,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    version: u32,
    kind: String,
    chain_id: u64,
    start_block: u64,
    anchor_block: u64,
    epoch_count: u32,
    epoch_image_id: B256,
    accumulator_image_id: B256,
    epochs: Vec<EpochArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accumulator: Option<AccumulatorArtifact>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EpochArtifact {
    index: u32,
    start_block: u64,
    end_block: u64,
    witness_file: String,
    journal_file: String,
    receipt_file: String,
    status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccumulatorArtifact {
    journal_file: String,
    receipt_file: String,
    seal_file: String,
    journal_sha256: String,
    receipt_sha256: String,
    seal_sha256: String,
    mmr_root: B256,
    proof_mode: String,
    status: String,
}

fn image_id(words: [u32; 8]) -> B256 {
    B256::from_slice(Digest::from(words).as_bytes())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    match cli.command {
        Command::Plan { rpc_url, out } => plan(rpc_url, &out).await,
        Command::Fetch {
            rpc_url,
            manifest,
            artifact_dir,
            concurrency,
        } => fetch(rpc_url, &manifest, &artifact_dir, concurrency).await,
        Command::ProveEpochs {
            manifest,
            artifact_dir,
            groth16,
        } => prove_epochs(&manifest, &artifact_dir, groth16),
        Command::Aggregate {
            manifest,
            artifact_dir,
            groth16,
        } => aggregate(&manifest, &artifact_dir, groth16),
        Command::StatePlan {
            manifest,
            artifact_dir,
            oracle,
            blocks,
            batch_size,
            out,
        } => state_plan(&manifest, &artifact_dir, oracle, &blocks, batch_size, &out),
        Command::DevE2e { artifact_dir } => dev_e2e(&artifact_dir),
    }
}

async fn plan(rpc_url: Url, out: &Path) -> Result<()> {
    let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;
    let head = provider.get_block_number().await?;
    ensure!(
        head > HISTORICAL_START_BLOCK,
        "Base head predates historical start"
    );
    let available = head - 1;
    let epoch_count = (available - HISTORICAL_START_BLOCK + 1) / EPOCH_SIZE as u64;
    ensure!(epoch_count > 0, "no complete epoch available");
    let anchor = HISTORICAL_START_BLOCK + epoch_count * EPOCH_SIZE as u64 - 1;
    if head - anchor > EIP2935_WINDOW {
        let next_anchor = anchor + EPOCH_SIZE as u64;
        bail!(
            "no full-epoch anchor is currently in EIP-2935; retry after Base block {next_anchor}"
        );
    }
    ensure!(
        anchor >= REQUIRED_COVERAGE_END_BLOCK,
        "eligible anchor does not cover the proof period"
    );
    let epoch_count = u32::try_from(epoch_count)?;
    let epochs = (0..epoch_count)
        .map(|index| {
            Ok(EpochArtifact {
                index,
                start_block: epoch_start(index).map_err(anyhow::Error::msg)?,
                end_block: epoch_end(index).map_err(anyhow::Error::msg)?,
                witness_file: format!("epoch-{index:04}.witness.json"),
                journal_file: format!("epoch-{index:04}.journal.bin"),
                receipt_file: format!("epoch-{index:04}.receipt.bin"),
                status: "planned".into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = Manifest {
        version: 2,
        kind: "antseed-history-accumulator-artifacts".into(),
        chain_id: 8_453,
        start_block: HISTORICAL_START_BLOCK,
        anchor_block: anchor,
        epoch_count,
        epoch_image_id: image_id(EPOCH_IMAGE_ID),
        accumulator_image_id: image_id(ACCUMULATOR_IMAGE_ID),
        epochs,
        accumulator: None,
    };
    write_json(out, &manifest)?;
    println!("planned {} epochs through anchor {}", epoch_count, anchor);
    Ok(())
}

async fn fetch(
    rpc_url: Url,
    manifest_path: &Path,
    artifact_dir: &Path,
    concurrency: usize,
) -> Result<()> {
    ensure!(concurrency > 0, "concurrency must be positive");
    let mut manifest: Manifest = read_json(manifest_path)?;
    validate_manifest(&manifest)?;
    fs::create_dir_all(artifact_dir)?;
    let provider = ProviderBuilder::new().connect(rpc_url.as_str()).await?;
    for artifact_index in 0..manifest.epochs.len() {
        let artifact = manifest.epochs[artifact_index].clone();
        let path = artifact_dir.join(&artifact.witness_file);
        if path.exists() {
            let witness: EpochWitness = read_json(&path)?;
            let journal = validate_epoch(&witness).map_err(anyhow::Error::msg)?;
            ensure!(
                witness.epoch_index == artifact.index,
                "cached witness epoch index mismatch"
            );
            ensure!(
                journal.startBlockNumber == artifact.start_block
                    && journal.endBlockNumber == artifact.end_block,
                "cached witness epoch geometry mismatch"
            );
            println!("epoch {} cached", artifact.index);
            if manifest.epochs[artifact_index].status == "planned" {
                manifest.epochs[artifact_index].status = "fetched".into();
                write_json(manifest_path, &manifest)?;
            }
            continue;
        }
        let headers = stream::iter(artifact.start_block..=artifact.end_block)
            .map(|number| {
                let provider = provider.clone();
                async move {
                    let block = provider
                        .get_block_by_number(number.into())
                        .hashes()
                        .await?
                        .with_context(|| format!("Base block {number} not found"))?;
                    let header: Header = block.header.inner;
                    ensure!(
                        header.number == number,
                        "Base RPC returned wrong block number"
                    );
                    Ok::<_, anyhow::Error>(Bytes::from(alloy_rlp::encode(header)))
                }
            })
            .buffered(concurrency)
            .try_collect::<Vec<_>>()
            .await?;
        let witness = EpochWitness {
            epoch_index: artifact.index,
            base_headers_rlp: headers,
        };
        validate_epoch(&witness).map_err(anyhow::Error::msg)?;
        write_json(&path, &witness)?;
        manifest.epochs[artifact_index].status = "fetched".into();
        write_json(manifest_path, &manifest)?;
        println!("fetched epoch {}", artifact.index);
    }
    Ok(())
}

fn prove_epochs(manifest_path: &Path, artifact_dir: &Path, groth16: bool) -> Result<()> {
    ensure!(
        !groth16,
        "epoch proofs must remain composable; omit --groth16"
    );
    let mut manifest: Manifest = read_json(manifest_path)?;
    validate_manifest(&manifest)?;
    for artifact_index in 0..manifest.epochs.len() {
        let artifact = manifest.epochs[artifact_index].clone();
        let witness: EpochWitness = read_json(&artifact_dir.join(&artifact.witness_file))?;
        let expected = validate_epoch(&witness).map_err(anyhow::Error::msg)?;
        let journal_path = artifact_dir.join(&artifact.journal_file);
        let receipt_path = artifact_dir.join(&artifact.receipt_file);
        if journal_path.exists() && receipt_path.exists() {
            let journal =
                EpochJournal::decode(&fs::read(&journal_path)?).map_err(anyhow::Error::msg)?;
            let receipt: Receipt = bincode::deserialize(&fs::read(&receipt_path)?)?;
            receipt.verify(EPOCH_IMAGE_ID)?;
            ensure!(
                journal == expected && receipt.journal.bytes == journal.abi_encode(),
                "cached epoch {} proof mismatch",
                artifact.index
            );
            println!("epoch {} proof cached", artifact.index);
            if manifest.epochs[artifact_index].status != "proven" {
                manifest.epochs[artifact_index].status = "proven".into();
                write_json(manifest_path, &manifest)?;
            }
            continue;
        }
        let env = ExecutorEnv::builder().write(&witness)?.build()?;
        let opts = if groth16 {
            ProverOpts::groth16()
        } else {
            ProverOpts::default()
        };
        let info = default_prover().prove_with_ctx(
            env,
            &VerifierContext::default(),
            EPOCH_GUEST_ELF,
            &opts,
        )?;
        info.receipt.verify(EPOCH_IMAGE_ID)?;
        let journal =
            EpochJournal::decode(&info.receipt.journal.bytes).map_err(anyhow::Error::msg)?;
        ensure!(
            journal == expected,
            "epoch {} journal mismatch",
            artifact.index
        );
        fs::write(
            artifact_dir.join(&artifact.journal_file),
            &info.receipt.journal.bytes,
        )?;
        fs::write(
            artifact_dir.join(&artifact.receipt_file),
            bincode::serialize(&info.receipt)?,
        )?;
        manifest.epochs[artifact_index].status = "proven".into();
        write_json(manifest_path, &manifest)?;
        println!(
            "proved epoch {}: {} padded cycles",
            artifact.index, info.stats.total_cycles
        );
    }
    Ok(())
}

fn aggregate(manifest_path: &Path, artifact_dir: &Path, groth16: bool) -> Result<()> {
    ensure!(
        !(groth16 && std::env::var("RISC0_DEV_MODE").ok().as_deref() == Some("1")),
        "Groth16 aggregation is forbidden in RISC0_DEV_MODE"
    );
    let mut manifest: Manifest = read_json(manifest_path)?;
    validate_manifest(&manifest)?;
    ensure!(
        manifest
            .epochs
            .iter()
            .all(|artifact| artifact.status == "proven"),
        "all epoch proofs must be complete before aggregation"
    );
    let mut journals = Vec::with_capacity(manifest.epochs.len());
    let mut receipts = Vec::with_capacity(manifest.epochs.len());
    for artifact in &manifest.epochs {
        journals.push(Bytes::from(fs::read(
            artifact_dir.join(&artifact.journal_file),
        )?));
        receipts.push(bincode::deserialize::<Receipt>(&fs::read(
            artifact_dir.join(&artifact.receipt_file),
        )?)?);
    }
    let input = AccumulatorInput {
        epoch_image_id: manifest.epoch_image_id,
        epoch_journals: journals,
    };
    let expected = validate_accumulator(&input).map_err(anyhow::Error::msg)?;
    ensure!(
        expected.anchorBlockNumber == manifest.anchor_block,
        "manifest anchor mismatch"
    );
    let mut builder = ExecutorEnv::builder();
    builder.write(&input)?;
    for receipt in receipts {
        builder.add_assumption(receipt);
    }
    let env = builder.build()?;
    let opts = if groth16 {
        ProverOpts::groth16()
    } else {
        ProverOpts::default()
    };
    let info = default_prover().prove_with_ctx(
        env,
        &VerifierContext::default(),
        ACCUMULATOR_GUEST_ELF,
        &opts,
    )?;
    info.receipt.verify(ACCUMULATOR_IMAGE_ID)?;
    let journal =
        AccumulatorJournal::decode(&info.receipt.journal.bytes).map_err(anyhow::Error::msg)?;
    ensure!(journal == expected, "aggregate journal mismatch");
    let journal_file = "accumulator.journal.bin";
    let receipt_file = "accumulator.receipt.bin";
    let seal_file = "accumulator.seal.bin";
    fs::write(artifact_dir.join(journal_file), &info.receipt.journal.bytes)?;
    fs::write(
        artifact_dir.join(receipt_file),
        bincode::serialize(&info.receipt)?,
    )?;
    fs::write(artifact_dir.join(seal_file), encode_seal(&info.receipt)?)?;
    manifest.accumulator = Some(AccumulatorArtifact {
        journal_file: journal_file.into(),
        receipt_file: receipt_file.into(),
        seal_file: seal_file.into(),
        journal_sha256: file_sha256(&artifact_dir.join(journal_file))?,
        receipt_sha256: file_sha256(&artifact_dir.join(receipt_file))?,
        seal_sha256: file_sha256(&artifact_dir.join(seal_file))?,
        mmr_root: journal.mmrRoot,
        proof_mode: if groth16 { "groth16" } else { "composite" }.into(),
        status: "proven".into(),
    });
    write_json(manifest_path, &manifest)?;
    println!(
        "aggregated {} epochs into {}",
        manifest.epoch_count, journal.mmrRoot
    );
    Ok(())
}

fn state_plan(
    manifest_path: &Path,
    artifact_dir: &Path,
    oracle: Address,
    blocks: &[u64],
    batch_size: usize,
    out: &Path,
) -> Result<()> {
    ensure!(
        !blocks.is_empty() && batch_size > 0,
        "blocks and batch size are required"
    );
    let manifest: Manifest = read_json(manifest_path)?;
    validate_manifest(&manifest)?;
    let aggregate = manifest
        .accumulator
        .as_ref()
        .context("accumulator proof is incomplete")?;
    ensure!(
        aggregate.status == "proven",
        "accumulator proof is incomplete"
    );
    ensure!(
        aggregate.proof_mode == "groth16",
        "state plans require a production Groth16 accumulator receipt"
    );
    ensure!(
        file_sha256(&artifact_dir.join(&aggregate.journal_file))? == aggregate.journal_sha256,
        "accumulator journal digest mismatch"
    );
    ensure!(
        file_sha256(&artifact_dir.join(&aggregate.receipt_file))? == aggregate.receipt_sha256,
        "accumulator receipt digest mismatch"
    );
    ensure!(
        file_sha256(&artifact_dir.join(&aggregate.seal_file))? == aggregate.seal_sha256,
        "accumulator seal digest mismatch"
    );
    let journal_data = fs::read(artifact_dir.join(&aggregate.journal_file))?;
    let receipt: Receipt =
        bincode::deserialize(&fs::read(artifact_dir.join(&aggregate.receipt_file))?)?;
    let seal = fs::read(artifact_dir.join(&aggregate.seal_file))?;
    let journal_digest = B256::from_slice(&Sha256::digest(&journal_data));
    receipt.verify(ACCUMULATOR_IMAGE_ID)?;
    ensure!(
        matches!(&receipt.inner, InnerReceipt::Groth16(_)),
        "accumulator receipt is not Groth16"
    );
    ensure!(
        receipt.journal.bytes == journal_data,
        "accumulator receipt journal mismatch"
    );
    ensure!(
        encode_seal(&receipt)? == seal,
        "accumulator seal does not match receipt"
    );
    let accumulator = AccumulatorJournal::decode(&journal_data).map_err(anyhow::Error::msg)?;
    ensure!(
        aggregate.mmr_root == accumulator.mmrRoot,
        "accumulator manifest MMR root mismatch"
    );
    let mut epoch_journals = Vec::with_capacity(manifest.epochs.len());
    for artifact in &manifest.epochs {
        epoch_journals.push(
            EpochJournal::decode(&fs::read(artifact_dir.join(&artifact.journal_file))?)
                .map_err(anyhow::Error::msg)?,
        );
    }
    let expected_accumulator = validate_accumulator(&AccumulatorInput {
        epoch_image_id: manifest.epoch_image_id,
        epoch_journals: epoch_journals
            .iter()
            .map(|journal| Bytes::from(journal.abi_encode()))
            .collect(),
    })
    .map_err(anyhow::Error::msg)?;
    ensure!(
        accumulator == expected_accumulator,
        "accumulator artifact mismatch"
    );
    let commitments = epoch_journals
        .iter()
        .map(epoch_commitment)
        .collect::<Vec<_>>();
    let mut proofs = Vec::new();
    let mut sorted = blocks.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    for block_number in sorted {
        ensure!(
            block_number >= HISTORICAL_START_BLOCK && block_number <= accumulator.endBlockNumber,
            "block outside accumulator"
        );
        let epoch_index =
            usize::try_from((block_number - HISTORICAL_START_BLOCK) / EPOCH_SIZE as u64)?;
        let artifact = &manifest.epochs[epoch_index];
        let witness: EpochWitness = read_json(&artifact_dir.join(&artifact.witness_file))?;
        let witness_journal = validate_epoch(&witness).map_err(anyhow::Error::msg)?;
        ensure!(
            witness_journal == epoch_journals[epoch_index],
            "epoch witness does not match proved journal"
        );
        let hashes = witness
            .base_headers_rlp
            .iter()
            .map(|header| keccak256(header.as_ref()))
            .collect::<Vec<_>>();
        let offset = usize::try_from(block_number - artifact.start_block)?;
        let block_hash = hashes[offset];
        let block_siblings: [B256; 14] =
            block_merkle_proof(artifact.start_block, &hashes, block_number)
                .map_err(anyhow::Error::msg)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("wrong block proof depth"))?;
        let MmrProof {
            mountain_siblings,
            peaks,
            target_peak_index,
        } = mmr_proof(&commitments, epoch_index).map_err(anyhow::Error::msg)?;
        let epoch = &epoch_journals[epoch_index];
        proofs.push(HistoricalBlockProof {
            blockNumber: block_number,
            blockHash: block_hash,
            blockSiblings: block_siblings,
            epochFirstParentHash: epoch.firstParentHash,
            epochEndBlockHash: epoch.endBlockHash,
            mountainSiblings: mountain_siblings,
            peaks,
            targetPeakIndex: target_peak_index,
        });
    }
    let mut entries = vec![entry(
        "historical-accumulator",
        0,
        "submit EIP-2935-anchored historical accumulator",
        oracle,
        &IAccumulatorOracle::submitHistoricalAccumulatorCall {
            seal: seal.into(),
            journalData: journal_data.into(),
        }
        .abi_encode(),
        vec![
            check(
                oracle,
                &IAccumulatorOracle::historicalCoverageCompleteCall {}.abi_encode(),
                &true.abi_encode(),
            ),
            check(
                oracle,
                &IAccumulatorOracle::historicalEndBlockCall {}.abi_encode(),
                &accumulator.endBlockNumber.abi_encode(),
            ),
            check(
                oracle,
                &IAccumulatorOracle::historicalEpochCountCall {}.abi_encode(),
                &accumulator.epochCount.abi_encode(),
            ),
            check(
                oracle,
                &IAccumulatorOracle::historicalMmrRootCall {}.abi_encode(),
                &accumulator.mmrRoot.abi_encode(),
            ),
            check(
                oracle,
                &IAccumulatorOracle::historicalJournalDigestCall {}.abi_encode(),
                &journal_digest.abi_encode(),
            ),
        ],
    )];
    for (batch_index, batch) in proofs.chunks(batch_size).enumerate() {
        let order = entries.len();
        entries.push(entry(
            format!("historical-materialization-{batch_index}"),
            order,
            format!("materialize {} historical blocks", batch.len()),
            oracle,
            &IAccumulatorOracle::materializeHistoricalBlocksCall {
                proofs: batch.to_vec(),
            }
            .abi_encode(),
            batch
                .iter()
                .map(|proof| {
                    check(
                        oracle,
                        &IAccumulatorOracle::canonicalBlockHashesCall {
                            blockNumber: proof.blockNumber,
                        }
                        .abi_encode(),
                        &proof.blockHash.abi_encode(),
                    )
                })
                .collect(),
        ));
    }
    write_json(out, &StatePlan::new(8_453, oracle, entries)?)?;
    println!(
        "wrote accumulator state plan with {} block proofs",
        proofs.len()
    );
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    ensure!(
        manifest.version == 2 && manifest.kind == "antseed-history-accumulator-artifacts",
        "unsupported accumulator manifest"
    );
    ensure!(
        manifest.chain_id == 8_453 && manifest.start_block == HISTORICAL_START_BLOCK,
        "accumulator manifest chain or start mismatch"
    );
    ensure!(
        manifest.epoch_count as usize == manifest.epochs.len() && manifest.epoch_count > 0,
        "accumulator manifest epoch count mismatch"
    );
    ensure!(
        manifest.epoch_image_id == image_id(EPOCH_IMAGE_ID),
        "accumulator manifest epoch image ID mismatch"
    );
    ensure!(
        manifest.accumulator_image_id == image_id(ACCUMULATOR_IMAGE_ID),
        "accumulator manifest image ID mismatch"
    );
    ensure!(
        manifest.anchor_block == epoch_end(manifest.epoch_count - 1).map_err(anyhow::Error::msg)?,
        "accumulator manifest anchor mismatch"
    );
    for (index, artifact) in manifest.epochs.iter().enumerate() {
        let index = u32::try_from(index)?;
        ensure!(
            artifact.index == index,
            "noncontiguous accumulator epoch indexes"
        );
        ensure!(
            matches!(artifact.status.as_str(), "planned" | "fetched" | "proven"),
            "invalid accumulator epoch status"
        );
        ensure!(
            artifact.start_block == epoch_start(index).map_err(anyhow::Error::msg)?
                && artifact.end_block == epoch_end(index).map_err(anyhow::Error::msg)?,
            "accumulator epoch geometry mismatch"
        );
        ensure!(
            artifact.witness_file == format!("epoch-{index:04}.witness.json")
                && artifact.journal_file == format!("epoch-{index:04}.journal.bin")
                && artifact.receipt_file == format!("epoch-{index:04}.receipt.bin"),
            "accumulator epoch filenames are invalid"
        );
    }
    if let Some(aggregate) = &manifest.accumulator {
        ensure!(
            aggregate.journal_file == "accumulator.journal.bin"
                && aggregate.receipt_file == "accumulator.receipt.bin"
                && aggregate.seal_file == "accumulator.seal.bin",
            "accumulator artifact filenames are invalid"
        );
        ensure!(
            matches!(aggregate.proof_mode.as_str(), "composite" | "groth16"),
            "invalid accumulator proof mode"
        );
        ensure!(aggregate.status == "proven", "invalid accumulator status");
        for digest in [
            &aggregate.journal_sha256,
            &aggregate.receipt_sha256,
            &aggregate.seal_sha256,
        ] {
            ensure!(
                digest.len() == 66
                    && digest.starts_with("0x")
                    && digest[2..].bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid accumulator artifact digest"
            );
        }
    }
    Ok(())
}

fn dev_e2e(artifact_dir: &Path) -> Result<()> {
    ensure!(
        std::env::var("RISC0_DEV_MODE").ok().as_deref() == Some("1"),
        "dev-e2e requires RISC0_DEV_MODE=1"
    );
    fs::create_dir_all(artifact_dir)?;

    let mut headers = Vec::with_capacity(EPOCH_SIZE);
    let mut parent_hash = keccak256(b"antseed-dev-genesis");
    for number in HISTORICAL_START_BLOCK..HISTORICAL_START_BLOCK + EPOCH_SIZE as u64 {
        let mut header = Header::default();
        header.number = number;
        header.parent_hash = parent_hash;
        let encoded = Bytes::from(alloy_rlp::encode(header));
        parent_hash = keccak256(encoded.as_ref());
        headers.push(encoded);
    }
    let witness = EpochWitness {
        epoch_index: 0,
        base_headers_rlp: headers,
    };
    let first_expected = validate_epoch(&witness).map_err(anyhow::Error::msg)?;
    let epoch_info = default_prover().prove(
        ExecutorEnv::builder().write(&witness)?.build()?,
        EPOCH_GUEST_ELF,
    )?;
    epoch_info.receipt.verify(EPOCH_IMAGE_ID)?;
    ensure!(
        EpochJournal::decode(&epoch_info.receipt.journal.bytes).map_err(anyhow::Error::msg)?
            == first_expected,
        "dev epoch journal mismatch"
    );

    let required_epoch_count = u32::try_from(
        (REQUIRED_COVERAGE_END_BLOCK - HISTORICAL_START_BLOCK + 1).div_ceil(EPOCH_SIZE as u64),
    )?;
    let mut journals = vec![Bytes::from(epoch_info.receipt.journal.bytes.clone())];
    let mut receipts = vec![epoch_info.receipt];
    let mut previous_hash = first_expected.endBlockHash;
    for epoch_index in 1..required_epoch_count {
        let end_hash = keccak256(epoch_index.to_be_bytes());
        let journal = EpochJournal {
            version: history_core::JOURNAL_VERSION,
            chainId: history_core::BASE_CHAIN_ID,
            epochIndex: epoch_index,
            startBlockNumber: epoch_start(epoch_index).map_err(anyhow::Error::msg)?,
            endBlockNumber: epoch_end(epoch_index).map_err(anyhow::Error::msg)?,
            firstParentHash: previous_hash,
            endBlockHash: end_hash,
            blockCount: EPOCH_SIZE as u32,
            blockRoot: keccak256(
                [
                    b"antseed-dev-block-root".as_slice(),
                    &epoch_index.to_be_bytes(),
                ]
                .concat(),
            ),
        };
        let encoded = journal.abi_encode();
        let claim = ReceiptClaim::ok(Digest::from(EPOCH_IMAGE_ID), encoded.clone());
        receipts.push(Receipt::new(
            InnerReceipt::Fake(FakeReceipt::new(claim)),
            encoded.clone(),
        ));
        journals.push(Bytes::from(encoded));
        previous_hash = end_hash;
    }

    let input = AccumulatorInput {
        epoch_image_id: image_id(EPOCH_IMAGE_ID),
        epoch_journals: journals,
    };
    let expected = validate_accumulator(&input).map_err(anyhow::Error::msg)?;
    let mut builder = ExecutorEnv::builder();
    builder.write(&input)?;
    for receipt in receipts {
        builder.add_assumption(receipt);
    }
    let aggregate_info = default_prover().prove(builder.build()?, ACCUMULATOR_GUEST_ELF)?;
    aggregate_info.receipt.verify(ACCUMULATOR_IMAGE_ID)?;
    ensure!(
        AccumulatorJournal::decode(&aggregate_info.receipt.journal.bytes)
            .map_err(anyhow::Error::msg)?
            == expected,
        "dev aggregate journal mismatch"
    );
    fs::write(
        artifact_dir.join("dev-accumulator.journal.bin"),
        &aggregate_info.receipt.journal.bytes,
    )?;
    fs::write(
        artifact_dir.join("dev-accumulator.receipt.bin"),
        bincode::serialize(&aggregate_info.receipt)?,
    )?;
    fs::write(
        artifact_dir.join("dev-accumulator.seal.bin"),
        encode_seal(&aggregate_info.receipt)?,
    )?;
    println!(
        "dev composition verified one epoch guest plus {required_epoch_count} aggregate assumptions"
    );
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn file_sha256(path: &Path) -> Result<String> {
    let digest = Sha256::digest(fs::read(path)?);
    Ok(format!("0x{digest:x}"))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(temp, path)?;
    Ok(())
}
