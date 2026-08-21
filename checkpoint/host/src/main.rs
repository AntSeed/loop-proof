use alloy::{
    providers::{Provider, ProviderBuilder},
    sol,
};
use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolValue};
use anyhow::{Context, Result, bail, ensure};
use checkpoint_host::state_plan::{StatePlan, check, entry};
use checkpoint_methods::ACCUMULATOR_GUEST_ELF;
use clap::{Parser, Subcommand};
use futures::{StreamExt, TryStreamExt, stream};
use history_core::{
    AccumulatorInput, AccumulatorJournal, EIP2935_WINDOW, EPOCH_SIZE, EpochJournal, EpochWitness,
    HISTORICAL_START_BLOCK, MmrProof, REQUIRED_COVERAGE_END_BLOCK, block_merkle_proof,
    epoch_commitment, epoch_end, epoch_start, mmr_proof, validate_accumulator, validate_epoch,
};
use history_methods::EPOCH_GUEST_ELF;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use sp1_sdk::{
    Elf, HashableKey, ProvingKey, SP1Proof, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey,
    SP1PublicValues, SP1Stdin,
    blocking::{NetworkProver, ProveRequest, Prover, ProverClient},
    network::proto::GetProofRequestParamsResponse,
};
use std::{
    env, fs,
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
        function submitHistoricalAccumulator(bytes proofBytes, bytes publicValues);
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
    ProgramMetadata {
        #[arg(long)]
        out: PathBuf,
    },
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
    },
    MeasureEpochs {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    SmokeRecursive {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Aggregate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
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
    #[serde(rename = "epochRecursionVKey")]
    epoch_recursion_vkey: B256,
    #[serde(rename = "accumulatorProgramVKey")]
    accumulator_program_vkey: B256,
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
    proof_file: String,
    status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccumulatorArtifact {
    journal_file: String,
    proof_file: String,
    proof_bytes_file: String,
    journal_sha256: String,
    proof_sha256: String,
    proof_bytes_sha256: String,
    mmr_root: B256,
    proof_mode: String,
    status: String,
}

#[derive(Clone, Copy)]
struct NetworkProofCaps {
    max_base_fee: u64,
    max_price_per_pgu: u64,
}

struct NetworkProofContext {
    client: NetworkProver,
    proving_key: SP1ProvingKey,
    caps: NetworkProofCaps,
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    match cli.command {
        Command::ProgramMetadata { out } => write_program_metadata(&out),
        Command::Plan { rpc_url, out } => {
            let (epoch_recursion_vkey, accumulator_program_vkey) = program_vkeys()?;
            runtime()?.block_on(plan(
                rpc_url,
                &out,
                epoch_recursion_vkey,
                accumulator_program_vkey,
            ))
        }
        Command::Fetch {
            rpc_url,
            manifest,
            artifact_dir,
            concurrency,
        } => {
            let planned: Manifest = read_json(&manifest)?;
            validate_manifest(&planned)?;
            runtime()?.block_on(fetch(rpc_url, &manifest, &artifact_dir, concurrency))
        }
        Command::ProveEpochs {
            manifest,
            artifact_dir,
        } => prove_epochs(&manifest, &artifact_dir),
        Command::MeasureEpochs {
            manifest,
            artifact_dir,
            out,
        } => measure_epochs(&manifest, &artifact_dir, &out),
        Command::SmokeRecursive {
            manifest,
            artifact_dir,
            out,
        } => smoke_recursive(&manifest, &artifact_dir, &out),
        Command::Aggregate {
            manifest,
            artifact_dir,
        } => aggregate(&manifest, &artifact_dir),
        Command::StatePlan {
            manifest,
            artifact_dir,
            oracle,
            blocks,
            batch_size,
            out,
        } => state_plan(&manifest, &artifact_dir, oracle, &blocks, batch_size, &out),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn write_program_metadata(out: &Path) -> Result<()> {
    let client = ProverClient::builder().cpu().build();
    let epoch_key = client.setup(EPOCH_GUEST_ELF.clone())?;
    let accumulator_key = client.setup(ACCUMULATOR_GUEST_ELF.clone())?;
    let metadata = serde_json::json!({
        "version": 1,
        "kind": "antseed-sp1-program-metadata",
        "sp1Version": "6.1.0",
        "programs": {
            "historyEpoch": program_metadata(
                &EPOCH_GUEST_ELF,
                epoch_key.verifying_key().bytes32(),
                Some(format!("0x{}", hex::encode(epoch_key.verifying_key().hash_bytes()))),
            ),
            "accumulator": program_metadata(
                &ACCUMULATOR_GUEST_ELF,
                accumulator_key.verifying_key().bytes32(),
                None,
            ),
        },
    });
    write_json(out, &metadata)
}

fn program_metadata(
    elf: &Elf,
    program_vkey: String,
    recursion_vkey: Option<String>,
) -> serde_json::Value {
    let bytes = match elf {
        Elf::Static(bytes) => *bytes,
        Elf::Dynamic(bytes) => bytes.as_ref(),
    };
    serde_json::json!({
        "programVKey": program_vkey,
        "recursionVKey": recursion_vkey,
        "elfSha256": format!("0x{:x}", Sha256::digest(bytes)),
        "elfBytes": bytes.len(),
    })
}

async fn plan(
    rpc_url: Url,
    out: &Path,
    epoch_recursion_vkey: B256,
    accumulator_program_vkey: B256,
) -> Result<()> {
    let provider = ProviderBuilder::new().connect_http(rpc_url);
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
                proof_file: format!("epoch-{index:04}.proof.bin"),
                status: "planned".into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = Manifest {
        version: 3,
        kind: "antseed-sp1-history-accumulator-artifacts".into(),
        chain_id: 8_453,
        start_block: HISTORICAL_START_BLOCK,
        anchor_block: anchor,
        epoch_count,
        epoch_recursion_vkey,
        accumulator_program_vkey,
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
    fs::create_dir_all(artifact_dir)?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);
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

fn prove_epochs(manifest_path: &Path, artifact_dir: &Path) -> Result<()> {
    ensure_production_prover()?;
    let mut manifest: Manifest = read_json(manifest_path)?;
    validate_manifest(&manifest)?;
    let client = ProverClient::from_env();
    let epoch_key = client.setup(EPOCH_GUEST_ELF.clone())?;
    let network = network_proof_context(EPOCH_GUEST_ELF.clone(), SP1ProofMode::Compressed)?;
    for artifact_index in 0..manifest.epochs.len() {
        let artifact = manifest.epochs[artifact_index].clone();
        let witness: EpochWitness = read_json(&artifact_dir.join(&artifact.witness_file))?;
        let expected = validate_epoch(&witness).map_err(anyhow::Error::msg)?;
        let journal_path = artifact_dir.join(&artifact.journal_file);
        let proof_path = artifact_dir.join(&artifact.proof_file);
        if journal_path.exists() && proof_path.exists() {
            let journal =
                EpochJournal::decode(&fs::read(&journal_path)?).map_err(anyhow::Error::msg)?;
            let proof = SP1ProofWithPublicValues::load(&proof_path)?;
            client.verify(&proof, epoch_key.verifying_key(), None)?;
            ensure!(
                matches!(&proof.proof, SP1Proof::Compressed(_))
                    && journal == expected
                    && proof.public_values.as_slice() == journal.abi_encode(),
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
        let mut stdin = SP1Stdin::new();
        stdin.write(&witness);
        let proof = if let Some(network) = &network {
            network.prove_compressed(stdin)?
        } else {
            client.prove(&epoch_key, stdin).compressed().run()?
        };
        client.verify(&proof, epoch_key.verifying_key(), None)?;
        ensure!(
            matches!(&proof.proof, SP1Proof::Compressed(_)),
            "epoch proof is not compressed"
        );
        let journal =
            EpochJournal::decode(proof.public_values.as_slice()).map_err(anyhow::Error::msg)?;
        ensure!(
            journal == expected,
            "epoch {} journal mismatch",
            artifact.index
        );
        fs::write(
            artifact_dir.join(&artifact.journal_file),
            proof.public_values.as_slice(),
        )?;
        proof.save(artifact_dir.join(&artifact.proof_file))?;
        manifest.epochs[artifact_index].status = "proven".into();
        write_json(manifest_path, &manifest)?;
        println!("proved SP1 epoch {}", artifact.index);
    }
    Ok(())
}

fn measure_epochs(manifest_path: &Path, artifact_dir: &Path, out: &Path) -> Result<()> {
    let manifest: Manifest = read_json(manifest_path)?;
    validate_manifest(&manifest)?;
    let client = ProverClient::builder().cpu().build();
    let mut measurements = Vec::with_capacity(manifest.epochs.len());
    for artifact in &manifest.epochs {
        let witness_path = artifact_dir.join(&artifact.witness_file);
        ensure!(
            witness_path.exists(),
            "epoch {} witness is missing",
            artifact.index
        );
        let witness: EpochWitness = read_json(&witness_path)?;
        let expected = validate_epoch(&witness).map_err(anyhow::Error::msg)?;
        let mut stdin = SP1Stdin::new();
        stdin.write(&witness);
        let (public_values, report) = client
            .execute(EPOCH_GUEST_ELF.clone(), stdin)
            .calculate_gas(true)
            .run()?;
        ensure!(
            public_values.as_slice() == expected.abi_encode(),
            "epoch {} measured journal mismatch",
            artifact.index
        );
        measurements.push(serde_json::json!({
            "index": artifact.index,
            "instructionCount": report.total_instruction_count(),
            "proverGasUnits": report.gas().context("SP1 gas calculation missing")?,
            "witnessBytes": fs::metadata(&witness_path)?.len(),
        }));
        println!("measured SP1 epoch {}", artifact.index);
    }
    write_json(
        out,
        &serde_json::json!({
            "version": 1,
            "kind": "antseed-sp1-epoch-measurements",
            "epochCount": measurements.len(),
            "measurements": measurements,
        }),
    )
}

fn smoke_recursive(manifest_path: &Path, artifact_dir: &Path, out: &Path) -> Result<()> {
    let manifest: Manifest = read_json(manifest_path)?;
    validate_manifest(&manifest)?;
    let client = ProverClient::builder().mock().build();
    let epoch_key = client.setup(EPOCH_GUEST_ELF.clone())?;
    let accumulator_key = client.setup(ACCUMULATOR_GUEST_ELF.clone())?;
    let first_artifact = manifest.epochs.first().context("manifest has no epochs")?;
    let first_witness: EpochWitness = read_json(&artifact_dir.join(&first_artifact.witness_file))?;
    let first_journal = validate_epoch(&first_witness).map_err(anyhow::Error::msg)?;
    let mut first_stdin = SP1Stdin::new();
    first_stdin.write(&first_witness);
    let template_proof = client.prove(&epoch_key, first_stdin).compressed().run()?;
    client.verify(&template_proof, epoch_key.verifying_key(), None)?;
    ensure!(
        matches!(&template_proof.proof, SP1Proof::Compressed(_))
            && template_proof.public_values.as_slice() == first_journal.abi_encode(),
        "mock epoch proof mismatch"
    );
    let mut journals = Vec::with_capacity(manifest.epochs.len());
    let mut proofs = Vec::with_capacity(manifest.epochs.len());
    let mut previous_end_hash = first_journal.endBlockHash;
    for artifact in &manifest.epochs {
        let journal = if artifact.index == 0 {
            first_journal.clone()
        } else {
            let end_block_hash = keccak256(("smoke-end", artifact.index).abi_encode());
            let journal = EpochJournal {
                version: history_core::JOURNAL_VERSION,
                chainId: history_core::BASE_CHAIN_ID,
                epochIndex: artifact.index,
                startBlockNumber: artifact.start_block,
                endBlockNumber: artifact.end_block,
                firstParentHash: previous_end_hash,
                endBlockHash: end_block_hash,
                blockCount: EPOCH_SIZE as u32,
                blockRoot: keccak256(("smoke-root", artifact.index).abi_encode()),
            };
            previous_end_hash = end_block_hash;
            journal
        };
        let journal_bytes = journal.abi_encode();
        let mut proof = template_proof.clone();
        proof.public_values = SP1PublicValues::from(&journal_bytes);
        journals.push(Bytes::from(journal_bytes));
        proofs.push(proof);
    }
    let input = AccumulatorInput {
        epoch_recursion_vkey: epoch_key.verifying_key().hash_u32(),
        epoch_journals: journals,
    };
    let expected = validate_accumulator(&input).map_err(anyhow::Error::msg)?;
    let accumulator_stdin = || {
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);
        for proof in &proofs {
            let SP1Proof::Compressed(compressed) = &proof.proof else {
                unreachable!("compressed proof checked above");
            };
            stdin.write_proof(
                compressed.as_ref().clone(),
                epoch_key.verifying_key().vk.clone(),
            );
        }
        stdin
    };
    let (public_values, report) = client
        .execute(ACCUMULATOR_GUEST_ELF.clone(), accumulator_stdin())
        .deferred_proof_verification(false)
        .calculate_gas(true)
        .run()?;
    ensure!(
        public_values.as_slice() == expected.abi_encode(),
        "mock accumulator execution mismatch"
    );
    let proof = client
        .prove(&accumulator_key, accumulator_stdin())
        .groth16()
        .deferred_proof_verification(false)
        .run()?;
    client.verify(&proof, accumulator_key.verifying_key(), None)?;
    ensure!(
        matches!(&proof.proof, SP1Proof::Groth16(_))
            && proof.public_values.as_slice() == expected.abi_encode(),
        "mock accumulator proof mismatch"
    );
    write_json(
        out,
        &serde_json::json!({
            "version": 1,
            "kind": "antseed-sp1-recursive-smoke",
            "securityMode": "insecure-mock",
            "epochCount": manifest.epoch_count,
            "accumulatorInstructionCount": report.total_instruction_count(),
            "accumulatorProverGasUnits": report.gas().context("SP1 gas calculation missing")?,
            "journalDigest": format!("0x{:x}", Sha256::digest(proof.public_values.as_slice())),
            "passed": true,
        }),
    )
}

fn aggregate(manifest_path: &Path, artifact_dir: &Path) -> Result<()> {
    ensure_production_prover()?;
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
    let mut proofs = Vec::with_capacity(manifest.epochs.len());
    for artifact in &manifest.epochs {
        journals.push(Bytes::from(fs::read(
            artifact_dir.join(&artifact.journal_file),
        )?));
        proofs.push(SP1ProofWithPublicValues::load(
            artifact_dir.join(&artifact.proof_file),
        )?);
    }
    let client = ProverClient::from_env();
    let epoch_key = client.setup(EPOCH_GUEST_ELF.clone())?;
    let accumulator_key = client.setup(ACCUMULATOR_GUEST_ELF.clone())?;
    let network = network_proof_context(ACCUMULATOR_GUEST_ELF.clone(), SP1ProofMode::Groth16)?;
    let input = AccumulatorInput {
        epoch_recursion_vkey: epoch_key.verifying_key().hash_u32(),
        epoch_journals: journals,
    };
    let expected = validate_accumulator(&input).map_err(anyhow::Error::msg)?;
    ensure!(
        expected.anchorBlockNumber == manifest.anchor_block,
        "manifest anchor mismatch"
    );
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);
    for proof in proofs {
        let SP1Proof::Compressed(compressed) = proof.proof else {
            bail!("epoch proof is not compressed");
        };
        stdin.write_proof(*compressed, epoch_key.verifying_key().vk.clone());
    }
    let proof = if let Some(network) = &network {
        network.prove_groth16(stdin)?
    } else {
        client.prove(&accumulator_key, stdin).groth16().run()?
    };
    client.verify(&proof, accumulator_key.verifying_key(), None)?;
    ensure!(
        matches!(&proof.proof, SP1Proof::Groth16(_)),
        "accumulator proof is not Groth16"
    );
    let journal =
        AccumulatorJournal::decode(proof.public_values.as_slice()).map_err(anyhow::Error::msg)?;
    ensure!(journal == expected, "aggregate journal mismatch");
    let journal_file = "accumulator.journal.bin";
    let proof_file = "accumulator.proof.bin";
    let proof_bytes_file = "accumulator.proof-bytes.bin";
    fs::write(
        artifact_dir.join(journal_file),
        proof.public_values.as_slice(),
    )?;
    proof.save(artifact_dir.join(proof_file))?;
    fs::write(artifact_dir.join(proof_bytes_file), proof.bytes())?;
    manifest.accumulator = Some(AccumulatorArtifact {
        journal_file: journal_file.into(),
        proof_file: proof_file.into(),
        proof_bytes_file: proof_bytes_file.into(),
        journal_sha256: file_sha256(&artifact_dir.join(journal_file))?,
        proof_sha256: file_sha256(&artifact_dir.join(proof_file))?,
        proof_bytes_sha256: file_sha256(&artifact_dir.join(proof_bytes_file))?,
        mmr_root: journal.mmrRoot,
        proof_mode: "sp1-groth16".into(),
        status: "proven".into(),
    });
    write_json(manifest_path, &manifest)?;
    println!(
        "aggregated {} epochs into {}",
        manifest.epoch_count, journal.mmrRoot
    );
    Ok(())
}

impl NetworkProofContext {
    fn new(elf: Elf, mode: SP1ProofMode) -> Result<Self> {
        let client = ProverClient::builder().network().build();
        let caps = network_proof_caps(&client, mode)?;
        let proving_key = client.setup(elf)?;
        Ok(Self {
            client,
            proving_key,
            caps,
        })
    }

    fn prove_compressed(&self, stdin: SP1Stdin) -> Result<SP1ProofWithPublicValues> {
        self.client
            .prove(&self.proving_key, stdin)
            .compressed()
            .max_price_per_pgu(self.caps.max_price_per_pgu)
            .run()
    }

    fn prove_groth16(&self, stdin: SP1Stdin) -> Result<SP1ProofWithPublicValues> {
        self.client
            .prove(&self.proving_key, stdin)
            .groth16()
            .max_price_per_pgu(self.caps.max_price_per_pgu)
            .run()
    }
}

fn network_proof_context(elf: Elf, mode: SP1ProofMode) -> Result<Option<NetworkProofContext>> {
    if env::var("SP1_PROVER").ok().as_deref() == Some("network") {
        Ok(Some(NetworkProofContext::new(elf, mode)?))
    } else {
        Ok(None)
    }
}

fn network_proof_caps(client: &NetworkProver, mode: SP1ProofMode) -> Result<NetworkProofCaps> {
    let caps = NetworkProofCaps {
        max_base_fee: required_base_fee_cap(&mode)?,
        max_price_per_pgu: required_u64_env("SP1_NETWORK_MAX_PRICE_PER_PGU_PROVE_WEI")?,
    };
    let GetProofRequestParamsResponse::Auction(params) = client
        .get_proof_request_params(mode)
        .context("read live SP1 auction parameters")?
    else {
        bail!("SP1 network did not return auction parameters");
    };
    let base_fee = parse_network_u64("base fee", &params.base_fee)?;
    let max_price_per_pgu = parse_network_u64("maximum price per PGU", &params.max_price_per_pgu)?;
    ensure!(
        base_fee <= caps.max_base_fee,
        "live SP1 base fee {} exceeds approved cap {}",
        base_fee,
        caps.max_base_fee
    );
    ensure!(
        max_price_per_pgu <= caps.max_price_per_pgu,
        "live SP1 max price per PGU {} exceeds approved cap {}",
        max_price_per_pgu,
        caps.max_price_per_pgu
    );
    let balance = client.get_balance().context("read SP1 network balance")?;
    ensure!(
        balance >= U256::from(base_fee),
        "SP1 balance {} is below the live base fee {}",
        balance,
        base_fee
    );
    Ok(caps)
}

fn parse_network_u64(label: &str, value: &str) -> Result<u64> {
    value
        .parse()
        .with_context(|| format!("SP1 network returned an invalid {label}"))
}

fn required_base_fee_cap(mode: &SP1ProofMode) -> Result<u64> {
    match mode {
        SP1ProofMode::Compressed => {
            required_u64_env("SP1_NETWORK_MAX_COMPRESSED_BASE_FEE_PROVE_WEI")
        }
        SP1ProofMode::Groth16 => required_u64_env("SP1_NETWORK_MAX_GROTH16_BASE_FEE_PROVE_WEI"),
        _ => bail!("unsupported SP1 network proof mode for checkpoint proving"),
    }
}

fn required_u64_env(name: &str) -> Result<u64> {
    env::var(name)
        .with_context(|| format!("{name} is required for SP1 network proving"))?
        .parse()
        .with_context(|| format!("{name} must be an unsigned decimal integer"))
}

fn ensure_production_prover() -> Result<()> {
    ensure!(
        !matches!(
            env::var("SP1_PROVER").ok().as_deref(),
            Some("mock" | "light")
        ),
        "production proving requires SP1_PROVER=cpu, cuda, or network"
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
        aggregate.proof_mode == "sp1-groth16",
        "state plans require a production SP1 Groth16 accumulator proof"
    );
    ensure!(
        file_sha256(&artifact_dir.join(&aggregate.journal_file))? == aggregate.journal_sha256,
        "accumulator journal digest mismatch"
    );
    ensure!(
        file_sha256(&artifact_dir.join(&aggregate.proof_file))? == aggregate.proof_sha256,
        "accumulator proof digest mismatch"
    );
    ensure!(
        file_sha256(&artifact_dir.join(&aggregate.proof_bytes_file))?
            == aggregate.proof_bytes_sha256,
        "accumulator proof bytes digest mismatch"
    );
    let journal_data = fs::read(artifact_dir.join(&aggregate.journal_file))?;
    let proof = SP1ProofWithPublicValues::load(artifact_dir.join(&aggregate.proof_file))?;
    let proof_bytes = fs::read(artifact_dir.join(&aggregate.proof_bytes_file))?;
    let journal_digest = B256::from_slice(&Sha256::digest(&journal_data));
    let client = ProverClient::from_env();
    let epoch_key = client.setup(EPOCH_GUEST_ELF.clone())?;
    let accumulator_key = client.setup(ACCUMULATOR_GUEST_ELF.clone())?;
    client.verify(&proof, accumulator_key.verifying_key(), None)?;
    ensure!(
        matches!(&proof.proof, SP1Proof::Groth16(_)),
        "accumulator proof is not Groth16"
    );
    ensure!(
        proof.public_values.as_slice() == journal_data,
        "accumulator proof public values mismatch"
    );
    ensure!(
        proof.bytes() == proof_bytes,
        "accumulator proof bytes do not match proof"
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
        epoch_recursion_vkey: epoch_key.verifying_key().hash_u32(),
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
            proofBytes: proof_bytes.into(),
            publicValues: journal_data.into(),
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
        manifest.version == 3 && manifest.kind == "antseed-sp1-history-accumulator-artifacts",
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
    let (epoch_recursion_vkey, accumulator_program_vkey) = program_vkeys()?;
    ensure!(
        manifest.epoch_recursion_vkey == epoch_recursion_vkey,
        "epoch recursion vkey mismatch"
    );
    ensure!(
        manifest.accumulator_program_vkey == accumulator_program_vkey,
        "accumulator program vkey mismatch"
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
                && artifact.proof_file == format!("epoch-{index:04}.proof.bin"),
            "accumulator epoch filenames are invalid"
        );
    }
    if let Some(aggregate) = &manifest.accumulator {
        ensure!(
            aggregate.journal_file == "accumulator.journal.bin"
                && aggregate.proof_file == "accumulator.proof.bin"
                && aggregate.proof_bytes_file == "accumulator.proof-bytes.bin",
            "accumulator artifact filenames are invalid"
        );
        ensure!(
            aggregate.proof_mode == "sp1-groth16",
            "invalid accumulator proof mode"
        );
        ensure!(aggregate.status == "proven", "invalid accumulator status");
        for digest in [
            &aggregate.journal_sha256,
            &aggregate.proof_sha256,
            &aggregate.proof_bytes_sha256,
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

fn program_vkeys() -> Result<(B256, B256)> {
    let client = ProverClient::builder().cpu().build();
    let epoch_key = client.setup(EPOCH_GUEST_ELF.clone())?;
    let accumulator_key = client.setup(ACCUMULATOR_GUEST_ELF.clone())?;
    Ok((
        B256::from(epoch_key.verifying_key().hash_bytes()),
        B256::from(accumulator_key.verifying_key().bytes32_raw()),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_preserves_vkey_acronyms() {
        let manifest = Manifest {
            version: 3,
            kind: "antseed-sp1-history-accumulator-artifacts".into(),
            chain_id: 8_453,
            start_block: HISTORICAL_START_BLOCK,
            anchor_block: HISTORICAL_START_BLOCK,
            epoch_count: 0,
            epoch_recursion_vkey: B256::ZERO,
            accumulator_program_vkey: B256::ZERO,
            epochs: Vec::new(),
            accumulator: None,
        };
        let value = serde_json::to_value(manifest).unwrap();
        assert!(value.get("epochRecursionVKey").is_some());
        assert!(value.get("accumulatorProgramVKey").is_some());
        assert!(value.get("epochRecursionVkey").is_none());
        assert!(value.get("accumulatorProgramVkey").is_none());
    }
}
