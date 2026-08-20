use alloy_primitives::{hex, B256};
use anyhow::{bail, Context, Result};
use risc0_zkvm::sha::{Digest as Risc0Digest, Digestible};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WitnessPackage {
    version: u32,
    kind: String,
    enforceable: bool,
    #[serde(flatten)]
    proof: ProofInput,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "proofType", content = "input")]
enum ProofInput {
    #[serde(rename = "P0_CLOSED_CYCLE")]
    ClosedCycle(enforcement_core::ClosedCycleInput),
    #[serde(rename = "P0_RECIPROCAL")]
    Reciprocal(enforcement_core::ReciprocalInput),
    #[serde(rename = "P1_COORDINATED_CONTROL")]
    CoordinatedControl(enforcement_core::CoordinatedControlInput),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofManifest {
    version: u32,
    kind: &'static str,
    chain_id: u64,
    security_mode: &'static str,
    entries: Vec<ProofEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofEntry {
    claim_id: B256,
    claim_type: &'static str,
    image_id: String,
    journal_bytes: String,
    journal_digest: B256,
    seal: Option<String>,
    user_cycles: Option<u64>,
    total_cycles: Option<u64>,
}

struct GuestExecution {
    journal: Vec<u8>,
    image_id: String,
    seal: Option<String>,
    user_cycles: Option<u64>,
    total_cycles: Option<u64>,
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args = env::args().skip(1).collect::<Vec<_>>();
    let input_path = arg(&args, "--input").context("missing --input <proof-witness-v2.json>")?;
    let output_path = arg(&args, "--output").context("missing --output <proof-result-v2.json>")?;
    let prove = args.iter().any(|value| value == "--prove");
    let production = args.iter().any(|value| value == "--production");
    if production && !prove {
        bail!("--production requires --prove");
    }
    if production && env::var("RISC0_DEV_MODE").ok().as_deref() != Some("0") {
        bail!("production proving requires RISC0_DEV_MODE=0");
    }

    let package: WitnessPackage = serde_json::from_slice(
        &fs::read(&input_path).with_context(|| format!("read {input_path}"))?,
    )
    .with_context(|| format!("decode {input_path}"))?;
    if package.version != enforcement_core::PREDICATE_VERSION
        || package.kind != "antseed-wash-trading-proof-witness"
    {
        bail!("expected a predicate-v2 self-contained witness package");
    }
    if !package.enforceable {
        bail!("analysis-only/router-attribution cases cannot be proven or submitted");
    }

    let entry = match package.proof {
        ProofInput::ClosedCycle(input) => {
            let journal =
                enforcement_core::verify_closed_cycle(&input).map_err(anyhow::Error::msg)?;
            let expected = journal.abi_encode();
            let execution = execute_or_prove(
                &input,
                expected,
                closed_cycle_methods::CLOSED_CYCLE_GUEST_ELF,
                closed_cycle_methods::CLOSED_CYCLE_GUEST_ID,
                prove,
            )?;
            entry(journal.claim_id, "P0_CLOSED_CYCLE", execution)
        }
        ProofInput::Reciprocal(input) => {
            let journal =
                enforcement_core::verify_reciprocal(&input).map_err(anyhow::Error::msg)?;
            let expected = journal.abi_encode();
            let execution = execute_or_prove(
                &input,
                expected,
                reciprocal_methods::RECIPROCAL_GUEST_ELF,
                reciprocal_methods::RECIPROCAL_GUEST_ID,
                prove,
            )?;
            entry(journal.claim_id, "P0_RECIPROCAL", execution)
        }
        ProofInput::CoordinatedControl(input) => {
            let journal =
                enforcement_core::verify_coordinated_control(&input).map_err(anyhow::Error::msg)?;
            let expected = journal.abi_encode();
            let execution = execute_or_prove(
                &input,
                expected,
                coordinated_control_methods::COORDINATED_CONTROL_GUEST_ELF,
                coordinated_control_methods::COORDINATED_CONTROL_GUEST_ID,
                prove,
            )?;
            entry(journal.claim_id, "P1_COORDINATED_CONTROL", execution)
        }
    };

    let manifest = ProofManifest {
        version: enforcement_core::PREDICATE_VERSION,
        kind: "antseed-wash-trading-proof-results",
        chain_id: enforcement_core::BASE_CHAIN_ID,
        security_mode: if production {
            "production"
        } else {
            "development"
        },
        entries: vec![entry],
    };
    let output_path = PathBuf::from(output_path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        output_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    Ok(())
}

fn entry(claim_id: B256, claim_type: &'static str, execution: GuestExecution) -> ProofEntry {
    let journal_digest = B256::from_slice(&Sha256::digest(&execution.journal));
    ProofEntry {
        claim_id,
        claim_type,
        image_id: execution.image_id,
        journal_bytes: format!("0x{}", hex::encode(execution.journal)),
        journal_digest,
        seal: execution.seal,
        user_cycles: execution.user_cycles,
        total_cycles: execution.total_cycles,
    }
}

fn execute_or_prove<T: Serialize>(
    input: &T,
    expected_journal: Vec<u8>,
    elf: &[u8],
    image_id: [u32; 8],
    prove: bool,
) -> Result<GuestExecution> {
    let env = risc0_zkvm::ExecutorEnv::builder().write(input)?.build()?;
    let digest = Risc0Digest::from(image_id);
    if prove {
        let info = risc0_zkvm::default_prover().prove(env, elf)?;
        info.receipt.verify(image_id)?;
        if info.receipt.journal.bytes != expected_journal {
            bail!("guest journal differs from native journal");
        }
        let seal = encode_seal(&info.receipt)?;
        Ok(GuestExecution {
            journal: info.receipt.journal.bytes,
            image_id: digest.to_string(),
            seal: Some(format!("0x{}", hex::encode(seal))),
            user_cycles: Some(info.stats.user_cycles),
            total_cycles: Some(info.stats.total_cycles),
        })
    } else {
        let session = risc0_zkvm::default_executor().execute(env, elf)?;
        if session.journal.bytes != expected_journal {
            bail!("guest journal differs from native journal");
        }
        Ok(GuestExecution {
            journal: session.journal.bytes,
            image_id: digest.to_string(),
            seal: None,
            user_cycles: None,
            total_cycles: None,
        })
    }
}

fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>> {
    let (selector, body): ([u8; 4], Vec<u8>) = match &receipt.inner {
        risc0_zkvm::InnerReceipt::Fake(fake) => {
            ([0xff; 4], fake.claim.digest().as_bytes().to_vec())
        }
        risc0_zkvm::InnerReceipt::Groth16(groth16) => (
            groth16.verifier_parameters.as_bytes()[..4]
                .try_into()
                .unwrap(),
            groth16.seal.to_vec(),
        ),
        _ => bail!("unsupported on-chain receipt type; use a Groth16 production prover"),
    };
    Ok([selector.to_vec(), body].concat())
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}
