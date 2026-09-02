use alloy_primitives::{hex, B256};
use anyhow::{bail, Context, Result};
#[path = "../proving.rs"]
mod proving;
use proving::ProofClient;
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Stdin};
use std::{env, fs, path::Path};
use wash_predicate::aggregate::{vkey_bytes32, CLOSED_LOOP_PROGRAM_ID, RECIPROCAL_PROGRAM_ID};
use wash_predicate::{
    verify_closed_loop, verify_reciprocal, ClosedLoopInput, ReciprocalInput, WashJournal,
};

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let index: usize = required(&args, "--index")?
        .parse()
        .context("invalid --index")?;
    let kind = required(&args, "--kind")?;
    let witness_path = required(&args, "--witness")?;
    let output_dir = required(&args, "--output-dir")?;
    let elf_path = match kind.as_str() {
        "closed-loop" => required(&args, "--closed-loop-elf")?,
        "reciprocal" => required(&args, "--reciprocal-elf")?,
        _ => bail!("unsupported child kind {kind}"),
    };
    let development = args.iter().any(|value| value == "--development");
    let client = ProofClient::from_args(development, &args)?;

    let witness = fs::read(&witness_path).with_context(|| format!("read {witness_path}"))?;
    let (program_id, public_values) = match kind.as_str() {
        "closed-loop" => {
            let input: ClosedLoopInput = serde_json::from_slice(&witness)?;
            let journal = verify_closed_loop(&input).map_err(anyhow::Error::msg)?;
            (CLOSED_LOOP_PROGRAM_ID, journal.abi_encode())
        }
        "reciprocal" => {
            let input: ReciprocalInput = serde_json::from_slice(&witness)?;
            let journal = verify_reciprocal(&input).map_err(anyhow::Error::msg)?;
            (RECIPROCAL_PROGRAM_ID, journal.abi_encode())
        }
        _ => unreachable!(),
    };
    let journal = WashJournal::abi_decode(&public_values).map_err(anyhow::Error::msg)?;
    let source_claim_id = journal.source_claim_id;

    let key = client.setup(Elf::Dynamic(fs::read(&elf_path)?.into()))?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);
    eprintln!("proving {kind} child {source_claim_id}");
    let proof = client.prove_compressed(&key, stdin)?;
    client.verify(&proof, &key)?;
    if proof.public_values.as_slice() != public_values {
        bail!("{kind} child public values differ from native execution");
    }
    let vkey_digest = key.verifying_key().hash_u32();
    let program_vkey: B256 = key.verifying_key().bytes32().parse()?;
    if vkey_bytes32(vkey_digest) != program_vkey {
        bail!("SP1 vkey encodings disagree");
    }

    fs::create_dir_all(&output_dir)?;
    let proof_path = Path::new(&output_dir).join(format!("{index:03}-{source_claim_id}.proof.bin"));
    proof.save(&proof_path)?;
    let artifact = serde_json::json!({
        "version": 2,
        "kind": "antseed-wash-trading-child-proof",
        "securityMode": client.security_mode(),
        "childKind": kind,
        "sourceClaimId": format!("{source_claim_id}"),
        "programId": format!("{program_id}"),
        "programVKey": format!("{program_vkey}"),
        "publicValues": format!("0x{}", hex::encode(&public_values)),
        "proofPath": proof_path,
        "verified": true,
    });
    fs::write(
        proof_path.with_extension("json"),
        serde_json::to_vec_pretty(&artifact)?,
    )?;
    println!("{}", proof_path.display());
    Ok(())
}

fn required(args: &[String], flag: &str) -> Result<String> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
        .with_context(|| format!("missing {flag}"))
}
