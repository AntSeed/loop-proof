use alloy_primitives::{hex, Address, B256};
use anyhow::{bail, Context, Result};
use enforcement_core::{
    CohortInput, EvidenceLocation, LogRef, MembershipProof, ReciprocalInput, SelectedEvidence,
    TransactionRef,
};
use loop_host::rpc::Client;
use risc0_zkvm::sha::Digest as Risc0Digest;
use risc0_zkvm::sha::Digestible;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofPlan {
    version: u32,
    chain_id: u64,
    report_root: B256,
    claims: Vec<ClaimPlan>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimPlan {
    claim_id: B256,
    r#type: String,
    subjects: Vec<Address>,
    #[serde(rename = "dependencyRoot")]
    _dependency_root: B256,
    claim_leaf: String,
    claim_membership: MembershipProof,
    selected_evidence: Vec<PlannedEvidence>,
    selected_blocks: Vec<u64>,
    checkpoint_windows: Vec<serde_json::Value>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannedEvidence {
    dependency_id: B256,
    evidence_type: String,
    block_number: Option<u64>,
    transaction_index: Option<u64>,
    log_index: Option<u64>,
    receipt_log_index: Option<usize>,
    deposit_log_index: Option<u64>,
    deposit_receipt_log_index: Option<usize>,
    dependency_leaf: String,
    dependency_membership: MembershipProof,
    seller_payment: Option<PlannedLocator>,
    relay_forward: Option<PlannedLocator>,
    funder_receipt: Option<PlannedLocator>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannedLocator {
    block_number: u64,
    transaction_index: u64,
    log_index: u64,
    receipt_log_index: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofResults {
    version: u32,
    kind: &'static str,
    chain_id: u64,
    report_root: B256,
    security_mode: String,
    entries: Vec<ProofResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofResult {
    claim_id: B256,
    claim_type: String,
    subjects: Vec<Address>,
    image_id: String,
    journal_bytes: String,
    journal_digest: B256,
    seal: Option<String>,
    user_cycles: Option<u64>,
    total_cycles: Option<u64>,
    selected_evidence: Vec<PlannedEvidence>,
    selected_blocks: Vec<u64>,
    checkpoint_windows: Vec<serde_json::Value>,
}

type GuestExecution = (Vec<u8>, String, Option<String>, Option<u64>, Option<u64>);

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args = std::env::args().collect::<Vec<_>>();
    let plan_path = arg(&args, "--plan").context("--plan required")?;
    let out_path = arg(&args, "--out").context("--out required")?;
    let prove = args.iter().any(|value| value == "--prove");
    let endpoints = arg(&args, "--rpc-url")
        .or_else(|| std::env::var("ANTSEED_BASE_RPC_URL").ok())
        .or_else(|| std::env::var("BASE_RPC_URL").ok())
        .map(|value| vec![value])
        .context("--rpc-url or ANTSEED_BASE_RPC_URL required")?;
    let plan: ProofPlan = serde_json::from_slice(&std::fs::read(plan_path)?)?;
    if plan.version != 1 || plan.chain_id != 8_453 {
        bail!("unsupported proof plan");
    }
    let client = Client::new(endpoints);
    let dev_mode = std::env::var("RISC0_DEV_MODE").unwrap_or_default() == "1";
    let security_mode = if prove && dev_mode {
        "development"
    } else if prove {
        "production"
    } else {
        "execute-only"
    };
    let mut entries = Vec::new();
    let claim_count = plan.claims.len();
    for (index, claim) in plan.claims.into_iter().enumerate() {
        eprintln!(
            "[{}/{}] building {} {}",
            index + 1,
            claim_count,
            claim.r#type,
            claim.claim_id
        );
        entries.push(prove_claim(
            &client,
            plan.chain_id,
            plan.report_root,
            claim,
            prove,
        )?);
    }
    let results = ProofResults {
        version: 1,
        kind: "antseed-wash-trading-proof-results",
        chain_id: plan.chain_id,
        report_root: plan.report_root,
        security_mode: security_mode.to_owned(),
        entries,
    };
    std::fs::write(&out_path, serde_json::to_vec_pretty(&results)?)?;
    println!(
        "wrote {} proof results to {out_path}",
        results.entries.len()
    );
    Ok(())
}

fn prove_claim(
    client: &Client,
    chain_id: u64,
    report_root: B256,
    claim: ClaimPlan,
    prove: bool,
) -> Result<ProofResult> {
    if !matches!(
        claim.r#type.as_str(),
        "P0_CLOSED_LOOP" | "P1_COORDINATED_CONTROL" | "P0_RECIPROCAL"
    ) {
        bail!("unsupported proof-plan claim type {}", claim.r#type);
    }
    let mut receipt_targets = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut transaction_targets = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut log_indices = BTreeMap::<u64, BTreeSet<u64>>::new();
    for evidence in &claim.selected_evidence {
        if evidence.evidence_type == "RELAY_PATH" {
            for locator in relay_locators(evidence)? {
                receipt_targets
                    .entry(locator.block_number)
                    .or_default()
                    .insert(locator.transaction_index);
                transaction_targets
                    .entry(locator.block_number)
                    .or_default()
                    .insert(locator.transaction_index);
                log_indices
                    .entry(locator.block_number)
                    .or_default()
                    .insert(locator.log_index);
            }
            continue;
        }
        let block_number = evidence
            .block_number
            .context("atomic evidence lacks blockNumber")?;
        let transaction_index = evidence
            .transaction_index
            .context("atomic evidence lacks transactionIndex")?;
        if evidence.evidence_type == "NATIVE_FUNDING" {
            transaction_targets
                .entry(block_number)
                .or_default()
                .insert(transaction_index);
        } else {
            receipt_targets
                .entry(block_number)
                .or_default()
                .insert(transaction_index);
            transaction_targets
                .entry(block_number)
                .or_default()
                .insert(transaction_index);
            log_indices
                .entry(block_number)
                .or_default()
                .insert(evidence.log_index.context("log evidence lacks logIndex")?);
            if let Some(deposit_log_index) = evidence.deposit_log_index {
                log_indices
                    .entry(block_number)
                    .or_default()
                    .insert(deposit_log_index);
            }
        }
    }
    let block_numbers = receipt_targets
        .keys()
        .chain(transaction_targets.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut blocks = Vec::new();
    let mut block_position = BTreeMap::new();
    let mut receipt_position = BTreeMap::new();
    let mut transaction_position = BTreeMap::new();
    for number in block_numbers {
        let receipts = receipt_targets
            .get(&number)
            .map(set_values)
            .unwrap_or_default();
        let transactions = transaction_targets
            .get(&number)
            .map(set_values)
            .unwrap_or_default();
        let logs = log_indices.get(&number).map(set_values).unwrap_or_default();
        let (block, _) =
            client.enforcement_block_evidence(number, &receipts, &transactions, &logs)?;
        let position = blocks.len();
        for (index, receipt) in block.receipts.iter().enumerate() {
            receipt_position.insert((number, receipt.tx_index), index);
        }
        for (index, transaction) in block.transactions.iter().enumerate() {
            transaction_position.insert((number, transaction.tx_index), index);
        }
        block_position.insert(number, position);
        blocks.push(block);
    }
    let evidence = claim
        .selected_evidence
        .iter()
        .map(|entry| {
            let location = if entry.evidence_type == "RELAY_PATH" {
                let locators = relay_locators(entry)?;
                EvidenceLocation::RelayPath {
                    seller_payment: log_ref(&locators[0], &block_position, &receipt_position),
                    relay_forward: log_ref(&locators[1], &block_position, &receipt_position),
                    funder_receipt: log_ref(&locators[2], &block_position, &receipt_position),
                }
            } else if entry.evidence_type == "NATIVE_FUNDING" {
                let block_number = entry
                    .block_number
                    .context("native evidence lacks blockNumber")?;
                let transaction_index = entry
                    .transaction_index
                    .context("native evidence lacks transactionIndex")?;
                EvidenceLocation::NativeTransaction(TransactionRef {
                    block: block_position[&block_number],
                    transaction: transaction_position[&(block_number, transaction_index)],
                })
            } else {
                let block_number = entry
                    .block_number
                    .context("log evidence lacks blockNumber")?;
                let transaction_index = entry
                    .transaction_index
                    .context("log evidence lacks transactionIndex")?;
                let transfer = LogRef {
                    block: block_position[&block_number],
                    receipt: receipt_position[&(block_number, transaction_index)],
                    log: entry
                        .receipt_log_index
                        .context("log evidence lacks receiptLogIndex")?,
                };
                if let Some(deposit_log) = entry.deposit_receipt_log_index {
                    EvidenceLocation::UsdcDeposit {
                        transfer,
                        deposited: LogRef {
                            log: deposit_log,
                            ..transfer
                        },
                    }
                } else {
                    EvidenceLocation::Log(transfer)
                }
            };
            Ok(SelectedEvidence {
                dependency_leaf: entry.dependency_leaf.as_bytes().to_vec().into(),
                dependency_membership: entry.dependency_membership.clone(),
                location,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let (journal_bytes, image_id, seal, user_cycles, total_cycles) =
        if claim.r#type == "P0_RECIPROCAL" {
            let input = ReciprocalInput {
                chain_id,
                channels: enforcement_core::CHANNELS_ADDRESS,
                report_root,
                claim_leaf: claim.claim_leaf.as_bytes().to_vec().into(),
                claim_membership: claim.claim_membership.clone(),
                blocks,
                evidence,
            };
            let native = enforcement_core::verify_reciprocal(&input).map_err(anyhow::Error::msg)?;
            if native.claim_id != claim.claim_id
                || claim.subjects.as_slice() != [native.seller_a, native.seller_b]
            {
                bail!("reciprocal journal identity differs from proof plan");
            }
            execute_or_prove(
                &input,
                native.abi_encode(),
                reciprocal_methods::RECIPROCAL_GUEST_ELF,
                reciprocal_methods::RECIPROCAL_GUEST_ID,
                prove,
            )?
        } else {
            let input = CohortInput {
                chain_id,
                usdc: enforcement_core::USDC_ADDRESS,
                channels: enforcement_core::CHANNELS_ADDRESS,
                deposits: enforcement_core::DEPOSITS_ADDRESS,
                report_root,
                claim_leaf: claim.claim_leaf.as_bytes().to_vec().into(),
                claim_membership: claim.claim_membership.clone(),
                blocks,
                evidence,
            };
            let native = enforcement_core::verify_cohort(&input).map_err(anyhow::Error::msg)?;
            let expected_claim_type = match claim.r#type.as_str() {
                "P0_CLOSED_LOOP" => 1,
                "P1_COORDINATED_CONTROL" => 2,
                _ => unreachable!(),
            };
            if native.claim_id != claim.claim_id
                || native.claim_type != expected_claim_type
                || claim.subjects.as_slice() != [native.seller]
            {
                bail!("cohort journal identity differs from proof plan");
            }
            execute_or_prove(
                &input,
                native.abi_encode(),
                cohort_methods::COHORT_GUEST_ELF,
                cohort_methods::COHORT_GUEST_ID,
                prove,
            )?
        };
    let journal_digest = B256::from_slice(&Sha256::digest(&journal_bytes));
    Ok(ProofResult {
        claim_id: claim.claim_id,
        claim_type: claim.r#type,
        subjects: claim.subjects,
        image_id,
        journal_bytes: format!("0x{}", hex::encode(journal_bytes)),
        journal_digest,
        seal,
        user_cycles,
        total_cycles,
        selected_evidence: claim.selected_evidence,
        selected_blocks: claim.selected_blocks,
        checkpoint_windows: claim.checkpoint_windows,
    })
}

fn execute_or_prove<T: serde::Serialize>(
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
        Ok((
            info.receipt.journal.bytes,
            digest.to_string(),
            Some(format!("0x{}", hex::encode(seal))),
            Some(info.stats.user_cycles),
            Some(info.stats.total_cycles),
        ))
    } else {
        let session = risc0_zkvm::default_executor().execute(env, elf)?;
        if session.journal.bytes != expected_journal {
            bail!("guest journal differs from native journal");
        }
        Ok((session.journal.bytes, digest.to_string(), None, None, None))
    }
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|value| value == flag)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn set_values(values: &BTreeSet<u64>) -> Vec<u64> {
    values.iter().copied().collect()
}

fn relay_locators(evidence: &PlannedEvidence) -> Result<[PlannedLocator; 3]> {
    Ok([
        evidence
            .seller_payment
            .clone()
            .context("relay path lacks sellerPayment")?,
        evidence
            .relay_forward
            .clone()
            .context("relay path lacks relayForward")?,
        evidence
            .funder_receipt
            .clone()
            .context("relay path lacks funderReceipt")?,
    ])
}

fn log_ref(
    locator: &PlannedLocator,
    blocks: &BTreeMap<u64, usize>,
    receipts: &BTreeMap<(u64, u64), usize>,
) -> LogRef {
    LogRef {
        block: blocks[&locator.block_number],
        receipt: receipts[&(locator.block_number, locator.transaction_index)],
        log: locator.receipt_log_index,
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
