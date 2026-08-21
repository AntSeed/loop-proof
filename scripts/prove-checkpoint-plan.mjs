#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { approveCostQuote } from "./proving-cost-quote.mjs";

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const planPath = value("--plan");
const artifactDir = resolve(value("--artifact-dir") ?? "checkpoint-proof-artifacts");
const l1RpcUrl = value("--l1-rpc-url") ?? process.env.L1_RPC_URL;
const baseRpcUrl = value("--base-rpc-url") ?? process.env.BASE_RPC_URL;
const beaconApiUrl = value("--beacon-api-url") ?? process.env.BEACON_API_URL ?? "https://ethereum-beacon-api.publicnode.com";
const costQuotePath = value("--cost-quote");
const approvedCostDigest = value("--approve-cost-digest");
if (!planPath || !l1RpcUrl || !baseRpcUrl || !costQuotePath || !approvedCostDigest || !args.includes("--confirm-production-proving")) {
  throw new Error("usage: prove-checkpoint-plan.mjs --plan checkpoint-plan.json --artifact-dir DIR --l1-rpc-url URL --base-rpc-url URL --cost-quote quote.json --approve-cost-digest 0x... --confirm-production-proving");
}
if (process.env.RISC0_DEV_MODE === "1") throw new Error("production checkpoint batch refuses RISC0_DEV_MODE=1");

const planBytes = await readFile(planPath);
const plan = JSON.parse(planBytes);
validatePlan(plan);
approveCostQuote(JSON.parse(await readFile(costQuotePath, "utf8")), approvedCostDigest, { checkpointProofs: plan.proofs.length });
await mkdir(artifactDir, { recursive: true });
const manifestPath = join(artifactDir, "manifest.json");
const manifest = await loadManifest(manifestPath, plan, sha256(planBytes));
const checkpointDir = resolve(dirname(fileURLToPath(import.meta.url)), "../checkpoint");

for (const [index, proof] of plan.proofs.entries()) {
  const stem = `checkpoint-${String(index).padStart(3, "0")}-${proof.checkpoint_block_number}`;
  const journalFile = `${stem}.journal.hex`;
  const sealFile = `${stem}.seal.hex`;
  const existing = manifest.proofs[index];
  if (existing?.status === "proven" && await artifactMatches(artifactDir, existing)) {
    console.log(`[${index + 1}/${plan.proofs.length}] ${proof.checkpoint_block_number} already proven`);
    continue;
  }
  console.log(`[${index + 1}/${plan.proofs.length}] proving checkpoint ${proof.checkpoint_block_number}`);
  await run("cargo", [
    "run", "--release", "-p", "checkpoint-host", "--",
    "--l1-rpc-url", l1RpcUrl,
    "--base-rpc-url", baseRpcUrl,
    "--beacon-api-url", beaconApiUrl,
    "--l1-block-number", String(plan.ethereum_finalized_block_number),
    "--expected-l1-block-hash", plan.ethereum_finalized_block_hash,
    "--game", proof.game,
    "--intermediate-root-index", String(proof.intermediate_root_index),
    "--target-blocks", proof.target_blocks.join(","),
    "--prove",
    "--journal-out", join(artifactDir, journalFile),
    "--seal-out", join(artifactDir, sealFile),
  ], checkpointDir);
  const journalBytes = await readFile(join(artifactDir, journalFile));
  const sealBytes = await readFile(join(artifactDir, sealFile));
  manifest.proofs[index] = {
    index,
    game: proof.game,
    intermediateRootIndex: proof.intermediate_root_index,
    checkpointBlockNumber: proof.checkpoint_block_number,
    targetBlocks: proof.target_blocks,
    journalFile,
    sealFile,
    journalSha256: sha256(journalBytes),
    sealSha256: sha256(sealBytes),
    status: "proven",
  };
  await writeJsonAtomic(manifestPath, manifest);
}
console.log(`checkpoint proof manifest written: ${manifestPath}`);

function validatePlan(valueToValidate) {
  if (valueToValidate?.version !== 1 || valueToValidate.chain_id !== 8_453 || !Array.isArray(valueToValidate.proofs) || valueToValidate.proofs.length === 0) throw new Error("unsupported checkpoint plan");
  if (!Number.isSafeInteger(valueToValidate.ethereum_finalized_block_number) || !/^0x[0-9a-f]{64}$/i.test(valueToValidate.ethereum_finalized_block_hash)) throw new Error("checkpoint plan has no fixed finalized Ethereum block");
}

async function loadManifest(path, checkpointPlan, planSha256) {
  try {
    const existing = JSON.parse(await readFile(path, "utf8"));
    if (existing.version !== 1 || existing.kind !== "antseed-checkpoint-proof-artifacts" || existing.planSha256 !== planSha256) throw new Error("checkpoint artifact manifest does not match the plan");
    return existing;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return {
      version: 1,
      kind: "antseed-checkpoint-proof-artifacts",
      chainId: checkpointPlan.chain_id,
      planSha256,
      ethereumFinalizedBlockNumber: checkpointPlan.ethereum_finalized_block_number,
      ethereumFinalizedBlockHash: checkpointPlan.ethereum_finalized_block_hash,
      proofs: new Array(checkpointPlan.proofs.length).fill(null),
    };
  }
}

async function artifactMatches(directory, artifact) {
  try {
    return sha256(await readFile(join(directory, artifact.journalFile))) === artifact.journalSha256
      && sha256(await readFile(join(directory, artifact.sealFile))) === artifact.sealSha256;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function run(command, commandArgs, cwd) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, { cwd, stdio: "inherit", env: process.env });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${code}`)));
  });
}

function sha256(bytes) {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

async function writeJsonAtomic(path, valueToWrite) {
  const temp = `${path}.tmp`;
  await writeFile(temp, `${JSON.stringify(valueToWrite, null, 2)}\n`);
  await rename(temp, path);
}
