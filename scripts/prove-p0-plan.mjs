#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { approveCostQuote } from "./proving-cost-quote.mjs";

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const planPath = value("--plan");
const artifactDir = resolve(value("--artifact-dir") ?? "p0-proof-artifacts");
const costQuotePath = value("--cost-quote");
const approvedCostDigest = value("--approve-cost-digest");
if (!planPath || !costQuotePath || !approvedCostDigest || !args.includes("--confirm-production-proving")) throw new Error("usage: prove-p0-plan.mjs --plan proof-plan.json --artifact-dir DIR --cost-quote quote.json --approve-cost-digest 0x... --confirm-production-proving");
if (!process.env.BASE_RPC_URL) throw new Error("BASE_RPC_URL is required");
if (["mock", "light"].includes(process.env.SP1_PROVER ?? "cpu")) throw new Error("production P0 batch requires an SP1 proving backend");

const planBytes = await readFile(planPath);
const plan = JSON.parse(planBytes);
if (plan?.version !== 2 || plan?.kind !== "antseed-wash-trading-proof-plan" || plan.chainId !== 8_453 || !Array.isArray(plan.claims) || plan.claims.length !== 26) throw new Error("production proof plan must contain exactly 26 claims");
approveCostQuote(JSON.parse(await readFile(costQuotePath, "utf8")), approvedCostDigest, { p0Claims: plan.claims.length });
await mkdir(artifactDir, { recursive: true });
const manifestPath = join(artifactDir, "manifest.json");
const manifest = await loadManifest(manifestPath, plan, sha256(planBytes));

for (const [index, claim] of plan.claims.entries()) {
  const stem = `${String(index).padStart(2, "0")}-${claim.claimId.slice(2, 18)}`;
  const witnessFile = `${stem}.witness.json`;
  const resultFile = `${stem}.result.json`;
  const existing = manifest.claims[index];
  if (existing?.status === "proven" && await artifactMatches(artifactDir, existing)) {
    console.log(`[${index + 1}/${plan.claims.length}] ${claim.claimId} already proven`);
    continue;
  }
  console.log(`[${index + 1}/${plan.claims.length}] materializing ${claim.claimId}`);
  await run("cargo", [
    "run", "--release", "-p", "loop-host", "--bin", "wash-trading-materialize-p0", "--",
    "--plan", resolve(planPath), "--claim-id", claim.claimId, "--output", join(artifactDir, witnessFile),
  ]);
  console.log(`[${index + 1}/${plan.claims.length}] proving ${claim.claimId}`);
  await run("cargo", [
    "run", "--release", "-p", "loop-host", "--bin", "wash-trading-prove", "--",
    "--input", join(artifactDir, witnessFile), "--output", join(artifactDir, resultFile), "--prove", "--production",
  ]);
  const result = JSON.parse(await readFile(join(artifactDir, resultFile), "utf8"));
  if (result.securityMode !== "production" || result.entries?.length !== 1 || result.entries[0].claimId.toLowerCase() !== claim.claimId.toLowerCase()) throw new Error(`${claim.claimId}: production result identity mismatch`);
  manifest.claims[index] = {
    index,
    claimId: claim.claimId,
    claimType: claim.type,
    witnessFile,
    resultFile,
    witnessSha256: sha256(await readFile(join(artifactDir, witnessFile))),
    resultSha256: sha256(await readFile(join(artifactDir, resultFile))),
    journalDigest: result.entries[0].journalDigest,
    programVKey: result.entries[0].programVKey,
    status: "proven",
  };
  await writeJsonAtomic(manifestPath, manifest);
}

const results = await Promise.all(manifest.claims.map(async (claim) => JSON.parse(await readFile(join(artifactDir, claim.resultFile), "utf8"))));
const combined = {
  version: 2,
  kind: "antseed-wash-trading-proof-results",
  chainId: 8_453,
  securityMode: "production",
  entries: results.flatMap((result) => result.entries),
};
if (combined.entries.length !== plan.claims.length) throw new Error("combined proof result count mismatch");
await writeJsonAtomic(join(artifactDir, "proof-results.json"), combined);
console.log(`production proof results written: ${join(artifactDir, "proof-results.json")}`);

async function loadManifest(path, proofPlan, planSha256) {
  try {
    const existing = JSON.parse(await readFile(path, "utf8"));
    if (existing.version !== 2 || existing.kind !== "antseed-sp1-p0-proof-artifacts" || existing.planSha256 !== planSha256) throw new Error("P0 artifact manifest does not match the plan");
    return existing;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return { version: 2, kind: "antseed-sp1-p0-proof-artifacts", chainId: proofPlan.chainId, planSha256, claims: new Array(proofPlan.claims.length).fill(null) };
  }
}

async function artifactMatches(directory, artifact) {
  try {
    return sha256(await readFile(join(directory, artifact.witnessFile))) === artifact.witnessSha256
      && sha256(await readFile(join(directory, artifact.resultFile))) === artifact.resultSha256;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function run(command, commandArgs) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, { cwd: process.cwd(), stdio: "inherit", env: process.env });
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
