#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { approveCostQuote } from "./proving-cost-quote.mjs";

const BASE_BLOCKHASH_STORE = "0x78b69899C8cD252126cBB1A50171ec37286C3877";

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const required = ["--plan", "--artifact-dir", "--closed-loop-elf", "--reciprocal-elf", "--closed-loop-vkey", "--reciprocal-vkey", "--cost-quote", "--approve-cost-digest"];
for (const flag of required) if (!value(flag)) throw new Error(`missing ${flag}`);
if (!args.includes("--confirm-production-proving")) throw new Error("production proving requires --confirm-production-proving");
if (!process.env.BASE_RPC_URLS && !process.env.BASE_RPC_URL) throw new Error("BASE_RPC_URLS or BASE_RPC_URL is required");
if (["mock", "light"].includes(process.env.SP1_PROVER ?? "cpu")) throw new Error("production batch requires a real SP1 proving backend");

const planPath = resolve(value("--plan"));
const artifactDir = resolve(value("--artifact-dir"));
const plan = JSON.parse(await readFile(planPath, "utf8"));
if (plan?.version !== 2 || plan.kind !== "antseed-wash-trading-proof-plan" || plan.chainId !== 8_453
    || !Array.isArray(plan.claims) || plan.claims.length === 0 || plan.claimCount !== plan.claims.length) {
  throw new Error("production proof plan must contain the approved nonempty claim set");
}
const plannedIds = new Set(plan.claims.map((claim) => claim.claimId.toLowerCase()));
if (plannedIds.size !== plan.claims.length) throw new Error("proof plan contains duplicate claim IDs");
approveCostQuote(
  JSON.parse(await readFile(value("--cost-quote"), "utf8")),
  value("--approve-cost-digest"),
  { p0Claims: plan.claims.length },
);
await mkdir(artifactDir, { recursive: true });

for (const [index, claim] of plan.claims.entries()) {
  const stem = `${String(index).padStart(3, "0")}-${claim.claimId.slice(2, 18)}`;
  const witnessPath = join(artifactDir, `${stem}.witness.json`);
  const resultPath = join(artifactDir, `${stem}.result.json`);
  const reciprocal = claim.type === "P0_RECIPROCAL";
  const elf = resolve(reciprocal ? value("--reciprocal-elf") : value("--closed-loop-elf"));
  console.error(`[${index + 1}/${plan.claims.length}] materializing ${claim.claimId}`);
  await run("cargo", [
    "run", "--release", "-p", "loop-host", "--bin", "wash-trading-materialize-p0", "--",
    "--plan", planPath, "--claim-id", claim.claimId, "--output", witnessPath,
  ]);
  console.error(`[${index + 1}/${plan.claims.length}] proving ${claim.claimId}`);
  const runArgs = [
    "run", "--release", "-p", "loop-host", "--features", "sp1", "--", "run", witnessPath,
    "--prove", "--production", "--elf", elf, "--result", resultPath,
    "--source-claim-id", claim.claimId,
  ];
  if (reciprocal) runArgs.push("--reciprocal");
  await run("cargo", runArgs);
  const result = JSON.parse(await readFile(resultPath, "utf8"));
  if (result?.version !== 2 || result.kind !== "antseed-wash-trading-proof-result"
      || result.securityMode !== "production" || result.entry?.sourceClaimId?.toLowerCase() !== claim.claimId.toLowerCase()
      || result.entry.claimType !== claim.type || result.entry.proofBytes === "0x") {
    throw new Error(`${claim.claimId}: production result identity mismatch`);
  }
}

const manifestPath = join(artifactDir, "proof-results.json");
await run("cargo", [
  "run", "--release", "-p", "loop-host", "--", "batch-manifest",
  "--results-dir", artifactDir,
  "--blockhash-store", BASE_BLOCKHASH_STORE,
  "--closed-loop-vkey", value("--closed-loop-vkey"),
  "--reciprocal-vkey", value("--reciprocal-vkey"),
  "--out", manifestPath,
]);
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (manifest.entries.length !== plan.claims.length) throw new Error("combined proof result count mismatch");
console.log(JSON.stringify({
  manifest: manifestPath,
  expectedBatchCount: manifest.batch.expectedBatchCount,
  expectedBatchDigest: manifest.batch.expectedBatchDigest,
  manifestSha256: sha256(await readFile(manifestPath)),
}, null, 2));

function run(command, commandArgs) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, { cwd: process.cwd(), stdio: "inherit", env: process.env });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${code}`)));
  });
}
function sha256(bytes) { return `0x${createHash("sha256").update(bytes).digest("hex")}`; }

if (process.argv[1] && basename(process.argv[1]) === basename(new URL(import.meta.url).pathname)) {
  // Top-level execution above intentionally performs the production workflow.
}
