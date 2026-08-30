#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { approveCostQuote } from "./proving-cost-quote.mjs";

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const required = ["--plan", "--manifest", "--artifact-dir", "--closed-loop-elf", "--reciprocal-elf", "--aggregator-elf", "--cost-quote", "--approve-cost-digest"];
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
  { p0Claims: plan.claims.length, aggregates: 1 },
);
await mkdir(artifactDir, { recursive: true });

for (const [index, claim] of plan.claims.entries()) {
  const stem = `${String(index).padStart(3, "0")}-${claim.claimId.slice(2, 18)}`;
  const witnessPath = join(artifactDir, `${stem}.witness.json`);
  const reciprocal = claim.type === "P0_RECIPROCAL";
  console.error(`[${index + 1}/${plan.claims.length}] materializing ${claim.claimId}`);
  await run("cargo", [
    "run", "--release", "-p", "loop-host", "--bin", "wash-trading-materialize-p0", "--",
    "--plan", planPath, "--claim-id", claim.claimId, "--output", witnessPath,
  ]);
  claim.witnessPath = witnessPath;
  claim.aggregateKind = reciprocal ? "reciprocal" : "closed-loop";
}

const aggregatePath = join(artifactDir, "aggregate-proof.json");
const aggregateArgs = [
  "run", "--release", "-p", "loop-host", "--features", "sp1", "--bin", "wash-trading-aggregate", "--",
  "--aggregator-elf", resolve(value("--aggregator-elf")),
  "--closed-loop-elf", resolve(value("--closed-loop-elf")),
  "--reciprocal-elf", resolve(value("--reciprocal-elf")),
  "--manifest", resolve(value("--manifest")),
  "--output", aggregatePath,
];
for (const claim of plan.claims) aggregateArgs.push("--child", `${claim.aggregateKind}:${claim.witnessPath}`);
await run("cargo", aggregateArgs);
const aggregate = JSON.parse(await readFile(aggregatePath, "utf8"));
if (aggregate?.kind !== "antseed-wash-trading-aggregate-proof" || aggregate.childCount !== plan.claims.length) {
  throw new Error("aggregate proof identity mismatch");
}
console.log(JSON.stringify({
  aggregate: aggregatePath,
  childCount: aggregate.childCount,
  sourceClaimCount: aggregate.sourceClaimCount,
  sellerCount: aggregate.sellerCount,
  aggregateSha256: sha256(await readFile(aggregatePath)),
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
