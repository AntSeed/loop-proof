#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAggregateCalldataArtifact } from "./generate-aggregate-calldata.mjs";
import { historicalManifestFromBundle } from "./generate-historical-manifest.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function buildApprovedBatchSummary(bundle, plan) {
  validateApprovedSet(bundle, plan);
  const bundleClaims = new Map(bundle.claims.map((claim) => [claim.claimId.toLowerCase(), claim]));
  const uniqueSettlements = new Map();
  let closedLoopVolume = 0n;
  let reciprocalVolume = 0n;

  for (const planned of plan.claims) {
    const approved = bundleClaims.get(planned.claimId.toLowerCase());
    let selectedVolume = 0n;
    for (const evidence of planned.selectedEvidence) {
      if (!["SETTLEMENT", "RECIPROCAL_SETTLEMENT"].includes(evidence.evidenceType)) continue;
      const source = evidence.dependencyLeaf ? JSON.parse(evidence.dependencyLeaf) : evidence;
      const logIndex = evidence.receiptLogIndex ?? source.logIndex;
      if (!source.transactionHash || !Number.isSafeInteger(logIndex) || logIndex < 0) {
        throw new Error(`${planned.claimId}: settlement identity is incomplete`);
      }
      const amount = BigInt(source.amountRaw);
      const identity = `${source.transactionHash}:${logIndex}`.toLowerCase();
      const existing = uniqueSettlements.get(identity);
      if (existing != null && existing !== amount) {
        throw new Error(`${planned.claimId}: settlement ${identity} has conflicting amounts`);
      }
      uniqueSettlements.set(identity, amount);
      selectedVolume += amount;
    }
    const approvedVolume = approved.type === "P0_RECIPROCAL"
      ? BigInt(approved.metrics.volumeAToBRaw) + BigInt(approved.metrics.volumeBToARaw)
      : BigInt(approved.metrics.qualifiedVolumeRaw);
    if (selectedVolume !== approvedVolume) {
      throw new Error(`${planned.claimId}: selected volume ${selectedVolume} differs from approved volume ${approvedVolume}`);
    }
    if (approved.type === "P0_RECIPROCAL") reciprocalVolume += selectedVolume;
    else closedLoopVolume += selectedVolume;
  }

  const uniqueVolume = [...uniqueSettlements.values()].reduce((total, amount) => total + amount, 0n);
  return {
    reportRoot: bundle.reportRoot,
    period: bundle.period,
    approvedClaimCount: bundle.claims.length,
    approvedSellerCount: new Set(bundle.claims.flatMap((claim) => claim.subjects.map((subject) => subject.toLowerCase()))).size,
    closedLoopVolumeRaw: closedLoopVolume.toString(),
    reciprocalVolumeRaw: reciprocalVolume.toString(),
    uniqueSuspectedVolumeRaw: uniqueVolume.toString(),
    uniqueSettlementCount: uniqueSettlements.size,
  };
}

export function validateApprovedSet(bundle, plan) {
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle" || !Array.isArray(bundle.claims)) {
    throw new Error("invalid approved proof bundle");
  }
  if (plan?.version !== 2 || plan.kind !== "antseed-wash-trading-proof-plan" || !Array.isArray(plan.claims)) {
    throw new Error("invalid approved proof plan");
  }
  if (bundle.chainId !== 8_453 || plan.chainId !== bundle.chainId || plan.reportRoot !== bundle.reportRoot) {
    throw new Error("bundle and plan identity mismatch");
  }
  if (plan.claimCount !== plan.claims.length || plan.claims.length !== bundle.claims.length) {
    throw new Error(`partial proof plan: expected ${bundle.claims.length} claims, received ${plan.claims.length}`);
  }
  const approvedIds = bundle.claims.map((claim) => claim.claimId.toLowerCase()).sort();
  const plannedIds = plan.claims.map((claim) => claim.claimId.toLowerCase()).sort();
  if (new Set(approvedIds).size !== approvedIds.length || new Set(plannedIds).size !== plannedIds.length) {
    throw new Error("bundle or plan contains duplicate claim IDs");
  }
  if (approvedIds.some((claimId, index) => claimId !== plannedIds[index])) {
    throw new Error("proof plan does not contain the complete approved claim set");
  }
  if (JSON.stringify(plan.period) !== JSON.stringify(bundle.period)) {
    throw new Error("bundle and plan periods differ");
  }
}

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const index = args.indexOf(flag);
    return index < 0 ? null : args[index + 1];
  };
  const bundlePath = resolve(required(value("--bundle"), "--bundle"));
  const planPath = resolve(required(value("--plan"), "--plan"));
  const artifactDir = resolve(value("--artifact-dir") ?? "out/approved-development-proofs");
  const summaryPath = resolve(value("--summary") ?? join(artifactDir, "summary.json"));
  const toolchain = process.env.RUSTUP_TOOLCHAIN ?? "1.94";
  const skipGuestBuild = args.includes("--skip-guest-build");
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  const approved = buildApprovedBatchSummary(bundle, plan);
  const manifestPath = join(artifactDir, "historical-manifest.json");

  await mkdir(artifactDir, { recursive: true });
  const witnessEntries = plan.claims.map((claim, index) => ({
    claim,
    witnessPath: join(artifactDir, `${String(index).padStart(3, "0")}-${claim.claimId.slice(2, 18)}.witness.json`),
  }));
  const missingWitnesses = [];
  for (const entry of witnessEntries) {
    if (!await isCurrentWitness(entry.witnessPath, plan.period, entry.claim)) missingWitnesses.push(entry);
  }
  if (missingWitnesses.length > 0) {
    const endpoints = (process.env.BASE_RPC_URLS ?? process.env.BASE_RPC_URL ?? "")
      .split(",")
      .map((endpoint) => endpoint.trim())
      .filter(Boolean);
    if (endpoints.length === 0) {
      throw new Error("BASE_RPC_URLS or BASE_RPC_URL is required to materialize canonical witnesses");
    }
  }

  const materializer = resolve(root, "target/release/wash-trading-materialize-p0");
  await run("cargo", [
    "build", "--release", "-p", "loop-host",
    "--bin", "wash-trading-materialize-p0",
  ], root, { RUSTUP_TOOLCHAIN: toolchain });

  const children = [];
  for (const [index, { claim, witnessPath }] of witnessEntries.entries()) {
    if (!await isCurrentWitness(witnessPath, plan.period, claim)) {
      console.error(`[${index + 1}/${plan.claims.length}] materializing ${claim.claimId}`);
      await run(materializer, ["--plan", planPath, "--claim-id", claim.claimId, "--output", witnessPath], root, {
        LOOP_RPC_CONCURRENCY: process.env.LOOP_RPC_CONCURRENCY ?? "1",
      });
    } else {
      console.error(`[${index + 1}/${plan.claims.length}] reusing ${basename(witnessPath)}`);
    }
    children.push(`${claim.type === "P0_RECIPROCAL" ? "reciprocal" : "closed-loop"}:${witnessPath}`);
  }
  if (children.length !== approved.approvedClaimCount) throw new Error("not every approved claim has a witness");

  for (const guest of ["closed-loop", "reciprocal", "aggregator"]) {
    if (!skipGuestBuild) {
      await run("cargo", ["prove", "build"], resolve(root, "program", guest), { RUSTUP_TOOLCHAIN: "succinct" });
    } else {
      await stat(guestElf(guest));
    }
  }
  await writeFile(manifestPath, `${JSON.stringify(historicalManifestFromBundle(bundle), null, 2)}\n`);

  const aggregatePath = join(artifactDir, "aggregate-proof.json");
  const aggregateArgs = [
    "run", "--release", "-p", "loop-host", "--features", "sp1", "--bin", "wash-trading-aggregate", "--",
    "--development",
    "--aggregator-elf", guestElf("aggregator"),
    "--closed-loop-elf", guestElf("closed-loop"),
    "--reciprocal-elf", guestElf("reciprocal"),
    "--manifest", manifestPath,
    "--resolved-manifest-output", manifestPath,
    "--child-artifact-dir", join(artifactDir, "children"),
    "--output", aggregatePath,
  ];
  for (const child of children) aggregateArgs.push("--child", child);
  await run("cargo", aggregateArgs, root, { RUSTUP_TOOLCHAIN: toolchain });

  const aggregate = JSON.parse(await readFile(aggregatePath, "utf8"));
  if (aggregate.securityMode !== "development"
      || aggregate.childCount !== approved.approvedClaimCount
      || aggregate.sourceClaimCount !== approved.approvedClaimCount
      || aggregate.sellerCount !== approved.approvedSellerCount
      || aggregate.provenWashVolumeRaw !== approved.uniqueSuspectedVolumeRaw) {
    throw new Error("aggregate does not prove the complete approved report totals");
  }
  const calldataPath = join(artifactDir, "submit-aggregate-calldata.json");
  await writeFile(
    calldataPath,
    `${JSON.stringify(buildAggregateCalldataArtifact(aggregate), null, 2)}\n`,
  );
  const summary = {
    version: 1,
    kind: "antseed-wash-trading-approved-development-summary",
    securityMode: "development",
    completeness: "complete-approved-report",
    ...approved,
    aggregate: {
      path: aggregatePath,
      sha256: sha256(await readFile(aggregatePath)),
      childCount: aggregate.childCount,
      sourceClaimCount: aggregate.sourceClaimCount,
      sellerCount: aggregate.sellerCount,
      blockReferenceCount: aggregate.blockReferenceCount,
      provenWashVolumeRaw: aggregate.provenWashVolumeRaw,
      calldataPath,
    },
  };
  await mkdir(dirname(summaryPath), { recursive: true });
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`WASH_TRADING_APPROVED_DEVELOPMENT_SUMMARY=${JSON.stringify(summary)}`);
}

async function isCurrentWitness(path, period, claim) {
  try {
    const witness = JSON.parse(await readFile(path, "utf8"));
    return witness?.chain_id === 8_453
      && witness.period_start_block === period.startBlock
      && witness.period_end_block === period.endBlockExclusive - 1
      && Array.isArray(witness.blocks)
      && witness.source_claim_id?.toLowerCase() === claim.claimId.toLowerCase()
      && (claim.type === "P0_RECIPROCAL"
        ? typeof witness.address_a === "string" && typeof witness.address_b === "string"
        : typeof witness.seller === "string");
  } catch (error) {
    if (error.code === "ENOENT" || error instanceof SyntaxError) return false;
    throw error;
  }
}

function guestElf(guest) {
  return resolve(root, `program/${guest}/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/${guest}-guest`);
}

function required(value, flag) {
  if (!value) throw new Error(`missing ${flag}`);
  return value;
}

function sha256(bytes) {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

function run(command, args, cwd, extraEnv = {}) {
  console.error(`> ${command} ${args.join(" ")}`);
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...extraEnv },
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${code}`)));
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
