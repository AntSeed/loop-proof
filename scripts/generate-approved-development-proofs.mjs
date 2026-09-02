#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAX_PREDICATE_BLOCK_REFS = 65_536;

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
    uniqueSettlementVolumeRaw: uniqueVolume.toString(),
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

export async function mapWithConcurrency(items, concurrency, worker) {
  if (!Number.isSafeInteger(concurrency) || concurrency < 1) {
    throw new Error("concurrency must be a positive integer");
  }
  const results = new Array(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

export function countClaimMaterializationBlocks(claim, periodEndBlock) {
  const blocks = new Set([periodEndBlock]);
  const atomicEvidence = [];
  for (const evidence of claim.selectedEvidence ?? []) {
    if (evidence.evidenceType === "RELAY_PATH") {
      atomicEvidence.push(evidence.sellerPayment, evidence.relayForward, evidence.funderReceipt);
    } else {
      atomicEvidence.push(evidence);
    }
  }
  for (const evidence of atomicEvidence) {
    if (Number.isSafeInteger(evidence?.blockNumber)) blocks.add(evidence.blockNumber);
  }
  return blocks.size;
}

export function validateClaimMaterializationBlocks(claim, periodEndBlock, maximum = MAX_PREDICATE_BLOCK_REFS) {
  const count = countClaimMaterializationBlocks(claim, periodEndBlock);
  if (count > maximum) {
    throw new Error(`${claim.claimId}: ${count} materialization blocks exceed predicate maximum ${maximum}`);
  }
  return count;
}

export async function shardProofPlan(planPath, shardDirectory, bundle) {
  await mkdir(shardDirectory, { recursive: true });
  const marker = '"claims":[';
  let pending = "";
  let metadata = null;
  let claimChunks = [];
  let claimDepth = 0;
  let inString = false;
  let escaped = false;
  let parsingClaims = false;
  let claimsEnded = false;
  const entries = [];
  const approvedById = new Map(bundle.claims.map((claim) => [claim.claimId.toLowerCase(), claim]));
  const seenIds = new Set();
  const accumulator = createBatchAccumulator(bundle);

  for await (const chunk of createReadStream(planPath, { encoding: "utf8" })) {
    pending += chunk;
    if (!parsingClaims) {
      const markerIndex = pending.indexOf(marker);
      if (markerIndex < 0) continue;
      metadata = JSON.parse(`${pending.slice(0, markerIndex)}"claims":[]}`);
      pending = pending.slice(markerIndex + marker.length);
      parsingClaims = true;
      validatePlanMetadata(bundle, metadata);
    }

    let claimStart = claimDepth > 0 ? 0 : null;
    let consumed = 0;
    for (let index = 0; index < pending.length; index += 1) {
      const character = pending[index];
      consumed = index + 1;
      if (claimsEnded) continue;
      if (claimDepth === 0) {
        if (character === "{") {
          claimDepth = 1;
          claimStart = index;
          inString = false;
          escaped = false;
        } else if (character === "]") {
          claimsEnded = true;
        }
        continue;
      }
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') inString = true;
      else if (character === "{") claimDepth += 1;
      else if (character === "}") {
        claimDepth -= 1;
        if (claimDepth === 0) {
          claimChunks.push(pending.slice(claimStart, index + 1));
          const claimText = claimChunks.join("");
          const claim = JSON.parse(claimText);
          const claimId = claim.claimId?.toLowerCase();
          const approved = approvedById.get(claimId);
          if (!approved || seenIds.has(claimId)) throw new Error(`unexpected or duplicate planned claim ${claim.claimId}`);
          accumulateClaim(accumulator, approved, claim);
          validateClaimMaterializationBlocks(claim, metadata.period.endBlockExclusive - 1);
          seenIds.add(claimId);
          const shardPath = join(shardDirectory, `${String(entries.length).padStart(3, "0")}-${claim.claimId.slice(2, 18)}.plan.json`);
          const shardPrefix = JSON.stringify({
            version: metadata.version,
            kind: metadata.kind,
            chainId: metadata.chainId,
            period: metadata.period,
          });
          await writeFile(shardPath, `${shardPrefix.slice(0, -1)},"claims":[${claimText}]}\n`);
          entries.push({ claim: { claimId: claim.claimId, type: claim.type }, shardPath });
          claimChunks = [];
          claimStart = null;
        }
      }
    }
    if (claimDepth > 0 && claimStart != null) claimChunks.push(pending.slice(claimStart));
    pending = parsingClaims ? pending.slice(consumed) : pending;
  }

  if (!metadata || !claimsEnded || claimDepth !== 0) throw new Error("incomplete proof plan JSON");
  if (entries.length !== bundle.claims.length || seenIds.size !== bundle.claims.length) {
    throw new Error(`partial proof plan: expected ${bundle.claims.length} claims, received ${entries.length}`);
  }
  if (metadata.claimCount !== entries.length) throw new Error("proof plan claim count mismatch");
  return { entries, period: metadata.period, approved: finishBatchAccumulator(accumulator) };
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
  const snapshotLockPath = resolve(required(value("--snapshot-lock"), "--snapshot-lock"));
  const toolchain = process.env.RUSTUP_TOOLCHAIN ?? "1.94";
  const skipGuestBuild = args.includes("--skip-guest-build");
  const materializeConcurrency = positiveInteger(
    value("--materialize-concurrency") ?? process.env.WASH_TRADING_MATERIALIZE_CONCURRENCY ?? "2",
    "--materialize-concurrency",
  );
  const bundleBytes = await readFile(bundlePath);
  const bundle = JSON.parse(bundleBytes);
  const snapshotLock = JSON.parse(await readFile(snapshotLockPath, "utf8"));
  await mkdir(artifactDir, { recursive: true });
  const planShardsDirectory = join(artifactDir, "plan-shards");
  const indexedPlan = await shardProofPlan(planPath, planShardsDirectory, bundle);
  validateSnapshotLock(snapshotLock, bundlePath, planPath, bundle, indexedPlan.approved, {
    bundle: sha256(bundleBytes),
    plan: await sha256File(planPath),
  });
  const approved = indexedPlan.approved;
  const copiedSnapshotLockPath = join(artifactDir, "snapshot-lock.json");
  await writeFile(copiedSnapshotLockPath, `${JSON.stringify(snapshotLock, null, 2)}\n`);
  const materializer = resolve(root, "target/release/wash-trading-materialize-p0");
  await run("cargo", [
    "build", "--release", "-p", "loop-host",
    "--bin", "wash-trading-materialize-p0",
  ], root, { RUSTUP_TOOLCHAIN: toolchain });
  const materializerSha256 = await sha256File(materializer);
  const witnessEntries = indexedPlan.entries.map(({ claim, shardPath }, index) => ({
    index,
    claim,
    shardPath,
    witnessPath: join(artifactDir, `${String(index).padStart(3, "0")}-${claim.claimId.slice(2, 18)}.witness.json`),
  }));
  const missingWitnesses = [];
  for (const entry of witnessEntries) {
    if (!await isCurrentWitness(entry.witnessPath, indexedPlan.period, entry.claim, materializerSha256)) {
      missingWitnesses.push(entry);
    } else {
      console.error(`[${entry.index + 1}/${witnessEntries.length}] reusing ${basename(entry.witnessPath)}`);
    }
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

  if (missingWitnesses.length > 0) {
    await mapWithConcurrency(missingWitnesses, materializeConcurrency, async ({ index, claim, shardPath, witnessPath }) => {
      console.error(`[${index + 1}/${witnessEntries.length}] materializing ${claim.claimId}`);
      await run(materializer, ["--plan", shardPath, "--claim-id", claim.claimId, "--output", witnessPath], root, {
        LOOP_RPC_CONCURRENCY: process.env.LOOP_RPC_CONCURRENCY ?? "1",
      });
      await writeWitnessCacheMetadata(witnessPath, indexedPlan.period, claim, materializerSha256);
    });
  }

  const children = [];
  for (const { claim, witnessPath } of witnessEntries) {
    if (!await isCurrentWitness(witnessPath, indexedPlan.period, claim, materializerSha256)) {
      throw new Error(`${claim.claimId}: canonical witness is missing or stale after materialization`);
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
  const sellers = [...new Set(bundle.claims.flatMap((claim) => claim.subjects.map((seller) => seller.toLowerCase())))].sort();
  if (sellers.length !== approved.approvedSellerCount) throw new Error("approved seller count mismatch");
  const sellerProofDirectory = join(artifactDir, "sellers");
  const childArtifactDirectory = join(artifactDir, "children");
  await mkdir(sellerProofDirectory, { recursive: true });
  const sellerProofs = [];
  for (const [sellerIndex, seller] of sellers.entries()) {
    const sellerProofPath = join(sellerProofDirectory, `${seller}.json`);
    const aggregateArgs = [
      "run", "--release", "-p", "loop-host", "--features", "sp1", "--bin", "wash-trading-aggregate", "--",
      "--development",
      "--seller", seller,
      "--aggregator-elf", guestElf("aggregator"),
      "--closed-loop-elf", guestElf("closed-loop"),
      "--reciprocal-elf", guestElf("reciprocal"),
      "--child-artifact-dir", childArtifactDirectory,
      "--reuse-child-proofs",
      "--output", sellerProofPath,
    ];
    for (const child of children) aggregateArgs.push("--child", child);
    console.error(`[${sellerIndex + 1}/${sellers.length}] aggregating seller ${seller}`);
    await run("cargo", aggregateArgs, root, { RUSTUP_TOOLCHAIN: toolchain });
    const sellerProof = JSON.parse(await readFile(sellerProofPath, "utf8"));
    if (sellerProof?.version !== 2 || sellerProof.kind !== "antseed-wash-trading-seller-proof"
        || sellerProof.securityMode !== "development" || sellerProof.seller.toLowerCase() !== seller) {
      throw new Error(`${seller}: invalid seller proof artifact`);
    }
    sellerProofs.push({
      seller,
      path: sellerProofPath,
      sha256: sha256(await readFile(sellerProofPath)),
      childCount: sellerProof.childCount,
      provenWashVolumeRaw: sellerProof.provenWashVolumeRaw,
      blockReferenceCount: sellerProof.blockReferenceCount,
    });
  }
  if (sellerProofs.length !== approved.approvedSellerCount) {
    throw new Error("not every approved seller received a proof artifact");
  }
  const summary = {
    version: 1,
    kind: "antseed-wash-trading-approved-development-summary",
    securityMode: "development",
    completeness: "all-approved-sellers-materialized-offchain",
    snapshotLock: { path: copiedSnapshotLockPath, sha256: sha256(await readFile(copiedSnapshotLockPath)) },
    ...approved,
    sellerProofCount: sellerProofs.length,
    sellerProofs,
  };
  await mkdir(dirname(summaryPath), { recursive: true });
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`WASH_TRADING_APPROVED_DEVELOPMENT_SUMMARY=${JSON.stringify(summary)}`);
}

export function validateSnapshotLock(lock, bundlePath, planPath, bundle, plan, digests = {}) {
  if (lock?.version !== 1 || lock.kind !== "antseed-unified-historical-wash-snapshot-lock") {
    throw new Error("invalid unified snapshot lock");
  }
  const approved = Array.isArray(plan?.claims) ? buildApprovedBatchSummary(bundle, plan) : plan;
  if (lock.reportRoot !== bundle.reportRoot || lock.counts?.approvedClaims !== bundle.claims.length
    || lock.counts?.approvedSellers !== approved?.approvedSellerCount) {
    throw new Error("snapshot lock totals do not match bundle and plan");
  }
  if (lock.bundle?.path !== bundlePath || lock.plan?.path !== planPath) {
    throw new Error("snapshot lock paths do not match requested inputs");
  }
  if (digests.bundle && lock.bundle.sha256 !== digests.bundle) throw new Error("snapshot bundle digest mismatch");
  if (digests.plan && lock.plan.sha256 !== digests.plan) throw new Error("snapshot plan digest mismatch");
}

function validatePlanMetadata(bundle, plan) {
  if (plan?.version !== 2 || plan.kind !== "antseed-wash-trading-proof-plan") throw new Error("invalid approved proof plan");
  if (bundle.chainId !== 8_453 || plan.chainId !== bundle.chainId || plan.reportRoot !== bundle.reportRoot) {
    throw new Error("bundle and plan identity mismatch");
  }
  if (JSON.stringify(plan.period) !== JSON.stringify(bundle.period)) throw new Error("bundle and plan periods differ");
}

function createBatchAccumulator(bundle) {
  return {
    bundle,
    uniqueSettlements: new Map(),
    closedLoopVolume: 0n,
    reciprocalVolume: 0n,
  };
}

function accumulateClaim(accumulator, approved, planned) {
  let selectedVolume = 0n;
  for (const evidence of planned.selectedEvidence ?? []) {
    if (!["SETTLEMENT", "RECIPROCAL_SETTLEMENT"].includes(evidence.evidenceType)) continue;
    const source = evidence.dependencyLeaf ? JSON.parse(evidence.dependencyLeaf) : evidence;
    const logIndex = evidence.receiptLogIndex ?? source.logIndex;
    if (!source.transactionHash || !Number.isSafeInteger(logIndex) || logIndex < 0) {
      throw new Error(`${planned.claimId}: settlement identity is incomplete`);
    }
    const amount = BigInt(source.amountRaw);
    const identity = `${source.transactionHash}:${logIndex}`.toLowerCase();
    const existing = accumulator.uniqueSettlements.get(identity);
    if (existing != null && existing !== amount) throw new Error(`${planned.claimId}: settlement ${identity} has conflicting amounts`);
    accumulator.uniqueSettlements.set(identity, amount);
    selectedVolume += amount;
  }
  const approvedVolume = approved.type === "P0_RECIPROCAL"
    ? BigInt(approved.metrics.volumeAToBRaw) + BigInt(approved.metrics.volumeBToARaw)
    : BigInt(approved.metrics.qualifiedVolumeRaw);
  if (selectedVolume !== approvedVolume) {
    throw new Error(`${planned.claimId}: selected volume ${selectedVolume} differs from approved volume ${approvedVolume}`);
  }
  if (approved.type === "P0_RECIPROCAL") accumulator.reciprocalVolume += selectedVolume;
  else accumulator.closedLoopVolume += selectedVolume;
}

function finishBatchAccumulator(accumulator) {
  const { bundle, uniqueSettlements, closedLoopVolume, reciprocalVolume } = accumulator;
  return {
    reportRoot: bundle.reportRoot,
    period: bundle.period,
    approvedClaimCount: bundle.claims.length,
    approvedSellerCount: new Set(bundle.claims.flatMap((claim) => claim.subjects.map((subject) => subject.toLowerCase()))).size,
    closedLoopVolumeRaw: closedLoopVolume.toString(),
    reciprocalVolumeRaw: reciprocalVolume.toString(),
    uniqueSettlementVolumeRaw: [...uniqueSettlements.values()].reduce((total, amount) => total + amount, 0n).toString(),
    uniqueSettlementCount: uniqueSettlements.size,
  };
}

function sha256File(path) {
  return new Promise((resolveDigest, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolveDigest(`0x${hash.digest("hex")}`));
  });
}

export async function writeWitnessCacheMetadata(path, period, claim, materializerSha256) {
  const witness = await stat(path);
  if (!witness.isFile() || witness.size === 0) throw new Error(`${path}: witness file is empty`);
  const metadata = {
    version: 1,
    kind: "antseed-wash-trading-witness-cache",
    chainId: 8_453,
    periodStartBlock: period.startBlock,
    periodEndBlock: period.endBlockExclusive - 1,
    sourceClaimId: claim.claimId.toLowerCase(),
    claimType: claim.type,
    materializerSha256,
    witnessSize: witness.size,
    witnessMtimeMs: witness.mtimeMs,
  };
  await writeFile(`${path}.cache.json`, `${JSON.stringify(metadata, null, 2)}\n`);
  return metadata;
}

export async function isCurrentWitness(path, period, claim, materializerSha256) {
  try {
    const [witness, metadata] = await Promise.all([
      stat(path),
      readFile(`${path}.cache.json`, "utf8").then(JSON.parse),
    ]);
    return witness.isFile()
      && witness.size > 0
      && metadata?.version === 1
      && metadata.kind === "antseed-wash-trading-witness-cache"
      && metadata.chainId === 8_453
      && metadata.periodStartBlock === period.startBlock
      && metadata.periodEndBlock === period.endBlockExclusive - 1
      && metadata.sourceClaimId === claim.claimId.toLowerCase()
      && metadata.claimType === claim.type
      && metadata.materializerSha256 === materializerSha256
      && metadata.witnessSize === witness.size
      && metadata.witnessMtimeMs === witness.mtimeMs;
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

function positiveInteger(value, flag) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${flag} must be a positive integer`);
  return parsed;
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
