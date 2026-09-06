#!/usr/bin/env node
import { open, readFile, readdir } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { attachMemberships, planClaim } from "./proof-planner.mjs";

export async function reconstructUnifiedProofPlan({ bundle, shardDirectory, outPath, onProgress = () => {} }) {
  const shardFiles = await readdir(shardDirectory);
  const claims = bundle.claims;
  const blockNumbers = new Set();
  const output = await open(outPath, "w");
  try {
    const metadata = {
      version: 2,
      kind: "antseed-wash-trading-proof-plan",
      bundleVersion: bundle.version,
      chainId: bundle.chainId,
      reportRoot: bundle.reportRoot,
      period: bundle.period,
      claimCount: claims.length,
    };
    const prefix = JSON.stringify(metadata);
    await output.write(`${prefix.slice(0, -1)},\"claims\":[`);
    for (let index = 0; index < claims.length; index += 1) {
      const approved = claims[index];
      const planned = approved.type === "P0_RECIPROCAL"
        ? await loadReusableReciprocalPlan(approved, shardDirectory, shardFiles)
        : planClaim(approved, approved.dependencies, bundle);
      const finalized = attachMemberships(planned, approved, claims);
      for (const blockNumber of finalized.selectedBlocks) blockNumbers.add(blockNumber);
      if (index > 0) await output.write(",");
      await output.write(JSON.stringify(finalized));
      onProgress(`[reuse ${index + 1}/${claims.length}] ${approved.type} ${approved.claimId}`);
    }
    const materializationBlockNumbers = [...blockNumbers].sort((left, right) => left - right);
    await output.write(`],\"evidenceBlockSelection\":${JSON.stringify({
      version: 1,
      chain_id: bundle.chainId,
      start_block: bundle.period.startBlock,
      end_block_exclusive: bundle.period.endBlockExclusive,
      materializationBlockNumbers,
    })}}\n`);
    return { claimCount: claims.length, materializationBlockNumbers };
  } finally {
    await output.close();
  }
}

async function loadReusableReciprocalPlan(approved, directory, files) {
  const prefix = approved.claimId.slice(2, 18).toLowerCase();
  const candidates = files.filter((file) => file.toLowerCase().includes(prefix) && file.endsWith(".plan.json"));
  if (candidates.length !== 1) throw new Error(`${approved.claimId}: expected one reusable plan shard, found ${candidates.length}`);
  const shard = JSON.parse(await readFile(join(directory, candidates[0]), "utf8"));
  const planned = shard.claims?.[0];
  if (!planned || planned.type !== "P0_RECIPROCAL" || planned.claimId.toLowerCase() !== approved.claimId.toLowerCase()) {
    throw new Error(`${approved.claimId}: reusable shard identity mismatch`);
  }
  if (planned.dependencyRoot !== approved.dependencyRoot) throw new Error(`${approved.claimId}: reusable shard dependency root mismatch`);
  const approvedDependencies = new Set(approved.dependencies.map((entry) => entry.dependencyId));
  if (planned.selectedEvidence.some((entry) => !approvedDependencies.has(entry.dependencyId))) {
    throw new Error(`${approved.claimId}: reusable shard contains evidence outside the finalized claim`);
  }
  return planned;
}

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const bundlePath = value("--bundle");
  const shardDirectory = value("--shard-dir");
  const outPath = value("--out");
  if (!bundlePath || !shardDirectory || !outPath) {
    throw new Error("usage: --bundle FILE --shard-dir DIRECTORY --out FILE");
  }
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const result = await reconstructUnifiedProofPlan({
    bundle,
    shardDirectory,
    outPath,
    onProgress: (message) => console.error(message),
  });
  console.log(`reconstructed ${result.claimCount} claims across ${result.materializationBlockNumbers.length} blocks into ${basename(outPath)}`);
}
