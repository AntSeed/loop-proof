#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { historicalManifestFromBundle } from "./generate-historical-manifest.mjs";
import { planFile } from "./proof-planner.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export async function buildSnapshotLock({ scanDirectory, bundlePath, planPath, plan: suppliedPlan = null }) {
  const sourcePaths = {
    manifest: join(scanDirectory, "manifest.json"),
    scan: join(scanDirectory, "scan.json"),
    sellerCoverage: join(scanDirectory, "discovery", "seller-coverage.json"),
    proofCoverage: join(scanDirectory, "proof", "proof-coverage.json"),
  };
  const [manifest, scan, sellerCoverage, proofCoverage, bundle, plan] = await Promise.all([
    readJson(sourcePaths.manifest),
    readJson(sourcePaths.scan),
    readJson(sourcePaths.sellerCoverage),
    readJson(sourcePaths.proofCoverage),
    readJson(bundlePath),
    suppliedPlan ?? readProofPlanSummary(planPath),
  ]);
  validateSnapshotInputs({ manifest, scan, sellerCoverage, proofCoverage, bundle, plan });
  const historicalManifest = historicalManifestFromBundle(bundle);
  const sourceClaimWashVolumeRaw = historicalManifest.claims
    .flatMap((claim) => claim.subjects)
    .reduce((total, subject) => total + BigInt(subject.proven_wash_volume), 0n)
    .toString();
  const approvedSellers = new Set(
    historicalManifest.claims.flatMap((claim) => claim.subjects.map((subject) => subject.seller)),
  ).size;
  const sourceDigests = Object.fromEntries(await Promise.all(Object.entries(sourcePaths).map(async ([name, path]) => [name, sha256(await readFile(path))])));
  return {
    version: 1,
    kind: "antseed-unified-historical-wash-snapshot-lock",
    scanId: scan.scanId,
    scanDirectory,
    scanDigest: sha256(Buffer.from(canonicalJson(sourceDigests))),
    sourceDigests,
    sellerUniverseDigest: sha256(Buffer.from(sellerCoverage.evaluated.join("\n"))),
    cutoff: {
      fromTimestamp: scan.period.from,
      toTimestamp: scan.period.to,
      fromIso: scan.period.fromIso,
      toIso: scan.period.toIso,
      startBlock: scan.proofPeriod.startBlock,
      endBlockExclusive: scan.proofPeriod.endBlockExclusive,
    },
    policyVersion: bundle.policyVersion,
    reportRoot: bundle.reportRoot,
    bundle: { path: bundlePath, sha256: await sha256File(bundlePath) },
    plan: { path: planPath, sha256: await sha256File(planPath) },
    counts: {
      evaluatedSellers: sellerCoverage.evaluated.length,
      approvedClaims: bundle.claims.length,
      approvedSellers,
    },
    sourceClaimWashVolumeRaw,
  };
}

export function validateSnapshotInputs({ manifest, scan, sellerCoverage, proofCoverage, bundle, plan }) {
  if (manifest.status !== "complete" || scan.status !== "complete") throw new Error("snapshot requires a completed scan");
  if (manifest.request?.seller) throw new Error("snapshot rejects seller-targeted scans");
  if (!sellerCoverage.complete || sellerCoverage.incomplete?.length !== 0) throw new Error("snapshot seller coverage is incomplete");
  const sellerCount = scan.counts?.sellers ?? scan.sellers?.length;
  if (sellerCoverage.evaluated?.length !== sellerCount || new Set(sellerCoverage.evaluated).size !== sellerCount) {
    throw new Error("snapshot seller universe does not match the completed scan");
  }
  if (proofCoverage.source?.scanId !== scan.scanId || bundle.scanId !== scan.scanId) throw new Error("snapshot artifacts come from different scans");
  if (bundle.claims?.length !== proofCoverage.summary?.totalProofs) throw new Error("bundle does not contain every approved proof claim");
  if (plan.reportRoot !== bundle.reportRoot || plan.claimCount !== bundle.claims.length || plan.claims?.length !== bundle.claims.length) {
    throw new Error("plan does not contain the complete unified bundle");
  }
  const plannedIds = new Set(plan.claims.map((claim) => claim.claimId?.toLowerCase()));
  if (bundle.claims.some((claim) => !plannedIds.has(claim.claimId.toLowerCase()))) throw new Error("plan claim identities differ from the unified bundle");
  if (JSON.stringify(plan.period) !== JSON.stringify(bundle.period)
    || JSON.stringify(bundle.period) !== JSON.stringify(scan.proofPeriod)) throw new Error("snapshot proof periods differ");
}

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
  const scanDirectory = resolve(required(value("--scan-dir"), "--scan-dir"));
  const outputDirectory = resolve(value("--out-dir") ?? join(scanDirectory, "proof", "unified-historical"));
  const rpcUrl = value("--rpc-url") ?? process.env.ANTSEED_BASE_RPC_URL ?? process.env.BASE_RPC_URL;
  if (!rpcUrl) throw new Error("ANTSEED_BASE_RPC_URL, BASE_RPC_URL, or --rpc-url is required");
  await mkdir(outputDirectory, { recursive: true });
  const bundlePath = join(outputDirectory, "proof-bundle.json");
  const planPath = join(outputDirectory, "proof-plan.json");
  await run(process.execPath, [join(root, "scripts", "build-unified-historical-bundle.mjs"), "--scan-dir", scanDirectory, "--out", bundlePath], root);
  const plan = await planFile({
    bundlePath,
    outPath: planPath,
    rpcUrl,
    concurrency: Number(value("--concurrency") ?? 1),
    claimConcurrency: Number(value("--claim-concurrency") ?? 4),
    claimIds: null,
    checkpointDirectory: join(outputDirectory, "ledger-finalization-checkpoints"),
    planCheckpointDirectory: join(outputDirectory, "proof-plan-checkpoints"),
    onProgress: (message) => console.error(message),
  });
  const lock = await buildSnapshotLock({ scanDirectory, bundlePath, planPath, plan });
  const lockPath = join(outputDirectory, "snapshot-lock.json");
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  console.log(`WASH_TRADING_UNIFIED_SNAPSHOT=${JSON.stringify({ lockPath, reportRoot: lock.reportRoot, counts: lock.counts, sourceClaimWashVolumeRaw: lock.sourceClaimWashVolumeRaw })}`);
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}
function sha256(bytes) { return `0x${createHash("sha256").update(bytes).digest("hex")}`; }
function sha256File(path) {
  return new Promise((resolveDigest, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolveDigest(`0x${hash.digest("hex")}`));
  });
}
function required(value, flag) { if (!value) throw new Error(`missing ${flag}`); return value; }
async function readJson(path) { return JSON.parse(await readFile(path, "utf8")); }
export async function readProofPlanSummary(path) {
  const marker = '"claims":[';
  let pending = "";
  let metadata = null;
  let claimDepth = 0;
  let inString = false;
  let escaped = false;
  let claimsEnded = false;
  let claimChunks = [];
  const claims = [];
  for await (const chunk of createReadStream(path, { encoding: "utf8" })) {
    pending += chunk;
    if (!metadata) {
      const markerIndex = pending.indexOf(marker);
      if (markerIndex < 0) continue;
      metadata = JSON.parse(`${pending.slice(0, markerIndex)}"claims":[]}`);
      pending = pending.slice(markerIndex + marker.length);
    }
    let claimStart = claimDepth > 0 ? 0 : null;
    let consumed = 0;
    for (let index = 0; index < pending.length; index += 1) {
      const character = pending[index];
      consumed = index + 1;
      if (claimsEnded) break;
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
          const claim = JSON.parse(claimChunks.join(""));
          claims.push({ claimId: claim.claimId });
          claimChunks = [];
          claimStart = null;
        }
      }
    }
    if (claimsEnded) break;
    if (claimDepth > 0 && claimStart != null) {
      claimChunks.push(pending.slice(claimStart, consumed));
      pending = pending.slice(consumed);
    } else {
      pending = pending.slice(consumed);
    }
  }
  if (!metadata || !claimsEnded) throw new Error("proof plan is incomplete");
  return { ...metadata, claimCount: metadata.claimCount ?? claims.length, claims };
}
function run(command, args, cwd) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, { cwd, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${basename(command)} exited with ${code}`)));
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
