#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mapWithConcurrency, shardProofPlan } from "./generate-approved-development-proofs.mjs";
import { approveCostQuote, sha256File } from "./proving-cost-quote.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
  const required = ["--bundle", "--plan", "--artifact-dir", "--witness-dir", "--closed-loop-elf", "--reciprocal-elf", "--aggregator-elf", "--guest-attestation", "--cost-quote", "--approve-cost-digest"];
  for (const flag of required) if (!value(flag)) throw new Error(`missing ${flag}`);
  const preflightOnly = args.includes("--preflight-only");
  if (!args.includes("--confirm-production-proving") && !preflightOnly) {
    throw new Error("production proving requires --confirm-production-proving");
  }
  if (!process.env.BASE_RPC_URLS && !process.env.BASE_RPC_URL) throw new Error("BASE_RPC_URLS or BASE_RPC_URL is required");
  if (process.env.SP1_PROVER !== "network") throw new Error("production batch requires SP1_PROVER=network");
  if (!preflightOnly && !process.env.NETWORK_PRIVATE_KEY) throw new Error("production batch requires NETWORK_PRIVATE_KEY");

  const bundlePath = resolve(value("--bundle"));
  const planPath = resolve(value("--plan"));
  const artifactDir = resolve(value("--artifact-dir"));
  const witnessDir = resolve(value("--witness-dir"));
  const sellerScope = value("--seller")?.toLowerCase() ?? null;
  if (sellerScope != null && !/^0x[0-9a-f]{40}$/.test(sellerScope)) throw new Error("invalid --seller address");
  const childConcurrency = positiveInteger(value("--child-concurrency") ?? "1", "--child-concurrency");
  const sellerConcurrency = positiveInteger(value("--seller-concurrency") ?? "1", "--seller-concurrency");
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  validateBundle(bundle);
  const claimById = new Map(bundle.claims.map((claim) => [claim.claimId.toLowerCase(), claim]));
  const allSellers = [...new Set(bundle.claims.flatMap((claim) => claim.subjects.map((seller) => seller.toLowerCase())))].sort();
  if (sellerScope != null && !allSellers.includes(sellerScope)) throw new Error(`${sellerScope}: seller is not approved`);
  const selectedSellers = sellerScope == null ? allSellers : [sellerScope];
  const selectedClaimIds = new Set(bundle.claims
    .filter((claim) => sellerScope == null || claim.subjects.map((seller) => seller.toLowerCase()).includes(sellerScope))
    .map((claim) => claim.claimId.toLowerCase()));

  const quote = approveCostQuote(
    JSON.parse(await readFile(value("--cost-quote"), "utf8")),
    value("--approve-cost-digest"),
    { counts: { p0Claims: selectedClaimIds.size, aggregates: selectedSellers.length }, seller: sellerScope },
  );
  const proofPlanSha256 = await sha256File(planPath);
  const proofBundleSha256 = sha256(await readFile(bundlePath));
  if (quote.body.sources.proofPlanSha256 !== proofPlanSha256
      || quote.body.sources.proofBundleSha256 !== sha256(canonicalJson(bundle))) {
    throw new Error("approved quote source digests do not match the requested bundle and plan");
  }

  const elfPaths = {
    "closed-loop": resolve(value("--closed-loop-elf")),
    reciprocal: resolve(value("--reciprocal-elf")),
    aggregator: resolve(value("--aggregator-elf")),
  };
  const guestAttestationPath = resolve(value("--guest-attestation"));
  const guestAttestation = JSON.parse(await readFile(guestAttestationPath, "utf8"));
  const guests = await validateGuestAttestation(guestAttestation, elfPaths);

  await mkdir(artifactDir, { recursive: true });
  const planShardDir = join(artifactDir, "plan-shards");
  const indexedPlan = await shardProofPlan(planPath, planShardDir, bundle);
  const allEntries = indexedPlan.entries.map((entry, index) => {
    const approved = claimById.get(entry.claim.claimId.toLowerCase());
    if (!approved) throw new Error(`${entry.claim.claimId}: missing approved claim`);
    return {
      index,
      claim: approved,
      kind: approved.type === "P0_RECIPROCAL" ? "reciprocal" : "closed-loop",
      shardPath: entry.shardPath,
      witnessPath: join(witnessDir, `${String(index).padStart(3, "0")}-${approved.claimId.slice(2, 18)}.witness.json`),
    };
  });
  const selectedEntries = allEntries.filter((entry) => selectedClaimIds.has(entry.claim.claimId.toLowerCase()));
  if (selectedEntries.length !== selectedClaimIds.size) throw new Error("selected proof-plan claim count mismatch");
  for (const entry of allEntries) {
    if (!await isNonemptyFile(entry.witnessPath)) throw new Error(`${entry.claim.claimId}: validated witness is missing at ${entry.witnessPath}`);
  }

  const runConfig = {
    version: 1,
    kind: "antseed-wash-trading-production-run",
    scope: { seller: sellerScope },
    sources: {
      proofBundleSha256,
      proofPlanSha256,
      guestAttestationSha256: sha256(await readFile(guestAttestationPath)),
      quoteDigest: quote.digest,
    },
    counts: quote.body.counts,
    networkLimits: quote.body.networkLimits,
    guests,
  };
  const runDirectory = join(artifactDir, "runs");
  await mkdir(runDirectory, { recursive: true });
  const runConfigPath = join(runDirectory, `${sellerScope ?? "full"}.json`);
  const childArtifactDir = join(artifactDir, "children");
  const sellerArtifactDir = join(artifactDir, "sellers");
  const paidCheckpointPaths = [
    ...selectedEntries.flatMap((entry) => {
      const proofPath = childProofPath(childArtifactDir, entry);
      return [proofPath, proofPath.replace(/\.bin$/, ".json")];
    }),
    ...selectedSellers.map((seller) => join(sellerArtifactDir, `${seller}.json`)),
  ];
  const hasPaidCheckpoints = (await Promise.all(paidCheckpointPaths.map(isNonemptyFile))).some(Boolean);
  await writeStableRunConfig(runConfigPath, runConfig, {
    allowReplace: !hasPaidCheckpoints,
    allowQuoteRotation: hasPaidCheckpoints,
  });

  await run("cargo", [
    "build", "--release", "-p", "loop-host", "--features", "sp1",
    "--bin", "wash-trading-prove-child", "--bin", "wash-trading-aggregate",
    "--bin", "wash-trading-network-preflight",
  ], root);
  await mkdir(childArtifactDir, { recursive: true });
  const pendingChildren = [];
  for (const entry of selectedEntries) {
    const proofPath = childProofPath(childArtifactDir, entry);
    if (await loadCurrentChildProof(proofPath, entry, guests)) {
      console.error(`[${entry.index + 1}/${allEntries.length}] reusing paid ${entry.kind} child proof ${entry.claim.claimId}`);
    } else {
      pendingChildren.push(entry);
    }
  }
  if (preflightOnly) {
    console.log(`paid child checkpoint preflight: ${selectedEntries.length - pendingChildren.length} reusable, ${pendingChildren.length} pending`);
    console.log(`production preflight passed for ${sellerScope ?? "all sellers"}`);
    return;
  }

  const networkArgs = [
    "--max-price-per-pgu-wei", quote.body.networkLimits.maxPricePerPguWei,
    "--proof-timeout-secs", String(quote.body.networkLimits.proofTimeoutSeconds),
    "--auction-timeout-secs", String(quote.body.networkLimits.auctionTimeoutSeconds),
  ];
  const childProver = resolve(root, "target/release/wash-trading-prove-child");
  await mapWithConcurrency(pendingChildren, childConcurrency, async (entry) => {
    console.error(`[${entry.index + 1}/${allEntries.length}] requesting paid ${entry.kind} child`);
    await run(childProver, [
      "--index", String(entry.index),
      "--kind", entry.kind,
      "--witness", entry.witnessPath,
      "--closed-loop-elf", elfPaths["closed-loop"],
      "--reciprocal-elf", elfPaths.reciprocal,
      "--output-dir", childArtifactDir,
      ...networkArgs,
    ], root);
    if (!await loadCurrentChildProof(childProofPath(childArtifactDir, entry), entry, guests)) {
      throw new Error(`${entry.claim.claimId}: paid child artifact failed validation`);
    }
  });

  await mkdir(sellerArtifactDir, { recursive: true });
  const aggregateProver = resolve(root, "target/release/wash-trading-aggregate");
  const sellerProofs = await mapWithConcurrency(selectedSellers, sellerConcurrency, async (seller, index) => {
    const sellerPath = join(sellerArtifactDir, `${seller}.json`);
    const expectedChildCount = bundle.claims.filter((claim) => claim.subjects.map((value) => value.toLowerCase()).includes(seller)).length;
    const existing = await loadCurrentSellerProof(sellerPath, seller, expectedChildCount, bundle.period, guests);
    if (existing) {
      console.error(`[${index + 1}/${selectedSellers.length}] reusing paid seller aggregate ${seller}`);
      return summarizeSellerProof(existing, sellerPath);
    }
    const aggregateArgs = [
      "--seller", seller,
      "--aggregator-elf", elfPaths.aggregator,
      "--closed-loop-elf", elfPaths["closed-loop"],
      "--reciprocal-elf", elfPaths.reciprocal,
      "--child-artifact-dir", childArtifactDir,
      "--reuse-child-proofs",
      "--output", sellerPath,
      "--request-checkpoint", sellerPath.replace(/\.json$/, ".request.json"),
      ...networkArgs,
    ];
    for (const entry of allEntries) aggregateArgs.push("--child", `${entry.kind}:${entry.witnessPath}`);
    console.error(`[${index + 1}/${selectedSellers.length}] requesting paid seller aggregate ${seller}`);
    await run(aggregateProver, aggregateArgs, root);
    const sellerProof = await loadCurrentSellerProof(sellerPath, seller, expectedChildCount, bundle.period, guests);
    if (!sellerProof) throw new Error(`${seller}: paid seller artifact failed validation`);
    return summarizeSellerProof(sellerProof, sellerPath);
  });

  const summary = {
    version: 1,
    kind: "antseed-wash-trading-production-summary",
    securityMode: "production",
    scope: { seller: sellerScope },
    quoteDigest: quote.digest,
    runConfigPath,
    childProofCount: selectedEntries.length,
    sellerProofCount: sellerProofs.length,
    totalProvenWashVolumeRaw: sellerProofs.reduce((total, proof) => total + BigInt(proof.provenWashVolumeRaw), 0n).toString(),
    sellerProofs,
  };
  const summaryPath = join(artifactDir, `summary-${sellerScope ?? "full"}.json`);
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`WASH_TRADING_PRODUCTION_SUMMARY=${JSON.stringify(summary)}`);
}

async function validateGuestAttestation(attestation, elfPaths) {
  if (attestation?.version !== 3 || attestation.kind !== "antseed-sp1-program-build-attestation" || attestation.reproducible !== true) {
    throw new Error("invalid reproducible guest build attestation");
  }
  const guests = {};
  for (const guest of ["closed-loop", "reciprocal", "aggregator"]) {
    const expected = attestation.guests?.[guest];
    if (!expected || !/^0x[0-9a-f]{64}$/i.test(expected.programVKey ?? "") || !/^0x[0-9a-f]{64}$/i.test(expected.elfSha256 ?? "")) {
      throw new Error(`${guest}: invalid guest attestation entry`);
    }
    const actualElfSha256 = await sha256File(elfPaths[guest]);
    if (actualElfSha256 !== expected.elfSha256) throw new Error(`${guest}: ELF digest differs from reproducible attestation`);
    guests[guest] = { programVKey: expected.programVKey.toLowerCase(), elfSha256: actualElfSha256 };
  }
  return guests;
}

export async function loadCurrentChildProof(proofPath, entry, guests) {
  const metadataPath = proofPath.replace(/\.bin$/, ".json");
  const proofExists = await isNonemptyFile(proofPath);
  const metadataExists = await isNonemptyFile(metadataPath);
  if (!proofExists && !metadataExists) return null;
  if (!proofExists || !metadataExists) throw new Error(`${entry.claim.claimId}: incomplete paid child checkpoint`);
  const artifact = JSON.parse(await readFile(metadataPath, "utf8"));
  const expectedVkey = guests[entry.kind].programVKey;
  if (artifact?.version !== 2 || artifact.kind !== "antseed-wash-trading-child-proof"
      || artifact.securityMode !== "production" || artifact.childKind !== entry.kind
      || artifact.sourceClaimId?.toLowerCase() !== entry.claim.claimId.toLowerCase()
      || artifact.programVKey?.toLowerCase() !== expectedVkey
      || artifact.verified !== true
      || !/^0x[0-9a-f]{64}$/i.test(artifact.programId ?? "")
      || !/^0x(?:[0-9a-f]{2})+$/i.test(artifact.publicValues ?? "")
      || typeof artifact.proofPath !== "string"
      || resolve(artifact.proofPath) !== resolve(proofPath)) {
    throw new Error(`${entry.claim.claimId}: stale or invalid paid child checkpoint`);
  }
  return artifact;
}

async function loadCurrentSellerProof(path, seller, childCount, period, guests) {
  if (!await isNonemptyFile(path)) return null;
  const artifact = JSON.parse(await readFile(path, "utf8"));
  if (artifact?.version !== 2 || artifact.kind !== "antseed-wash-trading-seller-proof"
      || artifact.securityMode !== "production" || artifact.seller?.toLowerCase() !== seller
      || artifact.childCount !== childCount
      || artifact.periodStartBlock !== period.startBlock
      || artifact.periodEndBlock !== period.endBlockExclusive - 1
      || artifact.aggregatorProgramVKey?.toLowerCase() !== guests.aggregator.programVKey
      || artifact.closedLoopProgramVKey?.toLowerCase() !== guests["closed-loop"].programVKey
      || artifact.reciprocalProgramVKey?.toLowerCase() !== guests.reciprocal.programVKey
      || !/^0x[0-9a-f]+$/i.test(artifact.proofBytes ?? "") || artifact.proofBytes === "0x") {
    throw new Error(`${seller}: stale or invalid paid seller checkpoint`);
  }
  return artifact;
}

function summarizeSellerProof(proof, path) {
  return {
    seller: proof.seller.toLowerCase(),
    path,
    childCount: proof.childCount,
    provenWashVolumeRaw: proof.provenWashVolumeRaw,
    blockReferenceCount: proof.blockReferenceCount,
    sha256: sha256(JSON.stringify(proof)),
  };
}

function childProofPath(directory, entry) {
  return join(directory, `${String(entry.index).padStart(3, "0")}-${entry.claim.claimId}.proof.bin`);
}

export async function writeStableRunConfig(path, config, {
  allowReplace = false,
  allowQuoteRotation = false,
} = {}) {
  const serialized = `${JSON.stringify(config, null, 2)}\n`;
  if (await isNonemptyFile(path)) {
    const existingSerialized = await readFile(path, "utf8");
    if (existingSerialized === serialized) return;
    if (allowQuoteRotation) {
      const existing = JSON.parse(existingSerialized);
      if (sameRunExceptQuoteDigest(existing, config)) {
        console.error(`updating approved quote for stable paid run ${path}`);
        await writeFile(path, serialized);
        return;
      }
    }
    if (!allowReplace) throw new Error(`run configuration differs from existing checkpoint ${path}`);
    console.error(`replacing stale no-spend run configuration ${path}`);
  }
  await writeFile(path, serialized);
}

function sameRunExceptQuoteDigest(existing, replacement) {
  if (!/^0x[0-9a-f]{64}$/i.test(existing?.sources?.quoteDigest ?? "")
      || !/^0x[0-9a-f]{64}$/i.test(replacement?.sources?.quoteDigest ?? "")) return false;
  const existingStable = structuredClone(existing);
  const replacementStable = structuredClone(replacement);
  delete existingStable.sources.quoteDigest;
  delete replacementStable.sources.quoteDigest;
  return canonicalJson(existingStable) === canonicalJson(replacementStable);
}

async function isNonemptyFile(path) {
  try { return (await stat(path)).isFile() && (await stat(path)).size > 0; } catch { return false; }
}

function validateBundle(bundle) {
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle" || bundle.chainId !== 8_453
      || !Array.isArray(bundle.claims) || bundle.claims.length === 0) {
    throw new Error("invalid approved proof bundle");
  }
}

function positiveInteger(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

function run(command, commandArgs, cwd) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, { cwd, stdio: "inherit", env: process.env });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${code}`)));
  });
}

function sha256(value) { return `0x${createHash("sha256").update(value).digest("hex")}`; }
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

if (process.argv[1] && basename(process.argv[1]) === basename(new URL(import.meta.url).pathname)) {
  main().catch((error) => { console.error(error.stack ?? error.message); process.exitCode = 1; });
}
