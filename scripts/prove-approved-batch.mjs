#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mapWithConcurrency, shardProofPlan } from "./generate-approved-development-proofs.mjs";
import { approveCostQuote, sha256File } from "./proving-cost-quote.mjs";
import { sellerEvidenceByAddress, singleEvidenceEntry } from "./seller-evidence.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const index = args.indexOf(flag);
    return index < 0 ? null : args[index + 1];
  };
  const requiredFlags = [
    "--bundle", "--plan", "--artifact-dir", "--witness-dir", "--seller-elf",
    "--guest-attestation", "--cost-quote", "--approve-cost-digest",
  ];
  for (const flag of requiredFlags) if (!value(flag)) throw new Error(`missing ${flag}`);

  const preflightOnly = args.includes("--preflight-only");
  if (!preflightOnly && !args.includes("--confirm-production-proving")) {
    throw new Error("production proving requires --confirm-production-proving");
  }
  if (process.env.SP1_PROVER !== "network") throw new Error("production batch requires SP1_PROVER=network");
  if (!preflightOnly && !process.env.NETWORK_PRIVATE_KEY) {
    throw new Error("production batch requires NETWORK_PRIVATE_KEY");
  }

  const bundlePath = resolve(value("--bundle"));
  const planPath = resolve(value("--plan"));
  const artifactDir = resolve(value("--artifact-dir"));
  const witnessDir = resolve(value("--witness-dir"));
  const totalVolumeWitnessDir = value("--total-volume-witness-dir") ? resolve(value("--total-volume-witness-dir")) : null;
  const sellerElf = resolve(value("--seller-elf"));
  const guestAttestationPath = resolve(value("--guest-attestation"));
  const sellerScope = value("--seller")?.toLowerCase() ?? null;
  if (sellerScope != null && !/^0x[0-9a-f]{40}$/.test(sellerScope)) {
    throw new Error("invalid --seller address");
  }
  const sellerConcurrency = positiveInteger(value("--seller-concurrency") ?? "1", "--seller-concurrency");

  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  validateBundle(bundle);
  sellerEvidenceByAddress(bundle, bundle.claims.map((claim) => ({ claim })));
  const claimById = new Map(bundle.claims.map((claim) => [claim.claimId.toLowerCase(), claim]));
  const allSellers = [...new Set(
    bundle.claims.flatMap((claim) => claim.subjects.map((seller) => seller.toLowerCase())),
  )].sort();
  if (sellerScope != null && !allSellers.includes(sellerScope)) {
    throw new Error(`${sellerScope}: seller is not approved`);
  }
  const selectedSellers = sellerScope == null ? allSellers : [sellerScope];

  const quote = approveCostQuote(
    JSON.parse(await readFile(resolve(value("--cost-quote")), "utf8")),
    value("--approve-cost-digest"),
    { counts: { sellerProofs: selectedSellers.length }, seller: sellerScope },
  );
  const proofPlanSha256 = await sha256File(planPath);
  if (quote.body.sources.proofPlanSha256 !== proofPlanSha256
      || quote.body.sources.proofBundleSha256 !== sha256(canonicalJson(bundle))) {
    throw new Error("approved quote source digests do not match the requested bundle and plan");
  }

  const attestation = JSON.parse(await readFile(guestAttestationPath, "utf8"));
  const guest = await validateGuestAttestation(attestation, sellerElf);
  const guestAttestationSha256 = await sha256File(guestAttestationPath);

  await mkdir(artifactDir, { recursive: true });
  const indexedPlan = await shardProofPlan(planPath, join(artifactDir, "plan-shards"), bundle);
  const entries = indexedPlan.entries.map((entry, index) => {
    const approved = claimById.get(entry.claim.claimId.toLowerCase());
    if (!approved) throw new Error(`${entry.claim.claimId}: missing approved claim`);
    return {
      claim: approved,
      kind: approved.type === "P0_RECIPROCAL" ? "reciprocal" : "closed-loop",
      witnessPath: join(witnessDir, `${String(index).padStart(3, "0")}-${approved.claimId.slice(2, 18)}.witness.json`),
    };
  });
  for (const entry of entries) {
    if (!await isNonemptyFile(entry.witnessPath)) {
      throw new Error(`${entry.claim.claimId}: validated witness is missing at ${entry.witnessPath}`);
    }
  }
  const evidenceBySeller = sellerEvidenceByAddress(bundle, entries);

  const networkArgs = [
    "--production", "--confirm-production",
    "--max-price-per-pgu-wei", quote.body.networkLimits.maxPricePerPguWei,
    "--proof-timeout-secs", String(quote.body.networkLimits.proofTimeoutSeconds),
    "--auction-timeout-secs", String(quote.body.networkLimits.auctionTimeoutSeconds),
  ];
  const runConfigPath = join(artifactDir, "runs", `${sellerScope ?? "full"}.json`);
  await mkdir(dirname(runConfigPath), { recursive: true });
  const runConfig = {
    version: 2,
    kind: "antseed-wash-trading-production-run",
    proofArchitecture: "direct-seller-v1",
    scope: { seller: sellerScope },
    sellers: selectedSellers,
    claimCount: new Set(selectedSellers.flatMap(
      (seller) => [evidenceBySeller.get(seller).claim.claimId],
    )).size,
    sources: {
      proofBundleSha256: sha256(await readFile(bundlePath)),
      proofPlanSha256,
      guestAttestationSha256,
      sellerElfSha256: guest.elfSha256,
      quoteDigest: quote.digest,
    },
    sellerProgramVKey: guest.programVKey,
    networkLimits: quote.body.networkLimits,
  };
  await writeStableRunConfig(runConfigPath, runConfig, {
    allowReplace: preflightOnly,
    allowQuoteRotation: !preflightOnly,
  });

  await run("cargo", [
    "build", "--release", "-p", "loop-host", "--features", "sp1",
    "--bin", "wash-trading-prove-seller",
  ], root);
  await preflightSellerInputs({
    prover: resolve(root, "target/release/wash-trading-prove-seller"),
    sellers: selectedSellers,
    evidenceBySeller,
    period: bundle.period,
    artifactDir: join(artifactDir, "native-preflight"),
    concurrency: sellerConcurrency,
    totalVolumeWitnessDir,
  });
  if (preflightOnly) {
    console.log(`WASH_TRADING_PRODUCTION_PREFLIGHT=${JSON.stringify({
      proofArchitecture: "direct-seller-v1",
      sellerCount: selectedSellers.length,
      sellerProgramVKey: guest.programVKey,
      runConfigPath,
      proverNetworkSubmitted: false,
    })}`);
    return;
  }

  const sellerArtifactDir = join(artifactDir, "sellers");
  const sellerWitnessDir = join(artifactDir, "seller-witnesses");
  await mkdir(sellerArtifactDir, { recursive: true });
  await mkdir(sellerWitnessDir, { recursive: true });
  const prover = resolve(root, "target/release/wash-trading-prove-seller");
  const sellerProofs = await mapWithConcurrency(selectedSellers, sellerConcurrency, async (seller, index) => {
    const output = join(sellerArtifactDir, `${seller}.json`);
    const evidence = evidenceBySeller.get(seller);
    const existing = await loadCurrentSellerProof(output, seller, bundle.period, 1, guest.programVKey);
    if (existing) {
      console.error(`[${index + 1}/${selectedSellers.length}] reusing paid direct seller proof ${seller}`);
      return summarizeSellerProof(existing, output);
    }
    const command = [
      ...networkArgs,
      "--seller", seller,
      "--seller-elf", sellerElf,
      "--output", output,
      "--seller-witness", join(sellerWitnessDir, `${seller}.json`),
      "--request-checkpoint", output.replace(/\.json$/, ".request.json"),
    ];
    if (totalVolumeWitnessDir) command.push("--total-volume-witness", join(totalVolumeWitnessDir, `${seller}.json`));
    command.push("--evidence", `${evidence.kind}:${evidence.witnessPath}`);
    console.error(`[${index + 1}/${selectedSellers.length}] requesting paid direct seller proof ${seller}`);
    await run(prover, command, root);
    const proof = await loadCurrentSellerProof(output, seller, bundle.period, 1, guest.programVKey);
    if (!proof) throw new Error(`${seller}: paid direct seller artifact failed validation`);
    return summarizeSellerProof(proof, output);
  });

  const totalProvenWashVolumeRaw = sellerProofs
    .reduce((total, proof) => total + BigInt(proof.provenWashVolumeRaw), 0n)
    .toString();
  if (sellerScope == null && totalProvenWashVolumeRaw !== indexedPlan.approved.uniqueSettlementVolumeRaw) {
    throw new Error(`direct seller total ${totalProvenWashVolumeRaw} differs from approved ${indexedPlan.approved.uniqueSettlementVolumeRaw}`);
  }
  const summary = {
    version: 2,
    kind: "antseed-wash-trading-production-summary",
    proofArchitecture: "direct-seller-v1",
    securityMode: "production",
    scope: { seller: sellerScope },
    quoteDigest: quote.digest,
    runConfigPath,
    sellerProofCount: sellerProofs.length,
    totalSellerVolumeRaw: sellerProofs.reduce((total, proof) => total + BigInt(proof.totalSellerVolumeRaw), 0n).toString(),
    totalProvenWashVolumeRaw,
    approvedUniqueSettlementVolumeRaw: indexedPlan.approved.uniqueSettlementVolumeRaw,
    sellerProofs,
  };
  const summaryPath = join(artifactDir, `summary-${sellerScope ?? "full"}.json`);
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`WASH_TRADING_PRODUCTION_SUMMARY=${JSON.stringify(summary)}`);
}

async function validateGuestAttestation(attestation, sellerElf) {
  if (attestation?.version !== 4 || attestation.kind !== "antseed-sp1-program-build-attestation"
      || attestation.sp1Version !== "6.1.0" || attestation.reproducible !== true
      || Object.keys(attestation.guests ?? {}).length !== 1) {
    throw new Error("invalid direct seller guest build attestation");
  }
  const guest = attestation.guests?.seller;
  if (!/^0x[0-9a-f]{64}$/i.test(guest?.programVKey ?? "")
      || !/^0x[0-9a-f]{64}$/i.test(guest?.elfSha256 ?? "")) {
    throw new Error("seller: invalid guest attestation entry");
  }
  const elfSha256 = await sha256File(sellerElf);
  if (elfSha256 !== guest.elfSha256) throw new Error("seller: ELF digest differs from reproducible attestation");
  return { programVKey: guest.programVKey.toLowerCase(), elfSha256 };
}

export async function loadCurrentSellerProof(path, seller, period, claimCount, sellerProgramVKey) {
  if (!await isNonemptyFile(path)) return null;
  const artifact = JSON.parse(await readFile(path, "utf8"));
  if (artifact?.version !== 3 || artifact.kind !== "antseed-wash-trading-seller-proof"
      || artifact.proofArchitecture !== "direct-seller-v1"
      || artifact.securityMode !== "production" || artifact.seller?.toLowerCase() !== seller
      || claimCount !== 1 || artifact.claimCount !== 1
      || artifact.evidenceFormat !== "single-bundle-v1"
      || !Array.isArray(artifact.sourceClaimIds) || artifact.sourceClaimIds.length !== 1
      || artifact.periodStartBlock !== period.startBlock
      || artifact.periodEndBlock !== period.endBlockExclusive - 1
      || artifact.sellerProgramVKey?.toLowerCase() !== sellerProgramVKey.toLowerCase()
      || artifact.proved !== true || artifact.verified !== true
      || !/^[1-9][0-9]*$/.test(artifact.totalSellerVolumeRaw ?? "")
      || !/^0x(?:[0-9a-f]{2})+$/i.test(artifact.publicValues ?? "")
      || !/^0x(?:[0-9a-f]{2})+$/i.test(artifact.proofBytes ?? "")
      || artifact.proofBytes === "0x" || artifact.requestId == null) {
    throw new Error(`${seller}: stale or invalid paid direct seller checkpoint`);
  }
  return artifact;
}

export async function preflightSellerInputs({
  prover, sellers, evidenceBySeller, period, artifactDir, concurrency = 1, totalVolumeWitnessDir = null, runVerifier = run,
}) {
  for (const seller of sellers) singleEvidenceEntry(evidenceBySeller.get(seller), seller);
  await mkdir(artifactDir, { recursive: true });
  const failures = [];
  const results = await mapWithConcurrency(sellers, concurrency, async (seller) => {
    try {
      const evidence = evidenceBySeller.get(seller);
      const output = join(artifactDir, `${seller}.json`);
      const command = ["--witness-only", "--seller", seller, "--output", output];
      if (totalVolumeWitnessDir) command.push("--total-volume-witness", join(totalVolumeWitnessDir, `${seller}.json`));
      command.push("--evidence", `${evidence.kind}:${evidence.witnessPath}`);
      await runVerifier(prover, command, root);
      const artifact = JSON.parse(await readFile(output, "utf8"));
      if (artifact.kind !== "antseed-wash-trading-seller-witness" || artifact.verified !== true
          || artifact.proverNetworkSubmitted !== false || artifact.seller?.toLowerCase() !== seller
          || artifact.periodStartBlock !== period.startBlock || artifact.periodEndBlock !== period.endBlockExclusive - 1
          || artifact.claimCount !== 1 || artifact.evidenceFormat !== "single-bundle-v1"
          || !Array.isArray(artifact.sourceClaimIds) || artifact.sourceClaimIds.length !== 1
          || !/^[1-9][0-9]*$/.test(artifact.totalSellerVolumeRaw ?? "")) {
        throw new Error("invalid native seller preflight artifact");
      }
      return { seller, provenWashVolumeRaw: artifact.provenWashVolumeRaw, totalSellerVolumeRaw: artifact.totalSellerVolumeRaw };
    } catch (error) {
      failures.push({ seller, error: error.message });
      return null;
    }
  });
  const summary = { complete: failures.length === 0, proverNetworkSubmitted: false, sellers: results.filter(Boolean), failures };
  await writeFile(join(artifactDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  if (failures.length > 0) {
    throw new Error(`${failures.length} seller inputs failed native preflight; no paid requests submitted: ${failures.map(failure => failure.seller).join(", ")}`);
  }
  return summary;
}

async function summarizeSellerProof(proof, path) {
  return {
    seller: proof.seller.toLowerCase(),
    path,
    claimCount: proof.claimCount,
    provenWashVolumeRaw: proof.provenWashVolumeRaw,
    totalSellerVolumeRaw: proof.totalSellerVolumeRaw,
    blockReferenceCount: proof.blockReferenceCount,
    sha256: await sha256File(path),
  };
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
  try {
    const details = await stat(path);
    return details.isFile() && details.size > 0;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function validateBundle(bundle) {
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle"
      || bundle.chainId !== 8_453 || !Array.isArray(bundle.claims) || bundle.claims.length === 0) {
    throw new Error("invalid approved proof bundle");
  }
}

function positiveInteger(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

function run(command, commandArgs, cwd) {
  console.error(`> ${command} ${commandArgs.join(" ")}`);
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, { cwd, stdio: "inherit", env: process.env });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${code}`)));
  });
}

function sha256(value) {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

if (process.argv[1] && basename(process.argv[1]) === basename(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error(error.stack ?? error.message);
    process.exitCode = 1;
  });
}
