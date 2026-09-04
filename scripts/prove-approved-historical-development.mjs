#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mapWithConcurrency } from "./generate-approved-development-proofs.mjs";
import { sellerEvidenceByAddress } from "./seller-evidence.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const index = args.indexOf(flag);
    return index < 0 ? null : args[index + 1];
  };
  const bundlePath = resolve(required(value("--bundle"), "--bundle"));
  const artifactDir = resolve(value("--artifact-dir") ?? "out/unified-historical/development");
  const witnessDir = resolve(value("--witness-dir") ?? artifactDir);
  const sellerElf = resolve(value("--seller-elf") ?? guestElf());
  const guestAttestationPath = value("--guest-attestation")?.trim();
  const sellerConcurrency = positiveInteger(
    value("--seller-concurrency") ?? process.env.WASH_TRADING_SELLER_CONCURRENCY ?? "1",
    "--seller-concurrency",
  );
  const mode = args.includes("--witness-only")
    ? "witness-only"
    : args.includes("--execute-only") ? "execute-only" : "development";
  const selectedModes = ["--witness-only", "--execute-only"].filter((flag) => args.includes(flag));
  if (selectedModes.length > 1) throw new Error("development modes are mutually exclusive");

  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  validateBundle(bundle);
  const approvedClaims = new Map(bundle.claims.map((claim) => [claim.claimId.toLowerCase(), claim]));
  const entries = await loadWitnessEntries(witnessDir, approvedClaims, bundle.period);
  if (entries.length !== bundle.claims.length) {
    throw new Error(`expected ${bundle.claims.length} witnesses, found ${entries.length}`);
  }
  const evidenceBySeller = sellerEvidenceByAddress(bundle, entries);
  const sellers = [...evidenceBySeller.keys()].sort();

  let sellerProgramVKey = null;
  if (mode !== "witness-only") {
    if (guestAttestationPath) {
      sellerProgramVKey = await validateGuestAttestation(
        JSON.parse(await readFile(resolve(guestAttestationPath), "utf8")),
        sellerElf,
      );
    } else {
      await run("cargo", ["prove", "build", "--workspace-directory", "../.."], resolve(root, "program/seller"), {
        RUSTUP_TOOLCHAIN: "succinct",
      });
    }
    if (!await isNonemptyFile(sellerElf)) throw new Error(`seller guest ELF is missing: ${sellerElf}`);
  }
  await run("cargo", [
    "build", "--release", "-p", "loop-host", "--features", "sp1", "--bin", "wash-trading-prove-seller",
  ], root, { RUSTUP_TOOLCHAIN: process.env.RUSTUP_TOOLCHAIN ?? "1.94" });

  const sellerDir = join(artifactDir, "sellers");
  const sellerWitnessDir = join(artifactDir, "seller-witnesses");
  await mkdir(sellerDir, { recursive: true });
  await mkdir(sellerWitnessDir, { recursive: true });
  const prover = resolve(root, "target/release/wash-trading-prove-seller");
  const sellerFailures = [];
  const results = await mapWithConcurrency(sellers, sellerConcurrency, async (seller, index) => {
    try {
      const evidence = evidenceBySeller.get(seller);
      const output = join(sellerDir, `${seller}.json`);
      const existing = await loadCurrentArtifact(output, seller, bundle.period, 1, mode, sellerProgramVKey);
      if (existing) {
        console.error(`[${index + 1}/${sellers.length}] reusing direct seller ${mode} artifact ${seller}`);
        return summarize(existing, output);
      }
      const command = [
        `--${mode}`,
        "--seller", seller,
        "--output", output,
        "--seller-witness", join(sellerWitnessDir, `${seller}.json`),
      ];
      if (mode !== "witness-only") command.push("--seller-elf", sellerElf);
      command.push("--evidence", `${evidence.kind}:${evidence.witnessPath}`);
      console.error(`[${index + 1}/${sellers.length}] generating direct seller ${mode} artifact ${seller}`);
      await run(prover, command, root);
      const artifact = await loadCurrentArtifact(output, seller, bundle.period, 1, mode, sellerProgramVKey);
      if (!artifact) throw new Error(`${seller}: direct seller artifact was not written`);
      return summarize(artifact, output);
    } catch (error) {
      sellerFailures.push({ seller, error: error.message });
      console.error(`${seller}: ${error.message}`);
      return null;
    }
  });
  const sellerResults = results.filter(Boolean);

  const totalProvenWashVolumeRaw = sellerResults
    .reduce((total, seller) => total + BigInt(seller.provenWashVolumeRaw), 0n)
    .toString();
  const approvedTotal = approvedUniqueSettlementVolume(bundle);
  if (sellerFailures.length === 0 && totalProvenWashVolumeRaw !== approvedTotal) {
    throw new Error(`direct seller total ${totalProvenWashVolumeRaw} differs from approved ${approvedTotal}`);
  }
  const summary = {
    version: 2,
    kind: "antseed-wash-trading-approved-development-summary",
    proofArchitecture: "direct-seller-v1",
    securityMode: "development",
    mode,
    proverNetworkSubmitted: false,
    approvedClaimCount: bundle.claims.length,
    approvedSellerCount: sellers.length,
    sellerProgramVKey,
    sellerArtifactCount: sellerResults.length,
    sellerFailures,
    complete: sellerFailures.length === 0,
    totalSellerVolumeRaw: sellerResults.reduce((total, seller) => total + BigInt(seller.totalSellerVolumeRaw), 0n).toString(),
    totalProvenWashVolumeRaw,
    totalProvenWashVolumeUsdc: formatUsdc(totalProvenWashVolumeRaw),
    sellerResults,
  };
  await mkdir(artifactDir, { recursive: true });
  await writeFile(join(artifactDir, `summary-${mode}.json`), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`WASH_TRADING_APPROVED_DEVELOPMENT_SUMMARY=${JSON.stringify(summary)}`);
  if (sellerFailures.length > 0) process.exitCode = 1;
}

async function loadWitnessEntries(directory, approvedClaims, period) {
  const entries = [];
  const seen = new Set();
  for (const name of (await readdir(directory)).filter((name) => /^\d{3}-[0-9a-f]{16}\.witness\.json$/.test(name)).sort()) {
    const index = Number(name.slice(0, 3));
    const witnessPath = join(directory, name);
    const metadata = JSON.parse(await readFile(`${witnessPath}.cache.json`, "utf8"));
    const details = await stat(witnessPath);
    const claimId = String(metadata.sourceClaimId ?? "").toLowerCase();
    const approved = approvedClaims.get(claimId);
    if (!approved || seen.has(claimId)) throw new Error(`${name}: unapproved or duplicate witness`);
    if (metadata.version !== 1 || metadata.kind !== "antseed-wash-trading-witness-cache"
        || metadata.chainId !== 8_453 || metadata.claimType !== approved.type
        || metadata.periodStartBlock !== period.startBlock || metadata.periodEndBlock !== period.endBlockExclusive - 1
        || metadata.witnessSize !== details.size || metadata.witnessMtimeMs !== details.mtimeMs) {
      throw new Error(`${name}: witness period differs from approved bundle`);
    }
    if (index !== entries.length) throw new Error(`${name}: non-contiguous witness index`);
    seen.add(claimId);
    entries.push({
      claim: approved,
      kind: approved.type === "P0_RECIPROCAL" ? "reciprocal" : "closed-loop",
      witnessPath,
    });
  }
  return entries;
}

export async function loadCurrentArtifact(path, seller, period, claimCount, mode, sellerProgramVKey) {
  if (!await isNonemptyFile(path)) return null;
  const artifact = JSON.parse(await readFile(path, "utf8"));
  const expectedVersion = mode === "witness-only" ? 1 : 3;
  const expectedKind = mode === "witness-only"
    ? "antseed-wash-trading-seller-witness"
    : "antseed-wash-trading-seller-proof";
  if (artifact?.version !== expectedVersion || artifact.kind !== expectedKind
      || artifact.proofArchitecture !== "direct-seller-v1" || artifact.securityMode !== "development"
      || artifact.seller?.toLowerCase() !== seller || claimCount !== 1 || artifact.claimCount !== 1
      || artifact.evidenceFormat !== "single-bundle-v1"
      || !Array.isArray(artifact.sourceClaimIds) || artifact.sourceClaimIds.length !== 1
      || artifact.periodStartBlock !== period.startBlock || artifact.periodEndBlock !== period.endBlockExclusive - 1
      || artifact.verified !== true || artifact.proverNetworkSubmitted === true
      || !/^[1-9][0-9]*$/.test(artifact.totalSellerVolumeRaw ?? "")
      || (sellerProgramVKey != null && artifact.sellerProgramVKey?.toLowerCase() !== sellerProgramVKey)) {
    return null;
  }
  if (mode === "development" && (artifact.proved !== true || artifact.proofBytes === "0x")) return null;
  if (mode === "execute-only" && artifact.proved !== false) return null;
  return artifact;
}

async function summarize(artifact, path) {
  return {
    seller: artifact.seller.toLowerCase(),
    path,
    sha256: sha256(await readFile(path)),
    claimCount: artifact.claimCount,
    provenWashVolumeRaw: artifact.provenWashVolumeRaw,
    totalSellerVolumeRaw: artifact.totalSellerVolumeRaw,
    blockReferenceCount: artifact.blockReferenceCount,
    instructionCount: artifact.instructionCount ?? null,
  };
}

async function validateGuestAttestation(attestation, sellerElf) {
  if (attestation?.version !== 4 || attestation.kind !== "antseed-sp1-program-build-attestation"
      || attestation.sp1Version !== "6.1.0" || attestation.reproducible !== true
      || Object.keys(attestation.guests ?? {}).length !== 1) {
    throw new Error("invalid direct seller guest build attestation");
  }
  const seller = attestation.guests.seller;
  if (!/^0x[0-9a-f]{64}$/i.test(seller?.programVKey ?? "")
      || seller.elfSha256 !== sha256(await readFile(sellerElf))) {
    throw new Error("seller guest differs from reproducible attestation");
  }
  return seller.programVKey.toLowerCase();
}

function approvedUniqueSettlementVolume(bundle) {
  const settlements = new Map();
  for (const claim of bundle.claims) {
    for (const settlement of claim.settlements ?? claim.selectedSettlements ?? []) {
      const identity = `${settlement.transactionHash}:${settlement.logIndex ?? settlement.receiptLogIndex}`.toLowerCase();
      const amount = BigInt(settlement.amountRaw);
      const existing = settlements.get(identity);
      if (existing != null && existing !== amount) throw new Error(`${claim.claimId}: conflicting settlement amount`);
      settlements.set(identity, amount);
    }
  }
  if (settlements.size > 0) return [...settlements.values()].reduce((sum, amount) => sum + amount, 0n).toString();
  return bundle.claims.reduce((sum, claim) => sum + (claim.type === "P0_RECIPROCAL"
    ? BigInt(claim.metrics.volumeAToBRaw) + BigInt(claim.metrics.volumeBToARaw)
    : BigInt(claim.metrics.qualifiedVolumeRaw)), 0n).toString();
}

function validateBundle(bundle) {
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle"
      || bundle.chainId !== 8_453 || !Array.isArray(bundle.claims) || bundle.claims.length === 0) {
    throw new Error("invalid approved proof bundle");
  }
}

function formatUsdc(raw) {
  const value = BigInt(raw).toString().padStart(7, "0");
  return `${value.slice(0, -6)}.${value.slice(-6)}`;
}

function guestElf() {
  return resolve(root, "program/seller/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/seller-guest");
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

function run(command, commandArgs, cwd, extraEnv = {}) {
  console.error(`> ${command} ${commandArgs.join(" ")}`);
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, {
      cwd,
      env: { ...process.env, ...extraEnv },
      stdio: ["ignore", "inherit", "pipe"],
    });
    let recentStderr = "";
    child.stderr.on("data", (chunk) => {
      process.stderr.write(chunk);
      recentStderr = `${recentStderr}${chunk}`.slice(-4096);
    });
    child.on("error", reject);
    child.on("close", (code, signal) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${signal ?? code}\n${recentStderr.trim()}`)));
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch((error) => {
  console.error(error.stack ?? error.message);
  process.exitCode = 1;
});
