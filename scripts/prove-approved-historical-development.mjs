#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mapWithConcurrency } from "./generate-approved-development-proofs.mjs";

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
  const elfPaths = {
    "closed-loop": resolve(value("--closed-loop-elf") ?? guestElf("closed-loop")),
    reciprocal: resolve(value("--reciprocal-elf") ?? guestElf("reciprocal")),
    aggregator: resolve(value("--aggregator-elf") ?? guestElf("aggregator")),
  };
  const guestAttestationPath = value("--guest-attestation")?.trim();
  const childConcurrency = positiveInteger(
    value("--child-concurrency") ?? process.env.WASH_TRADING_CHILD_CONCURRENCY ?? "2",
    "--child-concurrency",
  );
  const sellerConcurrency = positiveInteger(
    value("--seller-concurrency") ?? process.env.WASH_TRADING_SELLER_CONCURRENCY ?? "1",
    "--seller-concurrency",
  );
  const toolchain = process.env.RUSTUP_TOOLCHAIN ?? "1.94";
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle") {
    throw new Error("invalid approved proof bundle");
  }
  const approvedClaims = new Map(bundle.claims.map((claim) => [claim.claimId.toLowerCase(), claim]));
  const witnessEntries = await loadWitnessEntries(witnessDir, approvedClaims, bundle.period);
  if (witnessEntries.length !== bundle.claims.length) {
    throw new Error(`expected ${bundle.claims.length} witnesses, found ${witnessEntries.length}`);
  }

  let guests = null;
  if (guestAttestationPath) {
    guests = await validateGuestAttestation(
      JSON.parse(await readFile(resolve(guestAttestationPath), "utf8")),
      elfPaths,
    );
  } else {
    for (const guest of ["closed-loop", "reciprocal", "aggregator"]) {
      await run("cargo", ["prove", "build"], resolve(root, "program", guest), { RUSTUP_TOOLCHAIN: "succinct" });
    }
  }
  for (const path of Object.values(elfPaths)) {
    if (!await isNonemptyFile(path)) throw new Error(`guest ELF is missing: ${path}`);
  }
  await run("cargo", [
    "build", "--release", "-p", "loop-host", "--features", "sp1",
    "--bin", "wash-trading-prove-child",
    "--bin", "wash-trading-aggregate",
  ], root, { RUSTUP_TOOLCHAIN: toolchain });

  const childArtifactDir = join(artifactDir, "children");
  await mkdir(childArtifactDir, { recursive: true });
  const childProver = resolve(root, "target/release/wash-trading-prove-child");
  const pending = [];
  for (const entry of witnessEntries) {
    entry.proofPath = join(
      childArtifactDir,
      `${String(entry.index).padStart(3, "0")}-${entry.claimId}.proof.bin`,
    );
    if (await loadCurrentChildProof(entry, guests)) {
      console.error(`[${entry.index + 1}/${witnessEntries.length}] reusing ${entry.proofPath}`);
    } else {
      pending.push(entry);
    }
  }
  await mapWithConcurrency(pending, childConcurrency, async (entry) => {
    console.error(`[${entry.index + 1}/${witnessEntries.length}] proving ${entry.kind} child`);
    await run(childProver, [
      "--development",
      "--index", String(entry.index),
      "--kind", entry.kind,
      "--witness", entry.witnessPath,
      "--closed-loop-elf", elfPaths["closed-loop"],
      "--reciprocal-elf", elfPaths.reciprocal,
      "--output-dir", childArtifactDir,
    ], root);
  });
  for (const entry of witnessEntries) {
    if (!await loadCurrentChildProof(entry, guests)) throw new Error(`${entry.claimId}: child proof is missing or stale`);
  }

  const approvedSellers = [...new Set(
    bundle.claims.flatMap((claim) => claim.subjects.map((value) => value.toLowerCase())),
  )].sort();
  const sellerArtifactDir = join(artifactDir, "sellers");
  await mkdir(sellerArtifactDir, { recursive: true });
  const sellerProofs = await mapWithConcurrency(approvedSellers, sellerConcurrency, async (seller, index) => {
    const sellerPath = join(sellerArtifactDir, `${seller}.json`);
    const expectedChildCount = bundle.claims.filter((claim) => claim.subjects
      .some((subject) => subject.toLowerCase() === seller)).length;
    const existing = await loadCurrentSellerProof(sellerPath, seller, bundle.period, expectedChildCount, guests);
    if (existing) {
      console.error(`[${index + 1}/${approvedSellers.length}] reusing seller ${seller}`);
      return summarizeSellerProof(existing, sellerPath);
    }
    const aggregateArgs = [
      "run", "--release", "-p", "loop-host", "--features", "sp1",
      "--bin", "wash-trading-aggregate", "--",
      "--development",
      "--seller", seller,
      "--reuse-child-proofs",
      "--aggregator-elf", elfPaths.aggregator,
      "--closed-loop-elf", elfPaths["closed-loop"],
      "--reciprocal-elf", elfPaths.reciprocal,
      "--child-artifact-dir", childArtifactDir,
      "--output", sellerPath,
    ];
    for (const entry of witnessEntries) aggregateArgs.push("--child", `${entry.kind}:${entry.witnessPath}`);
    console.error(`[${index + 1}/${approvedSellers.length}] aggregating seller ${seller}`);
    await run("cargo", aggregateArgs, root, { RUSTUP_TOOLCHAIN: toolchain }, ["ignore", "ignore", "inherit"]);
    const sellerProof = JSON.parse(await readFile(sellerPath, "utf8"));
    if (!isCurrentSellerProof(sellerProof, seller, bundle.period, expectedChildCount, guests)) {
      throw new Error(`${seller}: invalid seller proof artifact`);
    }
    return summarizeSellerProof(sellerProof, sellerPath);
  });
  const summary = {
    version: 1,
    kind: "antseed-wash-trading-approved-historical-development-summary",
    securityMode: "development",
    period: bundle.period,
    approvedClaimCount: bundle.claims.length,
    approvedSellerCount: approvedSellers.length,
    sellerProofCount: sellerProofs.length,
    guests,
    totalProvenWashVolumeRaw: sellerProofs
      .reduce((total, proof) => total + BigInt(proof.provenWashVolumeRaw), 0n)
      .toString(),
    sellerProofs,
  };
  const summaryPath = join(artifactDir, "historical-summary.json");
  await writeFile(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`WASH_TRADING_APPROVED_HISTORICAL_DEVELOPMENT_SUMMARY=${JSON.stringify(summary)}`);
}

async function loadWitnessEntries(artifactDir, approvedClaims, period) {
  const names = (await readdir(artifactDir))
    .filter((name) => /^\d{3}-[0-9a-f]{16}\.witness\.json\.cache\.json$/.test(name))
    .sort();
  const entries = [];
  const seen = new Set();
  for (const name of names) {
    const index = Number(name.slice(0, 3));
    const witnessPath = join(artifactDir, name.slice(0, -".cache.json".length));
    const metadata = JSON.parse(await readFile(join(artifactDir, name), "utf8"));
    const claimId = metadata.sourceClaimId?.toLowerCase();
    const approved = approvedClaims.get(claimId);
    if (!approved || seen.has(claimId)) throw new Error(`${name}: unexpected or duplicate claim`);
    if (metadata.periodStartBlock !== period.startBlock
        || metadata.periodEndBlock !== period.endBlockExclusive - 1
        || metadata.claimType !== approved.type
        || !await isNonemptyFile(witnessPath)) {
      throw new Error(`${name}: stale witness metadata`);
    }
    if (index !== entries.length) throw new Error(`${name}: non-contiguous witness index`);
    seen.add(claimId);
    entries.push({
      index,
      claimId,
      witnessPath,
      kind: approved.type === "P0_RECIPROCAL" ? "reciprocal" : "closed-loop",
    });
  }
  return entries;
}

function guestElf(guest) {
  return resolve(root, `program/${guest}/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/${guest}-guest`);
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

async function validateGuestAttestation(attestation, elfPaths) {
  if (attestation?.version !== 3 || attestation.kind !== "antseed-sp1-program-build-attestation"
      || attestation.reproducible !== true) {
    throw new Error("invalid reproducible guest build attestation");
  }
  const guests = {};
  for (const guest of ["closed-loop", "reciprocal", "aggregator"]) {
    const expected = attestation.guests?.[guest];
    if (!expected || !/^0x[0-9a-f]{64}$/i.test(expected.programVKey ?? "")
        || !/^0x[0-9a-f]{64}$/i.test(expected.elfSha256 ?? "")) {
      throw new Error(`${guest}: invalid guest attestation entry`);
    }
    const actualElfSha256 = sha256(await readFile(elfPaths[guest]));
    if (actualElfSha256 !== expected.elfSha256) {
      throw new Error(`${guest}: ELF digest differs from reproducible attestation`);
    }
    guests[guest] = {
      programVKey: expected.programVKey.toLowerCase(),
      elfSha256: actualElfSha256,
    };
  }
  return guests;
}

async function loadCurrentChildProof(entry, guests) {
  if (!await isNonemptyFile(entry.proofPath)) return null;
  try {
    const artifact = JSON.parse(await readFile(entry.proofPath.replace(/\.bin$/, ".json"), "utf8"));
    const expectedVkey = guests?.[entry.kind]?.programVKey;
    return artifact?.version === 1
      && artifact.kind === "antseed-wash-trading-child-proof"
      && artifact.securityMode === "development"
      && artifact.childKind === entry.kind
      && artifact.sourceClaimId?.toLowerCase() === entry.claimId
      && (expectedVkey == null || artifact.programVKey?.toLowerCase() === expectedVkey)
      ? artifact
      : null;
  } catch (error) {
    if (error.code === "ENOENT" || error instanceof SyntaxError) return null;
    throw error;
  }
}

async function loadCurrentSellerProof(path, seller, period, childCount, guests) {
  try {
    const artifact = JSON.parse(await readFile(path, "utf8"));
    return isCurrentSellerProof(artifact, seller, period, childCount, guests) ? artifact : null;
  } catch (error) {
    if (error.code === "ENOENT" || error instanceof SyntaxError) return null;
    throw error;
  }
}

function isCurrentSellerProof(artifact, seller, period, childCount, guests) {
  return artifact?.version === 2
    && artifact.kind === "antseed-wash-trading-seller-proof"
    && artifact.securityMode === "development"
    && artifact.seller?.toLowerCase() === seller
    && artifact.periodStartBlock === period.startBlock
    && artifact.periodEndBlock === period.endBlockExclusive - 1
    && artifact.childCount === childCount
    && (guests == null
      || (artifact.closedLoopProgramVKey?.toLowerCase() === guests["closed-loop"].programVKey
        && artifact.reciprocalProgramVKey?.toLowerCase() === guests.reciprocal.programVKey
        && artifact.aggregatorProgramVKey?.toLowerCase() === guests.aggregator.programVKey))
    && !Object.hasOwn(artifact, "agentId")
    && !Object.hasOwn(artifact, "settledVolumeRaw");
}

async function summarizeSellerProof(artifact, path) {
  return {
    seller: artifact.seller.toLowerCase(),
    path,
    sha256: sha256(await readFile(path)),
    childCount: artifact.childCount,
    provenWashVolumeRaw: artifact.provenWashVolumeRaw,
    blockReferenceCount: artifact.blockReferenceCount,
  };
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

function run(command, args, cwd, extraEnv = {}, stdio = "inherit") {
  console.error(`> ${command} ${args.join(" ")}`);
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...extraEnv },
      stdio,
    });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${code}`)));
  });
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
