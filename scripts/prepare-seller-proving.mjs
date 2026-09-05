import { createWriteStream } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256, validateArtifact, validateManifest } from "./replay-seller-development.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function validateEstimate(estimate, baseline) {
  for (const field of ["version", "kind", "proofArchitecture", "alphaReturnBps", "seller",
    "sellerProgramVKey", "periodStartBlock", "periodEndBlock", "provenWashVolumeRaw",
    "totalSellerVolumeRaw", "evidenceDigest", "publicValues", "blockAuthenticationRoot",
    "blockReferenceCount", "instructionCount"]) {
    if (estimate[field] !== baseline[field]) throw new Error(`estimate changed ${field}`);
  }
  if (estimate.securityMode !== "development" || estimate.proved !== false
    || estimate.verified !== true || estimate.proverNetworkSubmitted !== false
    || estimate.proofBytes !== "0x" || estimate.requestId != null) throw new Error("expected execution-only estimate");
  if (typeof estimate.proverGasUnits !== "string" || !/^[1-9][0-9]*$/.test(estimate.proverGasUnits)) {
    throw new Error("missing positive PGU measurement");
  }
}

export function calculateBudget(gasUnits, pricePerPguWei, baseFeeWei, balanceWei) {
  const positive = (value) => {
    if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) throw new Error("expected positive decimal amount");
    return BigInt(value);
  };
  const nonnegative = (value) => {
    if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("expected nonnegative decimal amount");
    return BigInt(value);
  };
  if (!Array.isArray(gasUnits) || gasUnits.length === 0) throw new Error("empty estimate batch");
  const totalPgu = gasUnits.reduce((sum, value) => sum + positive(value), 0n);
  const computation = totalPgu * positive(pricePerPguWei);
  const baseFees = BigInt(gasUnits.length) * nonnegative(baseFeeWei);
  const total = computation + baseFees;
  const balance = nonnegative(balanceWei);
  return { proofCount: gasUnits.length, totalProverGasUnits: totalPgu.toString(),
    baseFeesWei: baseFees.toString(), computationAtPriceCapWei: computation.toString(),
    totalAtPriceCapWei: total.toString(), balanceWei,
    sufficientAtPriceCap: balance >= total,
    shortfallWei: (total > balance ? total - balance : 0n).toString() };
}

async function run(command, args, logPath) {
  const log = createWriteStream(logPath);
  const environment = { ...process.env };
  delete environment.NETWORK_PRIVATE_KEY;
  delete environment.BACKFILL_PRIVATE_KEY;
  delete environment.ANVIL_PRIVATE_KEY;
  delete environment.SP1_PROVER;
  await new Promise((accept, reject) => {
    const child = spawn(command, args, { cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.pipe(log, { end: false });
    child.stderr.pipe(log, { end: false });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? accept() : reject(new Error(`exit ${code}; see ${logPath}`)));
  }).finally(() => new Promise((accept) => log.end(accept)));
}

async function main() {
  const [manifestPath, baselinePath, proverPath, outputPath] = process.argv.slice(2);
  if (!outputPath || process.argv.length !== 6) throw new Error("usage: prepare-seller-proving.mjs manifest.json replay-summary.json prover output-directory");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  validateManifest(manifest);
  const baseline = JSON.parse(await readFile(baselinePath, "utf8"));
  const manifestSha256 = await sha256(manifestPath);
  if (!baseline.complete || baseline.securityMode !== "development" || baseline.manifestSha256 !== manifestSha256
    || baseline.results.length !== manifest.sellers.length || baseline.results.some((result) => !result.success)
    || new Set(baseline.results.map((result) => result.seller)).size !== manifest.sellers.length) throw new Error("baseline replay is incomplete or mismatched");
  const attestation = JSON.parse(await readFile(manifest.guestAttestation, "utf8"));
  const guestElfSha256 = await sha256(manifest.sellerElf);
  if (!attestation.reproducible || attestation.guests?.seller?.programVKey !== manifest.sellerProgramVKey
    || attestation.guests.seller.elfSha256 !== guestElfSha256
    || baseline.guestElfSha256 !== guestElfSha256) throw new Error("guest attestation mismatch");
  const sources = Object.entries(attestation.verifiedGuestSourceFiles ?? {});
  if (!sources.length) throw new Error("missing guest source attestation");
  for (const [path, hash] of sources) if (await sha256(join(root, path)) !== hash) throw new Error(`guest source drift: ${path}`);
  const provenance = { manifestSha256, baselineSha256: await sha256(baselinePath),
    proverSha256: await sha256(proverPath), guestElfSha256,
    guestAttestationSha256: await sha256(manifest.guestAttestation) };
  const output = resolve(outputPath);
  await mkdir(join(output, "estimates"), { recursive: true });
  await mkdir(join(output, "logs"), { recursive: true });
  const summaryPath = join(output, "summary.json");
  let summary;
  try {
    summary = JSON.parse(await readFile(summaryPath, "utf8"));
    if (summary.kind !== "seller-proving-execution-preflight" || JSON.stringify(summary.provenance) !== JSON.stringify(provenance)) throw new Error("resume provenance mismatch");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    summary = { version: 1, kind: "seller-proving-execution-preflight", provenance,
      expectedSellerCount: manifest.sellers.length, sellerProgramVKey: manifest.sellerProgramVKey,
      aip4Compliant: false, productionReady: false, proverNetworkSubmitted: false,
      startedAt: new Date().toISOString(), complete: false, results: [] };
  }
  let writes = Promise.resolve();
  const persist = () => {
    const content = `${JSON.stringify(summary, null, 2)}\n`;
    writes = writes.then(async () => { await writeFile(`${summaryPath}.tmp`, content); await rename(`${summaryPath}.tmp`, summaryPath); });
    return writes;
  };
  await persist();
  const sellers = [...manifest.sellers].sort((first, second) => {
    const firstResult = baseline.results.find((result) => result.seller === first.seller);
    const secondResult = baseline.results.find((result) => result.seller === second.seller);
    return firstResult.instructionCount - secondResult.instructionCount;
  });
  let next = 0;
  const worker = async () => {
    while (next < sellers.length) {
      const seller = sellers[next++];
      const artifactPath = join(output, "estimates", `${seller.seller}.json`);
      try {
        const previous = baseline.results.find((result) => result.seller === seller.seller);
        if (!previous || await sha256(previous.artifact) !== previous.artifactSha256) throw new Error("baseline artifact mismatch");
        const artifact = JSON.parse(await readFile(previous.artifact, "utf8"));
        validateArtifact(artifact, seller, manifest);
        const inputs = seller.sellerInput ? [seller.sellerInput] : [seller.evidencePath, seller.totalVolumePath];
        if (Object.keys(previous.inputSha256).length !== inputs.length) throw new Error("baseline input set mismatch");
        const checkInputs = async () => {
          for (const path of inputs) if (await sha256(path) !== previous.inputSha256[path]) throw new Error(`input changed: ${path}`);
        };
        await checkInputs();
        const completed = summary.results.find((result) => result.seller === seller.seller && result.success);
        if (completed) {
          if (await sha256(artifactPath) !== completed.artifactSha256) throw new Error("resume artifact changed");
          validateEstimate(JSON.parse(await readFile(artifactPath, "utf8")), artifact);
          continue;
        }
        console.log(`START ${seller.label ?? seller.seller}`);
        const args = ["--execute-only", "--seller", seller.seller, "--seller-elf", manifest.sellerElf, "--output", artifactPath];
        if (seller.sellerInput) args.push("--seller-input", seller.sellerInput);
        else args.push("--evidence", `${seller.evidenceKind}:${seller.evidencePath}`, "--total-volume-witness", seller.totalVolumePath);
        await run(resolve(proverPath), args, join(output, "logs", `${seller.seller}.log`));
        await checkInputs();
        const estimate = JSON.parse(await readFile(artifactPath, "utf8"));
        validateEstimate(estimate, artifact);
        summary.results = summary.results.filter((result) => result.seller !== seller.seller);
        summary.results.push({ seller: seller.seller, label: seller.label, success: true, artifact: artifactPath,
          artifactSha256: await sha256(artifactPath), inputSha256: previous.inputSha256,
          proverGasUnits: estimate.proverGasUnits, instructionCount: estimate.instructionCount,
          provenWashVolumeRaw: estimate.provenWashVolumeRaw, totalSellerVolumeRaw: estimate.totalSellerVolumeRaw });
        console.log(`PASS ${seller.label ?? seller.seller}: ${estimate.proverGasUnits} PGU`);
      } catch (error) {
        summary.results = summary.results.filter((result) => result.seller !== seller.seller);
        summary.results.push({ seller: seller.seller, success: false, error: error.message });
        console.error(`FAIL ${seller.label ?? seller.seller}: ${error.message}`);
      }
      await persist();
    }
  };
  await Promise.all([worker(), worker()]);
  summary.complete = summary.results.length === sellers.length && summary.results.every((result) => result.success);
  summary.totalProverGasUnits = summary.results.filter((result) => result.success).reduce((sum, result) => sum + BigInt(result.proverGasUnits), 0n).toString();
  summary.finishedAt = new Date().toISOString();
  await persist();
  console.log(`SUMMARY ${summaryPath}: complete=${summary.complete}, PGU=${summary.totalProverGasUnits}`);
  if (!summary.complete) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error); process.exitCode = 1; });
}
