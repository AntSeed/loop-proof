import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256, validateArtifact, validateManifest } from "./replay-seller-development.mjs";
import { calculateBudget, validateEstimate } from "./prepare-seller-proving.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rpc = "https://rpc.mainnet.succinct.xyz";
const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
export const quoteDigest = (body) => `0x${createHash("sha256").update(JSON.stringify(body)).digest("hex")}`;

async function exists(path) {
  try { await readFile(path); return true; } catch (error) { if (error.code === "ENOENT") return false; throw error; }
}

async function commandJson(command, args, { paid = false } = {}) {
  const environment = { ...process.env, SP1_PROVER: "network", NETWORK_RPC_URL: rpc };
  delete environment.BACKFILL_PRIVATE_KEY;
  delete environment.ANVIL_PRIVATE_KEY;
  if (!paid) delete environment.NETWORK_PRIVATE_KEY;
  return new Promise((accept, reject) => {
    const child = spawn(command, args, { cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code !== 0) return reject(new Error(`command failed (${code}): ${stderr.replace(/https?:\/\/\S+/g, "[redacted endpoint]")}`));
      try { accept(JSON.parse(stdout)); } catch { reject(new Error("command returned invalid JSON")); }
    });
  });
}

export async function validateSources(body) {
  for (const [path, expected] of Object.entries(body.sourceSha256)) {
    if (await sha256(path) !== expected) throw new Error(`source changed: ${path}`);
  }
  const manifest = await readJson(body.manifestPath);
  validateManifest(manifest);
  const attestation = await readJson(manifest.guestAttestation);
  if (!attestation.reproducible || attestation.guests?.seller?.programVKey !== manifest.sellerProgramVKey
    || await sha256(manifest.sellerElf) !== attestation.guests.seller.elfSha256) throw new Error("guest attestation mismatch");
  const sources = Object.entries(attestation.verifiedGuestSourceFiles ?? {});
  if (!sources.length) throw new Error("missing guest source attestation");
  for (const [path, expected] of sources) if (await sha256(join(root, path)) !== expected) throw new Error(`guest source changed: ${path}`);
  const seller = manifest.sellers.find((item) => item.seller === body.seller);
  if (!seller) throw new Error("seller absent from frozen manifest");
  const baseline = await readJson(body.baselinePath);
  if (!baseline.complete || baseline.manifestSha256 !== await sha256(body.manifestPath)) throw new Error("baseline manifest mismatch");
  const previous = baseline.results.find((item) => item.seller === body.seller && item.success);
  if (!previous || await sha256(previous.artifact) !== previous.artifactSha256) throw new Error("baseline artifact mismatch");
  const artifact = await readJson(previous.artifact);
  validateArtifact(artifact, seller, manifest);
  const estimate = await readJson(body.estimatePath);
  validateEstimate(estimate, artifact);
  const inputPaths = seller.sellerInput ? [seller.sellerInput] : [seller.evidencePath, seller.totalVolumePath];
  for (const path of inputPaths) if (await sha256(path) !== previous.inputSha256[path]) throw new Error(`input changed: ${path}`);
  if (estimate.proverGasUnits !== body.proverGasUnits || manifest.sellerProgramVKey !== body.sellerProgramVKey) throw new Error("quote estimate mismatch");
  return { manifest, seller, estimate };
}

export function validateQuote(quote, approval, resuming = false, now = Date.now()) {
  if (quote?.body?.kind !== "frozen-seller-canary-approval" || quote.body.version !== 1
    || quote.digest !== quoteDigest(quote.body) || approval !== quote.digest) throw new Error("canary digest approval mismatch");
  if (!resuming && (!Number.isFinite(Date.parse(quote.body.expiresAt)) || Date.parse(quote.body.expiresAt) <= now)) throw new Error("canary quote expired");
  if (quote.body.proofCount !== 1 || quote.body.aip4Compliant !== false
    || quote.body.rpc !== rpc || !/^0x[0-9a-f]{40}$/.test(quote.body.requester)) throw new Error("invalid canary scope");
  if (quote.body.maxBaseFeeWei != null) {
    const buffer = quote.body.baseFeeBufferBps;
    if (!Number.isSafeInteger(buffer) || buffer < 0 || buffer > 10000) throw new Error("invalid base fee buffer");
    const ceiling = (BigInt(quote.body.quotedBaseFeeWei) * BigInt(10000 + buffer) + 9999n) / 10000n;
    if (ceiling.toString() !== quote.body.maxBaseFeeWei) throw new Error("base fee allowance mismatch");
    const budget = calculateBudget([quote.body.proverGasUnits], quote.body.maxPricePerPguWei, quote.body.maxBaseFeeWei, "0");
    if (budget.totalAtPriceCapWei !== quote.body.maxEstimatedCostWei) throw new Error("fee allowance budget mismatch");
  }
}

export async function readPricing(priceReader) {
  return (await commandJson(priceReader, [])).groth16;
}

export function checkBaseFee(body, pricing, resuming = false) {
  const ceiling = body.maxBaseFeeWei ?? body.quotedBaseFeeWei;
  if (!resuming && BigInt(pricing.baseFeeWei) > BigInt(ceiling)) {
    throw new Error(`base fee increased beyond approved allowance: allowed ${ceiling} wei, live ${pricing.baseFeeWei} wei; refresh and approve the quote before submitting`);
  }
}

export function repriceQuote(quote, baseFeeWei, now = new Date(), baseFeeBufferBps = 500) {
  validateQuote(quote, quote.digest, true);
  if (!Number.isSafeInteger(baseFeeBufferBps) || baseFeeBufferBps < 0 || baseFeeBufferBps > 10000) throw new Error("invalid base fee buffer");
  const budget = calculateBudget([quote.body.proverGasUnits], quote.body.maxPricePerPguWei, baseFeeWei, "0");
  const maxBaseFeeWei = ((BigInt(baseFeeWei) * BigInt(10000 + baseFeeBufferBps) + 9999n) / 10000n).toString();
  const bufferedBudget = calculateBudget([quote.body.proverGasUnits], quote.body.maxPricePerPguWei, maxBaseFeeWei, "0");
  const body = { ...quote.body, generatedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
    quotedBaseFeeWei: baseFeeWei, estimatedCostWei: budget.totalAtPriceCapWei,
    baseFeeBufferBps, maxBaseFeeWei, maxEstimatedCostWei: bufferedBudget.totalAtPriceCapWei,
    previousQuoteDigest: quote.digest };
  return { body, digest: quoteDigest(body) };
}

export async function prepare(args, { quiet = false } = {}) {
  const [manifestPath, baselinePath, estimateDirectory, outputPath, requester, selectedSeller] = args;
  if (![5, 6].includes(args.length) || !/^0x[0-9a-fA-F]{40}$/.test(requester)) throw new Error("usage: prepare manifest.json replay-summary.json estimate-directory output-directory requester-address [seller-address]");
  const manifest = await readJson(manifestPath);
  const estimates = await readJson(join(estimateDirectory, "summary.json"));
  if (estimates.kind !== "seller-proving-execution-preflight"
    || estimates.provenance.manifestSha256 !== await sha256(manifestPath)
    || estimates.provenance.baselineSha256 !== await sha256(baselinePath)) throw new Error("estimate provenance mismatch");
  const candidates = estimates.results.filter((item) => item.success).sort((first, second) => BigInt(first.proverGasUnits) < BigInt(second.proverGasUnits) ? -1 : 1);
  if (!candidates.length) throw new Error("no measured canary available");
  const canary = selectedSeller == null ? candidates[0] : candidates.find((item) => item.seller === selectedSeller.toLowerCase());
  if (!canary) throw new Error("selected seller has no successful PGU estimate");
  if (await sha256(canary.artifact) !== canary.artifactSha256) throw new Error("estimate artifact changed");
  const prover = manifest.prover;
  const priceReader = join(dirname(prover), "wash-trading-network-price");
  const balanceReader = join(dirname(prover), "wash-trading-network-preflight");
  const pricing = (await commandJson(priceReader, [])).groth16;
  const budget = calculateBudget([canary.proverGasUnits], pricing.maxPricePerPguWei, pricing.baseFeeWei, "0");
  const output = resolve(outputPath);
  const sourcePaths = [resolve(manifestPath), resolve(baselinePath), canary.artifact, prover, priceReader, balanceReader,
    manifest.sellerElf, manifest.guestAttestation, ...Object.keys(canary.inputSha256)];
  const body = { version: 1, kind: "frozen-seller-canary-approval", proofCount: 1,
    aip4Compliant: false, policyWarning: "Current 30% predicate; cumulative funding completeness and other documented AIP-4 differences remain unresolved.",
    generatedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    rpc, requester: requester.toLowerCase(), seller: canary.seller, label: canary.label,
    sellerProgramVKey: manifest.sellerProgramVKey, proverGasUnits: canary.proverGasUnits,
    maxPricePerPguWei: pricing.maxPricePerPguWei, quotedBaseFeeWei: pricing.baseFeeWei,
    estimatedCostWei: budget.totalAtPriceCapWei,
    feeCaveat: "PGU and unit-price limits are enforced. Base fee is checked before launch, but the SDK fetches it again when requesting; this is not a guaranteed total-fee cap.",
    proofTimeoutSeconds: 14400, auctionTimeoutSeconds: 120,
    manifestPath: resolve(manifestPath), baselinePath: resolve(baselinePath), estimatePath: canary.artifact,
    prover, priceReader, balanceReader, output,
    sourceSha256: Object.fromEntries(await Promise.all(sourcePaths.map(async (path) => [path, await sha256(path)]))) };
  await validateSources(body);
  await mkdir(output, { recursive: true });
  const quote = { body, digest: quoteDigest(body) };
  await writeFile(join(output, "canary-quote.json"), `${JSON.stringify(quote, null, 2)}\n`, { flag: "wx" });
  if (!quiet) console.log(JSON.stringify(quote, null, 2));
  return quote;
}

export async function submit(args, preflightOnly) {
  const [quotePath, approval] = args;
  if (args.length !== 2) throw new Error("usage: submit|preflight canary-quote.json approved-digest");
  const quote = await readJson(quotePath);
  const body = quote.body;
  const checkpointPath = join(body.output, "seller.request.json");
  const resuming = await exists(checkpointPath);
  validateQuote(quote, approval, resuming);
  const { manifest, seller, estimate } = await validateSources(body);
  const pricing = await readPricing(body.priceReader);
  checkBaseFee(body, pricing, resuming);
  if (preflightOnly) {
    console.log(JSON.stringify({ complete: true, proofCount: 1, seller: body.seller, estimatedCostWei: body.estimatedCostWei, proverNetworkSubmitted: false }));
    return;
  }
  if (!process.env.NETWORK_PRIVATE_KEY) throw new Error("unlock the funded requester locally through NETWORK_PRIVATE_KEY");
  if (!resuming) {
    const account = await commandJson(body.balanceReader, ["--expected-seller-vkey", body.sellerProgramVKey], { paid: true });
    if (account.networkMode !== "Mainnet" || account.requester.toLowerCase() !== body.requester) throw new Error("unlocked requester does not match the approved funded account");
    if (BigInt(account.balanceWei) < BigInt(body.maxEstimatedCostWei ?? body.estimatedCostWei)) throw new Error("insufficient available PROVE for the seller estimate including its approved fee allowance");
  }
  const lock = join(body.output, "execution.lock");
  await writeFile(lock, `${process.pid}\n`, { flag: "wx" });
  try {
    const started = join(body.output, "submission-started.json");
    if (await exists(started) && !resuming) throw new Error("prior launch has no saved request ID; reconcile the requester history before retrying to avoid duplicate spending");
    if (!resuming) await writeFile(started, JSON.stringify({ quoteDigest: quote.digest, startedAt: new Date().toISOString() }), { flag: "wx" });
    const artifactPath = join(body.output, "seller.json");
    const command = ["--production", "--confirm-production", "--seller", body.seller,
      "--seller-elf", manifest.sellerElf, "--output", artifactPath, "--request-checkpoint", checkpointPath,
      "--max-prover-gas", body.proverGasUnits, "--max-price-per-pgu-wei", body.maxPricePerPguWei,
      "--proof-timeout-secs", String(body.proofTimeoutSeconds), "--auction-timeout-secs", String(body.auctionTimeoutSeconds)];
    if (seller.sellerInput) command.push("--seller-input", seller.sellerInput);
    else command.push("--evidence", `${seller.evidenceKind}:${seller.evidencePath}`, "--total-volume-witness", seller.totalVolumePath);
    console.log(`${resuming ? "Resuming" : "Submitting"} ONE paid seller proof for ${body.label} (${body.seller}); checkpoint ${checkpointPath}`);
    let displayedRequest = null;
    const progress = setInterval(async () => {
      try {
        const checkpoint = await readJson(checkpointPath);
        if (checkpoint.requestId && checkpoint.requestId !== displayedRequest) {
          displayedRequest = checkpoint.requestId;
          console.log(`REQUEST ${body.seller}: ${displayedRequest}; waiting for network proof`);
        }
      } catch { }
    }, 5000);
    try { await commandJson(body.prover, command, { paid: true }); }
    finally { clearInterval(progress); }
    const artifact = await readJson(artifactPath);
    for (const field of ["seller", "sellerProgramVKey", "publicValues", "evidenceDigest", "provenWashVolumeRaw", "totalSellerVolumeRaw", "proverGasUnits"]) {
      if (artifact[field] !== estimate[field]) throw new Error(`production artifact changed ${field}`);
    }
    if (artifact.securityMode !== "production" || !artifact.proved || !artifact.verified || !artifact.proverNetworkSubmitted
      || !/^0x[0-9a-fA-F]{64}$/.test(artifact.requestId ?? "") || !/^0x(?:[0-9a-fA-F]{2})+$/.test(artifact.proofBytes ?? "")) throw new Error("invalid production artifact");
    const result = { complete: true, requestId: artifact.requestId, artifact: artifactPath,
      artifactSha256: await sha256(artifactPath), productionProofVerified: true, aip4Compliant: false, submittedOnChain: false };
    console.log(JSON.stringify(result, null, 2));
    return result;
  } finally { await unlink(lock); }
}

async function main() {
  const [action, ...args] = process.argv.slice(2);
  if (action === "prepare") return prepare(args);
  if (action === "preflight" || action === "submit") return submit(args, action === "preflight");
  throw new Error("select prepare, preflight, or submit");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
