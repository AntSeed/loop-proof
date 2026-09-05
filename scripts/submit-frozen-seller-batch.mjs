import { mkdir, readFile, writeFile, rename, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256, validateManifest } from "./replay-seller-development.mjs";
import { prepare as prepareSeller, submit as submitSeller, quoteDigest, validateQuote, validateSources, readPricing, checkBaseFee, repriceQuote } from "./submit-frozen-seller-canary.mjs";

const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
async function exists(path) {
  try { await readFile(path); return true; } catch (error) { if (error.code === "ENOENT") return false; throw error; }
}

export function validateBatch(quote, approval) {
  const body = quote?.body;
  if (body?.version !== 1 || body.kind !== "frozen-seller-batch-approval"
    || quote.digest !== quoteDigest(body) || approval !== quote.digest) throw new Error("batch digest approval mismatch");
  if (!Array.isArray(body.entries) || body.entries.length === 0 || body.proofCount !== body.entries.length
    || new Set(body.entries.map((entry) => entry.seller)).size !== body.proofCount
    || body.aip4Compliant !== false || body.concurrency !== 1) throw new Error("invalid batch scope");
  if (!/^0x[0-9a-f]{40}$/.test(body.requester)) throw new Error("invalid requester");
}

export async function runQueue(entries, state, { run, verifyCompleted, persist }) {
  state.complete = false;
  state.status = "running";
  delete state.error;
  await persist();
  for (const entry of entries) {
    const completed = state.results.find((result) => result.seller === entry.seller && result.complete);
    if (completed) {
      await verifyCompleted(completed);
      continue;
    }
    state.currentSeller = entry.seller;
    await persist();
    try {
      const result = await run(entry);
      if (!result.complete || !result.productionProofVerified) throw new Error("seller proof did not verify");
      state.results = state.results.filter((item) => item.seller !== entry.seller);
      state.results.push({ seller: entry.seller, label: entry.label, ...result });
      await persist();
    } catch (error) {
      state.status = /insufficient available PROVE|prover-network balance is zero/i.test(error.message) ? "paused-insufficient-funds" : "needs-attention";
      state.error = error.message;
      await persist();
      return state;
    }
  }
  state.complete = true;
  state.status = "complete";
  state.currentSeller = null;
  state.finishedAt = new Date().toISOString();
  await persist();
  return state;
}

async function prepare(args) {
  const [manifestPath, baselinePath, estimateDirectory, outputPath, requester, existingCanaryDirectory] = args;
  if (args.length !== 6 || !/^0x[0-9a-fA-F]{40}$/.test(requester)) throw new Error("usage: prepare manifest.json replay-summary.json estimate-directory output-directory requester existing-canary-directory");
  const manifest = await readJson(manifestPath);
  validateManifest(manifest);
  const estimates = await readJson(join(estimateDirectory, "summary.json"));
  if (!estimates.complete || estimates.kind !== "seller-proving-execution-preflight"
    || estimates.expectedSellerCount !== manifest.sellers.length || estimates.results.length !== manifest.sellers.length
    || estimates.results.some((result) => !result.success)
    || new Set(estimates.results.map((result) => result.seller)).size !== manifest.sellers.length
    || estimates.provenance.manifestSha256 !== await sha256(manifestPath)
    || estimates.provenance.baselineSha256 !== await sha256(baselinePath)) throw new Error("all sellers need completed, matching PGU estimates before batch approval");
  const output = resolve(outputPath);
  if (await exists(join(output, "batch-quote.json"))) throw new Error("batch quote already exists; use preflight/run to resume, not prepare");
  await mkdir(output, { recursive: true });
  const existingPath = join(resolve(existingCanaryDirectory), "canary-quote.json");
  const existing = await readJson(existingPath);
  const ordered = [...estimates.results].sort((first, second) => {
    if (first.seller === existing.body.seller) return -1;
    if (second.seller === existing.body.seller) return 1;
    return BigInt(first.proverGasUnits) < BigInt(second.proverGasUnits) ? -1 : 1;
  });
  const entries = [];
  let totalCost = 0n;
  let totalPgu = 0n;
  for (const result of ordered) {
    if (!manifest.sellers.some((seller) => seller.seller === result.seller)) throw new Error("estimate contains an unexpected seller");
    const sellerOutput = result.seller === existing.body.seller ? resolve(existingCanaryDirectory) : join(output, "sellers", result.seller);
    const quotePath = join(sellerOutput, "canary-quote.json");
    const quote = await exists(quotePath) ? await readJson(quotePath) : await prepareSeller(
      [manifestPath, baselinePath, estimateDirectory, sellerOutput, requester, result.seller], { quiet: true });
    const resuming = await exists(join(sellerOutput, "seller.request.json"));
    validateQuote(quote, quote.digest, resuming);
    if (quote.body.seller !== result.seller || quote.body.requester !== requester.toLowerCase()
      || quote.body.proverGasUnits !== result.proverGasUnits || quote.body.sellerProgramVKey !== manifest.sellerProgramVKey
      || quote.body.manifestPath !== resolve(manifestPath) || quote.body.baselinePath !== resolve(baselinePath)
      || quote.body.output !== sellerOutput) throw new Error("existing seller quote has different scope");
    await validateSources(quote.body);
    entries.push({ seller: result.seller, label: result.label, quotePath, quoteDigest: quote.digest,
      proverGasUnits: result.proverGasUnits, estimatedCostWei: quote.body.estimatedCostWei });
    totalCost += BigInt(quote.body.estimatedCostWei);
    totalPgu += BigInt(result.proverGasUnits);
    console.log(`PREPARED ${entries.length}/${ordered.length}: ${result.label}`);
  }
  const body = { version: 1, kind: "frozen-seller-batch-approval", generatedAt: new Date().toISOString(),
    proofCount: entries.length, concurrency: 1, aip4Compliant: false, requester: requester.toLowerCase(),
    sellerProgramVKey: manifest.sellerProgramVKey, totalProverGasUnits: totalPgu.toString(),
    estimatedTotalCostWei: totalCost.toString(),
    feeCaveat: "Sum of snapshot estimates for all sellers, not a guaranteed total-fee cap. Each request enforces its measured PGU and price cap; the SDK refreshes the base fee.",
    fundingPolicy: "Start affordable requests sequentially; pause before the next unaffordable request. Top up the same network requester and rerun to resume.",
    policyWarning: "Current 30% predicate; documented AIP-4 completeness and attribution differences remain unresolved.",
    manifestPath: resolve(manifestPath), manifestSha256: await sha256(manifestPath),
    baselinePath: resolve(baselinePath), baselineSha256: await sha256(baselinePath),
    estimateSummaryPath: join(resolve(estimateDirectory), "summary.json"), estimateSummarySha256: await sha256(join(estimateDirectory, "summary.json")),
    output, entries };
  const quote = { body, digest: quoteDigest(body) };
  await writeFile(join(output, "batch-quote.json"), `${JSON.stringify(quote, null, 2)}\n`, { flag: "wx" });
  console.log(JSON.stringify({ quotePath: join(output, "batch-quote.json"), digest: quote.digest,
    proofCount: body.proofCount, totalProverGasUnits: body.totalProverGasUnits, estimatedTotalCostWei: body.estimatedTotalCostWei }, null, 2));
}

export async function refreshBatch(quotePath, { readPrices = readPricing, validate = validateSources, now = new Date() } = {}) {
  const quote = await readJson(quotePath);
  validateBatch(quote, quote.digest);
  const lockPath = join(quote.body.output, "batch.lock");
  await writeFile(lockPath, `${process.pid}\n`, { flag: "wx" });
  try {
    if ((await readJson(quotePath)).digest !== quote.digest) throw new Error("batch changed before refresh lock");
    const statePath = join(quote.body.output, "summary.json");
    const state = await exists(statePath) ? await readJson(statePath) : null;
    if (state && (state.kind !== "frozen-seller-batch-progress" || state.batchDigest !== quote.digest)) throw new Error("batch checkpoint mismatch before refresh");
    const prepared = [];
    const prices = new Map();
    for (const entry of quote.body.entries) {
      const sellerQuote = await readJson(entry.quotePath);
      validateQuote(sellerQuote, entry.quoteDigest, true);
      if (sellerQuote.body.seller !== entry.seller || sellerQuote.body.requester !== quote.body.requester) throw new Error("seller scope mismatch during refresh");
      const directory = sellerQuote.body.output;
      if (await exists(join(directory, "execution.lock"))) throw new Error(`seller execution is locked: ${entry.seller}`);
      const resuming = await exists(join(directory, "seller.request.json"));
      if (!resuming && await exists(join(directory, "submission-started.json"))) throw new Error(`ambiguous prior submission for ${entry.seller}; reconcile network history before refreshing`);
      await validate(sellerQuote.body);
      if (resuming) {
        prepared.push({ entry, quote: sellerQuote, changed: false });
        continue;
      }
      if (!prices.has(sellerQuote.body.priceReader)) prices.set(sellerQuote.body.priceReader, await readPrices(sellerQuote.body.priceReader));
      prepared.push({ entry, quote: repriceQuote(sellerQuote, prices.get(sellerQuote.body.priceReader).baseFeeWei, now), changed: true });
    }
    const history = join(quote.body.output, "quote-history", now.toISOString().replace(/[:.]/g, "-"));
    await mkdir(history, { recursive: true });
    await writeFile(join(history, "previous-batch-quote.json"), `${JSON.stringify(quote, null, 2)}\n`, { flag: "wx" });
    if (state) await writeFile(join(history, "previous-summary.json"), `${JSON.stringify(state, null, 2)}\n`, { flag: "wx" });
    const entries = [];
    for (const item of prepared) {
      const path = item.changed ? join(history, `${item.entry.seller}.json`) : item.entry.quotePath;
      if (item.changed) await writeFile(path, `${JSON.stringify(item.quote, null, 2)}\n`, { flag: "wx" });
      entries.push({ ...item.entry, quotePath: path, quoteDigest: item.quote.digest, estimatedCostWei: item.quote.body.estimatedCostWei,
        maxEstimatedCostWei: item.quote.body.maxEstimatedCostWei ?? item.quote.body.estimatedCostWei });
    }
    const body = { ...quote.body, generatedAt: now.toISOString(), previousBatchDigest: quote.digest, entries,
      newRequestBaseFeeBufferBps: 500,
      estimatedTotalCostWei: entries.reduce((sum, entry) => sum + BigInt(entry.estimatedCostWei), 0n).toString(),
      estimatedTotalCostWithFeeAllowanceWei: entries.reduce((sum, entry) => sum + BigInt(entry.maxEstimatedCostWei), 0n).toString() };
    const refreshed = { body, digest: quoteDigest(body) };
    await writeFile(`${quotePath}.tmp`, `${JSON.stringify(refreshed, null, 2)}\n`);
    await rename(`${quotePath}.tmp`, quotePath);
    if (state) {
      const updated = { ...state, batchDigest: refreshed.digest, status: state.complete ? "complete" : "awaiting-approval" };
      delete updated.error;
      await writeFile(`${statePath}.tmp`, `${JSON.stringify(updated, null, 2)}\n`);
      await rename(`${statePath}.tmp`, statePath);
    }
    return { quotePath, previousDigest: quote.digest, digest: refreshed.digest,
      refreshedSellers: prepared.filter((item) => item.changed).length,
      preservedPaidRequests: prepared.filter((item) => !item.changed).length,
      estimatedTotalCostWei: body.estimatedTotalCostWei,
      estimatedTotalCostWithFeeAllowanceWei: body.estimatedTotalCostWithFeeAllowanceWei,
      newRequestBaseFeeBufferBps: body.newRequestBaseFeeBufferBps, paidRequestsSubmitted: false };
  } finally { await unlink(lockPath); }
}

async function execute(args, preflightOnly) {
  const [quotePath, approval] = args;
  if (args.length !== 2) throw new Error("usage: preflight|run batch-quote.json approved-digest");
  const quote = await readJson(quotePath);
  validateBatch(quote, approval);
  const body = quote.body;
  for (const [path, hash] of [[body.manifestPath, body.manifestSha256], [body.baselinePath, body.baselineSha256], [body.estimateSummaryPath, body.estimateSummarySha256]]) {
    if (await sha256(path) !== hash) throw new Error(`batch source changed: ${path}`);
  }
  const prices = new Map();
  for (const entry of body.entries) {
    const sellerQuote = await readJson(entry.quotePath);
    validateQuote(sellerQuote, entry.quoteDigest, true);
    if (sellerQuote.body.seller !== entry.seller || sellerQuote.body.requester !== body.requester) throw new Error("seller quote scope differs from batch");
    await validateSources(sellerQuote.body);
    if (preflightOnly) {
      const resuming = await exists(join(sellerQuote.body.output, "seller.request.json"));
      validateQuote(sellerQuote, entry.quoteDigest, resuming);
      if (!resuming) {
        if (!prices.has(sellerQuote.body.priceReader)) prices.set(sellerQuote.body.priceReader, await readPricing(sellerQuote.body.priceReader));
        checkBaseFee(sellerQuote.body, prices.get(sellerQuote.body.priceReader));
      }
    }
  }
  if (preflightOnly) {
    console.log(JSON.stringify({ complete: true, proofCount: body.proofCount, paidRequestsSubmitted: false,
      estimatedTotalCostWei: body.estimatedTotalCostWei }));
    return;
  }
  if (!process.env.NETWORK_PRIVATE_KEY) throw new Error("unlock the requester locally through NETWORK_PRIVATE_KEY");
  const lockPath = join(body.output, "batch.lock");
  await writeFile(lockPath, `${process.pid}\n`, { flag: "wx" });
  try {
    if ((await readJson(quotePath)).digest !== quote.digest) throw new Error("batch approval changed before execution lock");
    const statePath = join(body.output, "summary.json");
    const state = await exists(statePath) ? await readJson(statePath) : {
      version: 1, kind: "frozen-seller-batch-progress", batchDigest: quote.digest,
      expectedSellerCount: body.proofCount, startedAt: new Date().toISOString(),
      aip4Compliant: false, submittedOnChain: false, complete: false, results: [] };
    if (state.kind !== "frozen-seller-batch-progress" || state.batchDigest !== quote.digest
      || !Array.isArray(state.results) || new Set(state.results.map((result) => result.seller)).size !== state.results.length
      || state.results.some((result) => !body.entries.some((entry) => entry.seller === result.seller))) throw new Error("batch checkpoint mismatch");
    const persist = async () => {
      await writeFile(`${statePath}.tmp`, `${JSON.stringify(state, null, 2)}\n`);
      await rename(`${statePath}.tmp`, statePath);
    };
    await runQueue(body.entries, state, {
      persist,
      verifyCompleted: async (completed) => {
        if (!completed.productionProofVerified || await sha256(completed.artifact) !== completed.artifactSha256) throw new Error(`completed artifact changed: ${completed.seller}`);
      },
      run: async (entry) => {
        console.log(`QUEUE ${state.results.filter((result) => result.complete).length + 1}/${body.proofCount}: ${entry.label}`);
        return submitSeller([entry.quotePath, entry.quoteDigest], false);
      },
    });
    console.log(JSON.stringify({ summary: statePath, status: state.status, complete: state.complete,
      verifiedProofs: state.results.filter((result) => result.complete).length, expectedSellerCount: body.proofCount,
      error: state.error }, null, 2));
    if (!state.complete) process.exitCode = 2;
  } finally { await unlink(lockPath); }
}

async function main() {
  const [action, ...args] = process.argv.slice(2);
  if (action === "prepare") return prepare(args);
  if (action === "refresh") {
    if (args.length !== 1) throw new Error("usage: refresh batch-quote.json");
    console.log(JSON.stringify(await refreshBatch(resolve(args[0])), null, 2));
    return;
  }
  if (action === "preflight" || action === "run") return execute(args, action === "preflight");
  throw new Error("select prepare, refresh, preflight, or run");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
