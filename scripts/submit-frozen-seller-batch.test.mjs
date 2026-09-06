import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runQueue, validateBatch, refreshBatch } from "./submit-frozen-seller-batch.mjs";
import { quoteDigest, repriceQuote, checkBaseFee } from "./submit-frozen-seller-canary.mjs";

test("refreshing the stale canary fee requires a new digest without changing scope or PGU price limits", () => {
  const body = { version: 1, kind: "frozen-seller-canary-approval", proofCount: 1, aip4Compliant: false,
    requester: `0x${"12".repeat(20)}`, rpc: "https://rpc.mainnet.succinct.xyz", seller: "seller",
    expiresAt: "2026-09-06T00:00:00Z", proverGasUnits: "305236355", maxPricePerPguWei: "660000000",
    quotedBaseFeeWei: "414364000000000000", estimatedCostWei: "615819994300000000",
    sourceSha256: { "/saved/input.json": "pinned" }, output: "/same/checkpoint/directory" };
  const quote = { body, digest: quoteDigest(body) };
  const pricing = { baseFeeWei: "414823000000000000" };
  assert.throws(() => checkBaseFee(body, pricing), /base fee increased/);
  const refreshed = repriceQuote(quote, pricing.baseFeeWei, new Date("2026-09-05T18:00:00Z"), 0);
  assert.doesNotThrow(() => checkBaseFee(refreshed.body, pricing));
  assert.notEqual(refreshed.digest, quote.digest);
  assert.equal(refreshed.body.estimatedCostWei, "616278994300000000");
  for (const field of ["seller", "requester", "proverGasUnits", "maxPricePerPguWei", "sourceSha256", "output"]) {
    assert.deepEqual(refreshed.body[field], body[field]);
  }
  assert.equal(quote.body.quotedBaseFeeWei, "414364000000000000");
  assert.doesNotThrow(() => checkBaseFee(body, pricing, true));
  assert.throws(() => checkBaseFee(refreshed.body, { baseFeeWei: "414824000000000000" }), /base fee increased/);
});

test("a newly approved 5 percent base-fee allowance tolerates small changes without raising PGU prices", () => {
  const body = { version: 1, kind: "frozen-seller-canary-approval", proofCount: 1, aip4Compliant: false,
    requester: `0x${"12".repeat(20)}`, rpc: "https://rpc.mainnet.succinct.xyz",
    expiresAt: "2026-09-06T00:00:00Z", proverGasUnits: "305236355", maxPricePerPguWei: "660000000",
    quotedBaseFeeWei: "414823000000000000", estimatedCostWei: "616278994300000000" };
  const quote = { body, digest: quoteDigest(body) };
  const refreshed = repriceQuote(quote, body.quotedBaseFeeWei, new Date("2026-09-05T18:00:00Z"));
  assert.equal(refreshed.body.baseFeeBufferBps, 500);
  assert.equal(refreshed.body.maxBaseFeeWei, "435564150000000000");
  assert.equal(refreshed.body.maxEstimatedCostWei, "637020144300000000");
  assert.equal(refreshed.body.estimatedCostWei, body.estimatedCostWei);
  assert.equal(refreshed.body.maxPricePerPguWei, body.maxPricePerPguWei);
  assert.notEqual(refreshed.digest, quote.digest);
  assert.throws(() => checkBaseFee(body, { baseFeeWei: "415973000000000000" }), /base fee increased/);
  assert.doesNotThrow(() => checkBaseFee(refreshed.body, { baseFeeWei: "415973000000000000" }));
  assert.doesNotThrow(() => checkBaseFee(refreshed.body, { baseFeeWei: refreshed.body.maxBaseFeeWei }));
  assert.throws(() => checkBaseFee(refreshed.body, { baseFeeWei: "435564150000000001" }), /base fee increased/);
  assert.throws(() => repriceQuote(quote, body.quotedBaseFeeWei, new Date(), -1), /buffer/);
});

test("full batch approval binds distinct sellers and sequential scope", () => {
  const body = { version: 1, kind: "frozen-seller-batch-approval", proofCount: 2,
    aip4Compliant: false, concurrency: 1, requester: `0x${"12".repeat(20)}`,
    entries: [{ seller: "first" }, { seller: "second" }] };
  const quote = { body, digest: quoteDigest(body) };
  assert.doesNotThrow(() => validateBatch(quote, quote.digest));
  assert.throws(() => validateBatch(quote, "wrong"));
  for (const mutation of [{ proofCount: 54 }, { entries: [{ seller: "first" }, { seller: "first" }] },
    { concurrency: 2 }, { aip4Compliant: true }, { requester: "other" }]) {
    const changed = { ...body, ...mutation };
    assert.throws(() => validateBatch({ body: changed, digest: quoteDigest(changed) }, quoteDigest(changed)));
  }
});

test("queue pauses before an unaffordable request and resumes without duplicating completed proofs", async () => {
  const entries = [{ seller: "first" }, { seller: "second" }, { seller: "third" }];
  const state = { results: [] };
  const called = [];
  await runQueue(entries, state, {
    persist: async () => {}, verifyCompleted: async () => {},
    run: async (entry) => {
      called.push(entry.seller);
      if (entry.seller === "second") throw new Error("insufficient available PROVE for the canary estimate");
      return { complete: true, productionProofVerified: true };
    },
  });
  assert.equal(state.complete, false);
  assert.equal(state.status, "paused-insufficient-funds");
  assert.deepEqual(called, ["first", "second"]);
  const reused = [];
  await runQueue(entries, state, {
    persist: async () => {}, verifyCompleted: async (result) => reused.push(result.seller),
    run: async (entry) => { called.push(entry.seller); return { complete: true, productionProofVerified: true }; },
  });
  assert.deepEqual(reused, ["first"]);
  assert.deepEqual(called, ["first", "second", "second", "third"]);
  assert.equal(state.complete, true);
  assert.equal(state.results.length, 3);
});

test("queue stops on an ambiguous or failed request instead of blindly paying again", async () => {
  const state = { results: [] };
  let attempts = 0;
  await runQueue([{ seller: "first" }, { seller: "second" }], state, {
    persist: async () => {}, verifyCompleted: async () => {},
    run: async () => { attempts++; throw new Error("prior launch has no saved request ID"); },
  });
  assert.equal(attempts, 1);
  assert.equal(state.status, "needs-attention");
  assert.equal(state.complete, false);
});

test("queue does not skip a changed completed artifact", async () => {
  const state = { results: [{ seller: "first", complete: true, productionProofVerified: true }] };
  let attempts = 0;
  await assert.rejects(runQueue([{ seller: "first" }], state, {
    persist: async () => {}, verifyCompleted: async () => { throw new Error("artifact changed"); },
    run: async () => { attempts++; },
  }), /artifact changed/);
  assert.equal(attempts, 0);
});

test("batch repricing archives approval and preserves paid request IDs and completed results", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wash-batch-refresh-"));
  try {
    const entries = [];
    const requester = `0x${"12".repeat(20)}`;
    for (const seller of ["first", "second"]) {
      const output = join(directory, seller);
      await mkdir(output);
      const body = { version: 1, kind: "frozen-seller-canary-approval", proofCount: 1, aip4Compliant: false,
        requester, rpc: "https://rpc.mainnet.succinct.xyz", seller, output, priceReader: "/reader",
        expiresAt: "2026-09-06T00:00:00Z", proverGasUnits: "10", maxPricePerPguWei: "2",
        quotedBaseFeeWei: "100", estimatedCostWei: "120", sourceSha256: {} };
      const quote = { body, digest: quoteDigest(body) };
      const quotePath = join(output, "canary-quote.json");
      await writeFile(quotePath, JSON.stringify(quote));
      entries.push({ seller, quotePath, quoteDigest: quote.digest, estimatedCostWei: "120" });
    }
    const requestPath = join(directory, "first", "seller.request.json");
    await writeFile(requestPath, JSON.stringify({ requestId: "existing-paid-request" }));
    const body = { version: 1, kind: "frozen-seller-batch-approval", proofCount: 2, concurrency: 1,
      aip4Compliant: false, requester, output: directory, estimatedTotalCostWei: "240", entries };
    const quote = { body, digest: quoteDigest(body) };
    const quotePath = join(directory, "batch-quote.json");
    await writeFile(quotePath, JSON.stringify(quote));
    const results = [{ seller: "first", complete: true, artifactSha256: "unchanged" }];
    await writeFile(join(directory, "summary.json"), JSON.stringify({
      kind: "frozen-seller-batch-progress", batchDigest: quote.digest, complete: false, results }));
    const firstQuoteBytes = await readFile(entries[0].quotePath, "utf8");
    const refreshed = await refreshBatch(quotePath, {
      readPrices: async () => ({ baseFeeWei: "200" }), validate: async () => {}, now: new Date("2026-09-05T18:00:00Z"),
    });
    assert.equal(refreshed.refreshedSellers, 1);
    assert.equal(refreshed.preservedPaidRequests, 1);
    assert.equal(refreshed.paidRequestsSubmitted, false);
    assert.equal(refreshed.estimatedTotalCostWei, "340");
    assert.equal(await readFile(entries[0].quotePath, "utf8"), firstQuoteBytes);
    assert.equal(JSON.parse(await readFile(requestPath, "utf8")).requestId, "existing-paid-request");
    const state = JSON.parse(await readFile(join(directory, "summary.json"), "utf8"));
    assert.deepEqual(state.results, results);
    assert.equal(state.batchDigest, refreshed.digest);
    assert.equal(state.status, "awaiting-approval");
    const next = JSON.parse(await readFile(quotePath, "utf8"));
    assert.equal(next.body.entries[0].quotePath, entries[0].quotePath);
    assert.notEqual(next.body.entries[1].quotePath, entries[1].quotePath);
    await writeFile(join(directory, "second", "submission-started.json"), "{}");
    await assert.rejects(refreshBatch(quotePath, {
      readPrices: async () => ({ baseFeeWei: "300" }), validate: async () => {}, now: new Date("2026-09-05T19:00:00Z"),
    }), /ambiguous prior submission/);
    assert.equal(JSON.parse(await readFile(quotePath, "utf8")).digest, refreshed.digest);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
