import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { refreshReturnSearchTraces } from "./refresh-return-search-traces.mjs";

test("refresh is read-only RPC, limited to shortfalls and reports truncated pages", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fixed-return-refresh-"));
  const originalFetch = globalThis.fetch;
  const calls = [];
  const seller = `0x${"11".repeat(20)}`;
  const funder = `0x${"22".repeat(20)}`;
  try {
    const input = join(directory, "input.json");
    const summaryPath = join(directory, "summary.json");
    const manifestPath = join(directory, "manifest.json");
    const outputDirectory = join(directory, "output");
    await writeFile(input, JSON.stringify({ period_start_block: 100, period_end_block: 200 }));
    const summary = JSON.stringify({ results: [
      { seller, funder, sellerInput: input, missingTraces: [], status: "candidate-shortfall" },
      { seller: "do-not-fetch", status: "already-meets-target" },
    ] });
    await writeFile(summaryPath, summary);
    await writeFile(manifestPath, JSON.stringify({ sellers: [{ seller }] }));
    globalThis.fetch = async (_url, options) => {
      calls.push(JSON.parse(options.body));
      return { ok: true, json: async () => ({ result: { transfers: [], pageKey: "more" } }) };
    };
    const results = await refreshReturnSearchTraces({ summaryPath, manifestPath, outputDirectory, endpoint: "http://test.invalid", maxPages: 1 });
    assert.equal(calls.length, 2);
    assert(calls.every((call) => call.method === "alchemy_getAssetTransfers" && call.params[0].fromBlock === "0x64" && call.params[0].toBlock === "0xc8"));
    assert(results.every((result) => !result.complete));
    assert.equal(await readFile(summaryPath, "utf8"), summary);
    const refreshed = JSON.parse(await readFile(join(outputDirectory, "manifest.json"), "utf8"));
    assert.equal(Object.keys(refreshed.sellers[0].traceOverrides).length, 2);
    await assert.rejects(refreshReturnSearchTraces({ summaryPath, manifestPath, outputDirectory, endpoint: "http://test.invalid" }), /EEXIST/);
  } finally {
    globalThis.fetch = originalFetch;
    await rm(directory, { recursive: true, force: true });
  }
});
