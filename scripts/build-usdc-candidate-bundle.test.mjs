import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildUsdcCandidates, primaryUsdcCohort } from "./build-usdc-candidate-bundle.mjs";

test("USDC candidates use the capital funder, not a shared gas funder", () => {
  const report = { strongestCohort: { funder: "capital" }, fundingProvenance: { sources: [{ funder: "capital", fundedAmountRaw: "90", buyers: ["buyer", "buyer"] }] }, networkSignals: { nativeFunderCohorts: [{ funder: "gas", buyerAddresses: ["other"] }] } };
  assert.deepEqual(primaryUsdcCohort(report), { funder: "capital", buyers: ["buyer"] });
  assert.throws(() => primaryUsdcCohort({ ...report, fundingProvenance: { sources: [] } }), /no positive primary USDC/);
});

test("joint discovery can select another positive USDC funder without merging capital", () => {
  const report = { strongestCohort: { funder: "primary" }, fundingProvenance: { sources: [
    { funder: "primary", fundedAmountRaw: "100", buyers: ["a"] },
    { funder: "alternative", fundedAmountRaw: "20", buyers: ["b"] },
  ] } };
  assert.deepEqual(primaryUsdcCohort(report, "alternative"), { funder: "alternative", buyers: ["b"] });
  assert.throws(() => primaryUsdcCohort(report, "unattributed"), /no positive/);
});

async function candidateFixture(context) {
  const directory = await mkdtemp(join(tmpdir(), "usdc-candidate-test-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const scanDirectory = join(directory, "scan");
  const outputDirectory = join(directory, "output");
  const period = { startBlock: 100, endBlock: 200 };
  const save = async (relative, value) => writeFile(join(scanDirectory, relative), JSON.stringify(value));
  for (const relative of ["sellers", "raw/traces", "raw/antscan"]) await mkdir(join(scanDirectory, relative), { recursive: true });
  await save("scan.json", { proofPeriod: period, period: { from: 1000, to: 2000 } });
  await save("raw/protocol-deposits.json", { records: [] });
  await save("sellers/seller.json", { stats: { volumeRaw: "1000" }, strongestCohort: { funder: "capital" }, fundingProvenance: { sources: [{ funder: "capital", fundedAmountRaw: "90", buyers: ["buyer"] }] } });
  await save("raw/traces/buyer.json", { complete: true, inboundUsdc: [
    { from: "gas", to: "buyer", amountRaw: "999", timestamp: 1050, txHash: "wrong-funder", logIndex: 0 },
    { from: "capital", to: "buyer", amountRaw: "90", timestamp: 1100, txHash: "funding", logIndex: 0 },
  ] });
  await save("raw/traces/seller.json", { complete: true, outboundUsdc: [
    { from: "seller", to: "capital", amountRaw: "30", timestamp: 1300, txHash: "return", logIndex: 0 },
    { from: "seller", to: "capital", amountRaw: "900", timestamp: 2100, txHash: "late-return", logIndex: 0 },
  ] });
  await save("raw/antscan/settlementVolumes.ndjson", { items: [
    { seller: "seller", buyer: "buyer", deltaUsdc: "100", timestamp: 1200, txHash: "settlement", logIndex: 0 },
    { seller: "seller", buyer: "buyer", deltaUsdc: "500", timestamp: 1090, txHash: "early-settlement", logIndex: 0 },
    { seller: "seller", buyer: "unfunded", deltaUsdc: "500", timestamp: 1200, txHash: "unfunded-settlement", logIndex: 0 },
  ] });
  return { options: { scanDirectory, outputDirectory, baseline: { period }, sellers: ["seller"] }, save };
}

test("builds a minority USDC draft without counting gas-funded, premature, or late evidence", async (context) => {
  const { options } = await candidateFixture(context);
  const [result] = await buildUsdcCandidates(options);
  assert.equal(result.status, "draft-not-proof");
  assert.equal(result.candidateSettlementRaw, "100");
  assert.equal(result.fundingRaw, "90");
  assert.equal(result.returnedRaw, "30");
  const original = await readFile(result.bundle, "utf8");
  const bundle = JSON.parse(original);
  assert.equal(bundle.predicatePolicy.alphaReturnBps, 3000);
  assert.deepEqual(bundle.claims[0].approvedFunders, ["capital"]);
  assert.equal(bundle.claims[0].dependencies.length, 3);
  await assert.rejects(buildUsdcCandidates(options), { code: "EEXIST" });
  assert.equal(await readFile(result.bundle, "utf8"), original);
});

test("incomplete USDC funding traces remain rejected drafts", async (context) => {
  const { options, save } = await candidateFixture(context);
  await save("raw/traces/buyer.json", { complete: false, inboundUsdc: [] });
  const [result] = await buildUsdcCandidates(options);
  assert.equal(result.status, "rejected");
  assert.match(result.error, /incomplete funding trace/);
});

test("relay returns must finish inside the selected period", async (context) => {
  const { options, save } = await candidateFixture(context);
  await save("raw/traces/seller.json", { complete: true, outboundUsdc: [
    { from: "seller", to: "relay", amountRaw: "40", timestamp: 1500, txHash: "first-hop", logIndex: 0 },
  ] });
  await save("raw/traces/relay.json", { complete: true, outboundUsdc: [
    { from: "relay", to: "capital", amountRaw: "40", timestamp: 2001, txHash: "late-hop", logIndex: 0 },
  ] });
  const [result] = await buildUsdcCandidates(options);
  assert.equal(result.status, "rejected");
  assert.match(result.error, /no non-overlapping return path/);
});
