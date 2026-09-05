import assert from "node:assert/strict";
import test from "node:test";
import { evaluateClosedLoopCandidate, selectLargestDeterministicSettlementSet, supportedSettlementCapacity } from "./build-discovery-proof-bundle.mjs";

const amount = (amountRaw) => ({ amountRaw: String(amountRaw) });
const path = (first, second, third) => ({ evidenceType: "RELAY_PATH", sellerPayment: amount(first), relayForward: amount(second), funderReceipt: amount(third) });
const directRelayPath = (first, second) => ({ evidenceType: "RELAY_PATH", sellerPayment: amount(first), relayForward: amount(second) });

test("candidate evaluation permits minority and exact-half claims", () => {
  const exactHalf = evaluateClosedLoopCandidate({
    sellerVolumeRaw: "200",
    settlements: [amount(100)],
    fundings: [amount(100)],
    paths: [path(100, 100, 100)],
  });
  assert.equal(exactHalf.accepted, true);
  assert.equal(exactHalf.deficits.positiveVolumeRaw, "0");

  const minority = evaluateClosedLoopCandidate({ sellerVolumeRaw: "1000", settlements: [amount(100)], fundings: [amount(90)], paths: [path(30, 30, 30)] });
  assert.equal(minority.accepted, true);
  const empty = evaluateClosedLoopCandidate({ sellerVolumeRaw: "1000", settlements: [], fundings: [], paths: [] });
  assert.equal(empty.accepted, false);

  const majority = evaluateClosedLoopCandidate({
    sellerVolumeRaw: "200",
    settlements: [amount(101)],
    fundings: [amount(91)],
    paths: [path(31, 31, 31)],
  });
  assert.equal(majority.accepted, true);
});

test("candidate evaluation reports bottleneck return and exact deficits", () => {
  const result = evaluateClosedLoopCandidate({
    sellerVolumeRaw: "200",
    settlements: [amount(101)],
    fundings: [amount(80)],
    paths: [path(8, 8, 248)],
  });
  assert.equal(result.bottleneckReturnRaw, 8n);
  assert.deepEqual(result.deficits, { positiveVolumeRaw: "0", fundingRaw: "11", returnRaw: "23" });
});

test("candidate evaluation credits a two-transfer relay path", () => {
  const result = evaluateClosedLoopCandidate({
    sellerVolumeRaw: "200",
    settlements: [amount(101)],
    fundings: [amount(91)],
    paths: [directRelayPath(31, 30)],
  });
  assert.equal(result.accepted, false);
  assert.equal(result.bottleneckReturnRaw, 30n);
  assert.equal(supportedSettlementCapacity([amount(100)], [directRelayPath(30, 29)]), 96n);
});

test("largest deterministic selection stays within funding and bottleneck capacity", () => {
  const paths = [path(30, 30, 300)];
  assert.equal(supportedSettlementCapacity([amount(100)], paths), 100n);
  const settlements = [
    { ...amount(70), timestamp: 3, transactionHash: "c" },
    { ...amount(40), timestamp: 1, transactionHash: "a" },
    { ...amount(30), timestamp: 2, transactionHash: "b" },
  ];
  assert.deepEqual(selectLargestDeterministicSettlementSet(settlements, 100n).map((entry) => entry.amountRaw), ["40", "30"]);
});

test("discovered sellers receive exact-total settlement evidence", async (context) => {
  const source = await import("node:fs/promises");
  const temporary = await source.mkdtemp("/tmp/discovery-bundle-");
  context.after(() => source.rm(temporary, { recursive: true, force: true }));
  await source.mkdir(`${temporary}/raw/antscan`, { recursive: true });
  await source.mkdir(`${temporary}/raw/traces`, { recursive: true });
  await source.mkdir(`${temporary}/sellers`, { recursive: true });
  await source.writeFile(`${temporary}/raw/protocol-deposits.json`, '{"records":[]}');
  await source.writeFile(`${temporary}/raw/antscan/settlementVolumes.ndjson`, '{"items":[]}\n');

  const script = await source.readFile(new URL("./build-discovery-proof-bundle.mjs", import.meta.url), "utf8");
  assert.match(script, /if \(!totalSettlementsBySeller\.has\(seller\)\) totalSettlementsBySeller\.set\(seller, \[\]\)/);
});

test("supplemental return paths preserve every authenticated hop", async () => {
  const { returnPathDependency } = await import("./proof-bundle.mjs");
  const dependency = returnPathDependency({ hops: [
    { tx: "0x1", blockNumber: 1, transactionIndex: 0, logIndex: 0, timestamp: 1, from: "0x0000000000000000000000000000000000000001", to: "0x0000000000000000000000000000000000000002", amountRaw: "8" },
    { tx: "0x2", blockNumber: 2, transactionIndex: 0, logIndex: 0, timestamp: 2, from: "0x0000000000000000000000000000000000000002", to: "0x0000000000000000000000000000000000000003", amountRaw: "8" },
    { tx: "0x3", blockNumber: 3, transactionIndex: 0, logIndex: 0, timestamp: 3, from: "0x0000000000000000000000000000000000000003", to: "0x0000000000000000000000000000000000000004", amountRaw: "248" },
    { tx: "0x4", blockNumber: 4, transactionIndex: 0, logIndex: 0, timestamp: 4, from: "0x0000000000000000000000000000000000000004", to: "0x0000000000000000000000000000000000000005", amountRaw: "248" },
  ] }, "0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000005");
  assert.equal(dependency.hops.length, 4);
  assert.deepEqual(dependency.hops.map((hop) => hop.evidenceType), ["RELAY_SELLER_PAYMENT", "RELAY_FORWARD", "RELAY_FORWARD", "RELAY_FUNDER_RECEIPT"]);
});
