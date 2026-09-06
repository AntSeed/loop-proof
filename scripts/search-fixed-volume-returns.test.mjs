import assert from "node:assert/strict";
import test from "node:test";
import { classifySeller, selectFixedVolumeReturns } from "./search-fixed-volume-returns.mjs";
import { requiredReturnRaw } from "./return-path-selection.mjs";

const baselineEntry = { supports30PercentReturnFloor: true, guestAlphaReturnBps: 3000, provenWashVolumeRaw: "101", returnedCreditRaw: "31" };
const hop = (identifier, amountRaw, from = "seller", to = "funder", timestamp = 20) => ({
  from, to, amountRaw: String(amountRaw), timestamp, txHash: `0x${identifier.toString(16).padStart(64, "0")}`, logIndex: 0,
});
const direct = (identifier, amountRaw) => ({ ...hop(identifier, amountRaw), evidenceType: "DIRECT_SELLER_FUNDER" });
const select = (overrides = {}) => selectFixedVolumeReturns({ baseline: [direct(1, 30)], candidates: [], volumeRaw: "100", seller: "seller", funder: "funder", earliest: 10, end: 100, startBlock: 1, endBlock: 100, ...overrides });

test("50% search target does not change the current guest default", () => {
  assert.equal(requiredReturnRaw(101), 31n);
  assert.equal(requiredReturnRaw(101, 5000), 51n);
  for (const target of [0, -1, 10001, 30.5]) assert.throws(() => requiredReturnRaw(100, target));
});

test("only below-target supported sellers are searched", () => {
  assert.equal(classifySeller(baselineEntry), "search-required");
  assert.equal(classifySeller({ ...baselineEntry, returnedCreditRaw: "51" }), "already-meets-target");
  assert.equal(classifySeller({ ...baselineEntry, guestAlphaReturnBps: 5000, returnedCreditRaw: undefined }), "already-meets-target");
  assert.equal(classifySeller({ ...baselineEntry, supports30PercentReturnFloor: false }), "excluded-baseline");
  assert.equal(classifySeller({ ...baselineEntry, returnedCreditRaw: undefined }), "missing-return-measurement");
});

test("finds additional return evidence without reducing V", () => {
  const result = select({ candidates: [direct(2, 20)] });
  assert.equal(result.fixedVolumeRaw, "100");
  assert.equal(result.candidateReturnRaw, "50");
  assert.equal(result.targetMetByCandidates, true);
});

test("shortfalls never shrink the denominator or double count logs", () => {
  const result = select({ candidates: [direct(1, 30), direct(2, 5), direct(2, 5)] });
  assert.equal(result.fixedVolumeRaw, "100");
  assert.equal(result.candidateReturnRaw, "35");
  assert.equal(result.shortfallRaw, "15");
  assert.equal(result.targetMetByCandidates, false);
});

test("rejects wrong funder, wrong seller and out-of-period candidates", () => {
  const result = select({ candidates: [
    { ...direct(2, 100), to: "other" }, { ...direct(3, 100), from: "other" },
    { ...direct(4, 100), timestamp: 101 }, { ...direct(5, 100), timestamp: 10 },
    { ...direct(6, 100), blockNumber: 101 },
  ] });
  assert.equal(result.candidateReturnRaw, "30");
});

test("baseline must be internally valid and never regresses under greedy conflicts", () => {
  assert.throws(() => select({ baseline: [direct(1, 30), direct(1, 30)] }), /overlapping/);
  const baseline = [direct(1, 20), direct(2, 20)];
  assert.equal(select({ baseline }).candidateReturnRaw, "40");
});

test("relay credit is the minimum hop and insufficient forwarding is rejected", () => {
  const candidates = [
    { evidenceType: "RELAY_PATH", hops: [hop(2, 40, "seller", "relay", 20), hop(3, 20, "relay", "funder", 21)] },
    { evidenceType: "RELAY_PATH", hops: [hop(4, 1000, "seller", "relay", 20), hop(5, 20, "relay", "funder", 21)] },
  ];
  assert.equal(select({ candidates }).candidateReturnRaw, "50");
});
