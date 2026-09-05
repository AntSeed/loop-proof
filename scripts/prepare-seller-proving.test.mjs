import test from "node:test";
import assert from "node:assert/strict";
import { calculateBudget, validateEstimate } from "./prepare-seller-proving.mjs";

test("budget uses measured PGU and exact integer fees, not instruction counts", () => {
  const budget = calculateBudget(["100", "200"], "3", "10", "919");
  assert.equal(budget.totalAtPriceCapWei, "920");
  assert.equal(budget.totalProverGasUnits, "300");
  assert.equal(budget.sufficientAtPriceCap, false);
  assert.equal(budget.shortfallWei, "1");
  assert.equal(calculateBudget(["100", "200"], "3", "10", "920").sufficientAtPriceCap, true);
  assert.equal(calculateBudget(["9007199254740993"], "2", "0", "0").totalAtPriceCapWei, "18014398509481986");
  for (const value of [0, "0", "-1", "1.2", undefined]) assert.throws(() => calculateBudget([value], "3", "0", "0"));
  assert.throws(() => calculateBudget([], "3", "0", "0"));
});

test("execution estimates must retain baseline values and cannot be proofs", () => {
  const baseline = { seller: "seller", instructionCount: 20, publicValues: "0x1234", totalSellerVolumeRaw: "500" };
  const estimate = { ...baseline, securityMode: "development", proved: false, verified: true,
    proverNetworkSubmitted: false, proofBytes: "0x", requestId: null, proverGasUnits: "123" };
  assert.doesNotThrow(() => validateEstimate(estimate, baseline));
  for (const mutation of [{ publicValues: "0x12" }, { totalSellerVolumeRaw: "600" },
    { proved: true }, { securityMode: "production" }, { requestId: "0x1234" },
    { proverNetworkSubmitted: true }, { proverGasUnits: null }, { proverGasUnits: 123 },
    { proverGasUnits: "0" }, { instructionCount: 21 }, { proofBytes: "0x1234" }]) {
    assert.throws(() => validateEstimate({ ...estimate, ...mutation }, baseline));
  }
});
