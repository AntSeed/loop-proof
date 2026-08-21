import assert from "node:assert/strict";
import test from "node:test";
import { approveCostQuote, buildCostQuote } from "./proving-cost-quote.mjs";

test("aggregate proving quote requires exact digest approval", () => {
  const now = new Date("2026-08-21T00:00:00.000Z");
  const quote = buildCostQuote({
    accumulatorManifest: { version: 2, kind: "antseed-history-accumulator-artifacts", chainId: 8_453, epochCount: 334, epochs: new Array(334).fill({}) },
    proofPlan: { version: 2, kind: "antseed-wash-trading-proof-plan", chainId: 8_453, claims: new Array(26).fill({}) },
    epochUnitUsd: "0.10",
    aggregateUnitUsd: "2.50",
    p0UnitUsd: "1.25",
    provider: "test-provider",
    expiresAt: "2026-08-22T00:00:00.000Z",
    now,
  });
  assert.equal(quote.body.aggregateMaxCostUsd, "68.400000");
  assert.throws(() => approveCostQuote(quote, `0x${"0".repeat(64)}`, { epochProofs: 334, p0Claims: 26 }, now), /explicit approval/);
  assert.equal(approveCostQuote(quote, quote.digest, { epochProofs: 334, aggregateProofs: 1, p0Claims: 26 }, now), quote);
});
