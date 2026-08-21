import assert from "node:assert/strict";
import test from "node:test";
import { approveCostQuote, buildCostQuote } from "./proving-cost-quote.mjs";

test("aggregate proving quote requires exact digest approval", () => {
  const now = new Date("2026-08-21T00:00:00.000Z");
  const quote = buildCostQuote({
    checkpointPlan: { version: 1, chain_id: 8_453, proofs: [{}, {}] },
    proofPlan: { version: 1, kind: "antseed-wash-trading-proof-plan", chainId: 8_453, claims: new Array(26).fill({}) },
    checkpointUnitUsd: "2.50",
    historicalUnitUsd: "0.10",
    p0UnitUsd: "1.25",
    provider: "test-provider",
    expiresAt: "2026-08-22T00:00:00.000Z",
    now,
  });
  assert.equal(quote.body.aggregateMaxCostUsd, "48.700000");
  assert.throws(() => approveCostQuote(quote, `0x${"0".repeat(64)}`, { checkpointProofs: 2, p0Claims: 26 }, now), /explicit approval/);
  assert.equal(approveCostQuote(quote, quote.digest, { checkpointProofs: 2, historicalChunks: 112, p0Claims: 26 }, now), quote);
});
