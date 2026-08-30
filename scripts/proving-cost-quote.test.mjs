import assert from "node:assert/strict";
import test from "node:test";
import { approveCostQuote, buildCostQuote } from "./proving-cost-quote.mjs";

test("aggregate proving quote requires exact digest approval", () => {
  const now = new Date("2026-08-21T00:00:00.000Z");
  const quote = buildCostQuote({
    proofPlan: { version: 2, kind: "antseed-wash-trading-proof-plan", chainId: 8_453, claimCount: 35, claims: new Array(35).fill({}) },
    p0UnitUsd: "1.25",
    aggregateUnitUsd: "4.00",
    provider: "test-provider",
    expiresAt: "2026-08-22T00:00:00.000Z",
    now,
  });
  assert.equal(quote.body.aggregateMaxCostUsd, "47.750000");
  assert.throws(() => approveCostQuote(quote, `0x${"0".repeat(64)}`, { p0Claims: 35, aggregates: 1 }, now), /explicit approval/);
  assert.equal(approveCostQuote(quote, quote.digest, { p0Claims: 35, aggregates: 1 }, now), quote);
});
