import assert from "node:assert/strict";
import test from "node:test";
import { approveCostQuote, buildCostQuote } from "./proving-cost-quote.mjs";

const proofBundle = {
  version: 1,
  kind: "antseed-wash-trading-proof-bundle",
  chainId: 8_453,
  claims: Array.from({ length: 35 }, (_, index) => ({
    claimId: `0x${index.toString(16).padStart(64, "0")}`,
    subjects: [`0x${(index % 3 + 1).toString(16).padStart(40, "0")}`],
  })),
};

test("production quote binds exact digest and network price cap", () => {
  const now = new Date("2026-08-31T00:00:00.000Z");
  const quote = buildCostQuote({
    proofBundle,
    proofPlanSha256: `0x${"1".repeat(64)}`,
    sellerProofUnitUsd: "4.00",
    maxPricePerPguWei: "1000000000000000000",
    proofTimeoutSeconds: "14400",
    auctionTimeoutSeconds: "120",
    provider: "Succinct Prover Network",
    expiresAt: "2026-09-01T00:00:00.000Z",
    now,
  });
  assert.equal(quote.body.aggregateMaxCostUsd, "12.000000");
  assert.equal(quote.body.networkLimits.maxPricePerPguWei, "1000000000000000000");
  assert.throws(() => approveCostQuote(quote, `0x${"0".repeat(64)}`, {
    counts: { sellerProofs: 3 }, seller: null,
  }, now), /explicit approval/);
  assert.equal(approveCostQuote(quote, quote.digest, {
    counts: { sellerProofs: 3 }, seller: null,
  }, now), quote);
});

test("canary quote contains only the selected seller claims", () => {
  const now = new Date("2026-08-31T00:00:00.000Z");
  const seller = proofBundle.claims[0].subjects[0];
  const quote = buildCostQuote({
    proofBundle,
    proofPlanSha256: `0x${"2".repeat(64)}`,
    sellerProofUnitUsd: "5",
    maxPricePerPguWei: "10",
    proofTimeoutSeconds: 60,
    auctionTimeoutSeconds: 30,
    provider: "test",
    expiresAt: "2026-09-01T00:00:00.000Z",
    seller,
    now,
  });
  assert.equal(quote.body.scope.seller, seller);
  assert.equal(quote.body.counts.sellerProofs, 1);
  assert.equal(quote.body.aggregateMaxCostUsd, "5.000000");
});

test("network-price-cap-only quote records no fictional USD limit", () => {
  const now = new Date("2026-08-31T00:00:00.000Z");
  const seller = proofBundle.claims[0].subjects[0];
  const quote = buildCostQuote({
    proofBundle,
    proofPlanSha256: `0x${"3".repeat(64)}`,
    sellerProofUnitUsd: null,
    maxPricePerPguWei: "660000000",
    proofTimeoutSeconds: 14_400,
    auctionTimeoutSeconds: 120,
    provider: "Succinct Prover Network",
    expiresAt: "2026-09-01T00:00:00.000Z",
    seller,
    now,
  });
  assert.equal(quote.body.approvalMode, "network-price-cap-only");
  assert.equal(quote.body.currency, null);
  assert.equal(quote.body.unitMaxCostUsd, null);
  assert.equal(quote.body.aggregateMaxCostUsd, null);
  assert.equal(approveCostQuote(quote, quote.digest, {
    counts: { sellerProofs: 1 }, seller,
  }, now), quote);
});
