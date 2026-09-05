import test from "node:test";
import assert from "node:assert/strict";
import { quoteDigest, validateQuote } from "./submit-frozen-seller-canary.mjs";

test("canary approval binds exact scope and expires before new paid requests", () => {
  const body = { version: 1, kind: "frozen-seller-canary-approval", proofCount: 1,
    aip4Compliant: false, rpc: "https://rpc.mainnet.succinct.xyz", requester: `0x${"12".repeat(20)}`,
    expiresAt: "2026-09-06T00:00:00Z" };
  const quote = { body, digest: quoteDigest(body) };
  const now = Date.parse("2026-09-05T00:00:00Z");
  assert.doesNotThrow(() => validateQuote(quote, quote.digest, false, now));
  assert.throws(() => validateQuote(quote, "wrong", false, now));
  assert.throws(() => validateQuote(quote, quote.digest, false, now + 86400000));
  assert.doesNotThrow(() => validateQuote(quote, quote.digest, true, now + 86400000));
  assert.throws(() => validateQuote({ ...quote, body: { ...body, proofCount: 54 } }, quote.digest, false, now));
  for (const mutation of [{ proofCount: 54 }, { aip4Compliant: true }, { rpc: "http://localhost" }, { requester: "other" }]) {
    const changed = { ...body, ...mutation };
    assert.throws(() => validateQuote({ body: changed, digest: quoteDigest(changed) }, quoteDigest(changed), false, now));
  }
});
