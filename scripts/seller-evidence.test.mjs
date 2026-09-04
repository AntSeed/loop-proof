import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sellerEvidenceByAddress } from "./seller-evidence.mjs";
import { preflightSellerInputs } from "./prove-approved-batch.mjs";

const firstSeller = `0x${"a".repeat(40)}`;
const secondSeller = `0x${"b".repeat(40)}`;
const first = { claimId: "first", subjects: [firstSeller] };
const second = { claimId: "second", subjects: [secondSeller] };

test("maps one bundle per seller and preserves a reciprocal pair", () => {
  const reciprocal = { claimId: "pair", subjects: [firstSeller, secondSeller] };
  const entry = { claim: reciprocal, kind: "reciprocal", witnessPath: "pair.json" };
  const result = sellerEvidenceByAddress({ claims: [reciprocal] }, [entry]);
  assert.equal(result.size, 2);
  assert.equal(result.get(firstSeller), entry);
  assert.equal(result.get(secondSeller), entry);
  assert.equal(sellerEvidenceByAddress({ claims: [first, second] }, [{ claim: first }, { claim: second }]).size, 2);
});

test("rejects overlapping sellers, even across evidence kinds or address casing", () => {
  const overlapping = { claimId: "pair", subjects: [firstSeller.toUpperCase(), secondSeller] };
  for (const claims of [[first, overlapping], [overlapping, first]]) {
    assert.throws(() => sellerEvidenceByAddress({ claims }, claims.map(claim => ({ claim }))), /exactly one evidence bundle/);
  }
});

test("rejects missing and duplicate source entries", () => {
  assert.throws(() => sellerEvidenceByAddress({ claims: [first] }, []), /approved evidence is missing/);
  assert.throws(() => sellerEvidenceByAddress({ claims: [first] }, [{ claim: first }, { claim: first }]), /duplicate evidence entry/);
});

test("preflight rejects missing or multi-bundle inputs before executing any seller", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wash-single-evidence-"));
  let calls = 0;
  try {
    const entry = { kind: "closed-loop", witnessPath: "input.json" };
    for (const invalid of [undefined, [], [entry], [entry, entry]]) {
      await assert.rejects(preflightSellerInputs({
        prover: "unused", sellers: [firstSeller, secondSeller],
        evidenceBySeller: new Map([[firstSeller, entry], [secondSeller, invalid]]),
        period: { startBlock: 10, endBlockExclusive: 20 }, artifactDir: directory,
        runVerifier: async () => { calls += 1; },
      }), /exactly one evidence bundle/);
    }
    assert.equal(calls, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
