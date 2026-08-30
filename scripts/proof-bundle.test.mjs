import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { finalizeBundle, finalizeClaim } from "./proof-bundle.mjs";

const approvedBundlePath = "/Users/alex/.antseed/forensics/wash-trading/scans/2026-08-13T22-54-53-096Z/proof/final-inputs/proof-bundle.json";

test("finalization reproduces approved dependency, claim, leaf, and report identities", async () => {
  const bundle = JSON.parse(await readFile(approvedBundlePath, "utf8"));
  const rebuiltClaims = bundle.claims.map((claim) => {
    const { dependencyRoot: _dependencyRoot, claimId: _claimId, leafHash: _leafHash, ...body } = claim;
    return finalizeClaim({
      ...body,
      dependencies: body.dependencies.map(({ dependencyId: _dependencyId, ...dependency }) => dependency),
    });
  });
  for (let index = 0; index < bundle.claims.length; index += 1) {
    assert.equal(rebuiltClaims[index].dependencyRoot, bundle.claims[index].dependencyRoot);
    assert.equal(rebuiltClaims[index].claimId, bundle.claims[index].claimId);
    assert.equal(rebuiltClaims[index].leafHash, bundle.claims[index].leafHash);
  }
  const { claimCounts: _claimCounts, reportRoot: _reportRoot, claims: _claims, ...header } = bundle;
  assert.equal(finalizeBundle({ ...header, claims: rebuiltClaims }).reportRoot, bundle.reportRoot);
});
