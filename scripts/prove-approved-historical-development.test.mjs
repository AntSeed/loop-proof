import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadCurrentArtifact } from "./prove-approved-historical-development.mjs";

test("historical replay rejects artifacts without a positive authenticated total", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wash-vt-artifact-"));
  const path = join(directory, "seller.json");
  const seller = `0x${"1".repeat(40)}`;
  const artifact = {
    version: 1,
    kind: "antseed-wash-trading-seller-witness",
    proofArchitecture: "direct-seller-v1",
    evidenceFormat: "single-bundle-v1",
    alphaReturnBps: 3000,
    sourceClaimIds: ["source"],
    securityMode: "development",
    seller,
    claimCount: 1,
    periodStartBlock: 10,
    periodEndBlock: 19,
    verified: true,
    totalSellerVolumeRaw: "200",
  };
  const load = () => loadCurrentArtifact(path, seller, { startBlock: 10, endBlockExclusive: 20 }, 1, "witness-only", null);
  try {
    await writeFile(path, JSON.stringify(artifact));
    assert.deepEqual(await load(), artifact);
    for (const totalSellerVolumeRaw of [undefined, "0", "-1", "abc"]) {
      await writeFile(path, JSON.stringify({ ...artifact, totalSellerVolumeRaw }));
      assert.equal(await load(), null);
    }
    for (const mutation of [{ alphaReturnBps: undefined }, { alphaReturnBps: 2000 }, { alphaReturnBps: 5000 }, { claimCount: 2 }, { evidenceFormat: undefined }, { sourceClaimIds: [] }, { sourceClaimIds: "a" }, { sourceClaimIds: ["first", "second"] }]) {
      await writeFile(path, JSON.stringify({ ...artifact, ...mutation }));
      assert.equal(await load(), null);
    }
    const sellerProgramVKey = `0x${"2".repeat(64)}`;
    const proof = { ...artifact, version: 3, kind: "antseed-wash-trading-seller-proof", proved: true, proofBytes: "0x1234", sellerProgramVKey };
    await writeFile(path, JSON.stringify(proof));
    const loadProof = (expectedKey) => loadCurrentArtifact(path, seller, { startBlock: 10, endBlockExclusive: 20 }, 1, "development", expectedKey);
    assert.equal(await loadProof(null), null);
    assert.equal(await loadProof(`0x${"3".repeat(64)}`), null);
    assert.deepEqual(await loadProof(sellerProgramVKey), proof);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
