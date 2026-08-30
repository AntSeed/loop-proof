import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { historicalManifestFromBundle } from "./generate-historical-manifest.mjs";

test("historical manifest fixes every approved seller and volume", () => {
  const manifest = historicalManifestFromBundle(bundle());
  assert.equal(manifest.claims.length, 2);
  assert.deepEqual(manifest.claims[0].subjects, [{
    seller: `0x${"11".repeat(20)}`,
    proven_wash_volume: "100",
  }]);
  assert.equal(manifest.claims[1].subjects.length, 2);
  assert.deepEqual(manifest.claims[1].subjects, [
    { seller: `0x${"22".repeat(20)}`, proven_wash_volume: "40" },
    { seller: `0x${"33".repeat(20)}`, proven_wash_volume: "30" },
  ]);
  assert.equal(manifest.claims[0].period_start_block, 10);
  assert.equal(manifest.period_end_block, 19);
});

test("historical manifest rejects sellers reused across claims", () => {
  const fixture = bundle();
  fixture.claims[1].walletA = fixture.claims[0].subjects[0];
  assert.throws(() => historicalManifestFromBundle(fixture), /appears in more than one/);
});

function bundle() {
  const fixture = {
    version: 1,
    kind: "antseed-wash-trading-proof-bundle",
    chainId: 8453,
    reportRoot: `0x${"aa".repeat(32)}`,
    period: { startBlock: 10, endBlockExclusive: 20 },
    claims: [
      {
        claimId: `0x${"01".repeat(32)}`,
        leafHash: `0x${"aa".repeat(32)}`,
        type: "P0_CLOSED_LOOP",
        subjects: [`0x${"11".repeat(20)}`],
        metrics: { qualifiedVolumeRaw: "100" },
      },
      {
        claimId: `0x${"02".repeat(32)}`,
        leafHash: `0x${"bb".repeat(32)}`,
        type: "P0_RECIPROCAL",
        walletA: `0x${"22".repeat(20)}`,
        walletB: `0x${"33".repeat(20)}`,
        metrics: { volumeAToBRaw: "30", volumeBToARaw: "40" },
      },
    ],
  };
  fixture.reportRoot = `0x${createHash("sha256").update(Buffer.concat([
    Buffer.from([1]),
    Buffer.from(fixture.claims[0].leafHash.slice(2), "hex"),
    Buffer.from(fixture.claims[1].leafHash.slice(2), "hex"),
  ])).digest("hex")}`;
  return fixture;
}
