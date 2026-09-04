import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadCurrentSellerProof, writeStableRunConfig } from "./prove-approved-batch.mjs";

const seller = `0x${"1".repeat(40)}`;
const sellerProgramVKey = `0x${"2".repeat(64)}`;
const period = { startBlock: 10, endBlockExclusive: 20 };

async function withCheckpoint(run) {
  const directory = await mkdtemp(join(tmpdir(), "wash-paid-seller-"));
  const path = join(directory, `${seller}.json`);
  const artifact = {
    version: 3,
    kind: "antseed-wash-trading-seller-proof",
    proofArchitecture: "direct-seller-v1",
    securityMode: "production",
    seller,
    sellerProgramVKey,
    periodStartBlock: 10,
    periodEndBlock: 19,
    claimCount: 2,
    provenWashVolumeRaw: "100",
    blockReferenceCount: 4,
    publicValues: "0x1234",
    proofBytes: "0xabcd",
    requestId: `0x${"3".repeat(64)}`,
    proved: true,
    verified: true,
  };
  await writeFile(path, JSON.stringify(artifact));
  try {
    await run({ artifact, path });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("accepts a verified version 3 paid direct seller checkpoint", async () => {
  await withCheckpoint(async ({ artifact, path }) => {
    assert.deepEqual(await loadCurrentSellerProof(path, seller, period, 2, sellerProgramVKey), artifact);
  });
});

test("rejects stale or incomplete direct seller checkpoints", async () => {
  const invalidArtifacts = [
    { version: 2 },
    { kind: "wrong-kind" },
    { proofArchitecture: "recursive" },
    { securityMode: "development" },
    { seller: `0x${"4".repeat(40)}` },
    { sellerProgramVKey: `0x${"5".repeat(64)}` },
    { periodEndBlock: 20 },
    { claimCount: 1 },
    { proofBytes: "0x" },
    { requestId: null },
    { proved: false },
    { verified: false },
  ];
  for (const mutation of invalidArtifacts) {
    await withCheckpoint(async ({ artifact, path }) => {
      await writeFile(path, JSON.stringify({ ...artifact, ...mutation }));
      await assert.rejects(
        loadCurrentSellerProof(path, seller, period, 2, sellerProgramVKey),
        /stale or invalid paid direct seller checkpoint/,
      );
    });
  }
});

test("rotates only the approved quote digest for a stable paid run", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wash-paid-run-"));
  const path = join(directory, "full.json");
  const original = {
    version: 2,
    kind: "antseed-wash-trading-production-run",
    proofArchitecture: "direct-seller-v1",
    sources: {
      proofBundleSha256: `0x${"4".repeat(64)}`,
      proofPlanSha256: `0x${"5".repeat(64)}`,
      guestAttestationSha256: `0x${"6".repeat(64)}`,
      sellerElfSha256: `0x${"7".repeat(64)}`,
      quoteDigest: `0x${"8".repeat(64)}`,
    },
    networkLimits: { maxPricePerPguWei: "660000000" },
  };
  const replacement = structuredClone(original);
  replacement.sources.quoteDigest = `0x${"9".repeat(64)}`;
  await writeFile(path, `${JSON.stringify(original, null, 2)}\n`);
  try {
    await writeStableRunConfig(path, replacement, { allowQuoteRotation: true });
    assert.deepEqual(JSON.parse(await readFile(path, "utf8")), replacement);
    const changedLimits = structuredClone(replacement);
    changedLimits.networkLimits.maxPricePerPguWei = "660000001";
    await assert.rejects(
      writeStableRunConfig(path, changedLimits, { allowQuoteRotation: true }),
      /run configuration differs from existing checkpoint/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
