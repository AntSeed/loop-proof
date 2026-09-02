import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { loadCurrentChildProof, writeStableRunConfig } from "./prove-approved-batch.mjs";

const claimId = `0x${"1".repeat(64)}`;
const programId = `0x${"2".repeat(64)}`;
const programVKey = `0x${"3".repeat(64)}`;
const entry = { kind: "reciprocal", claim: { claimId } };
const guests = { reciprocal: { programVKey } };

async function withCheckpoint(run) {
  const directory = await mkdtemp(join(tmpdir(), "wash-paid-child-"));
  const proofPath = join(directory, `000-${claimId}.proof.bin`);
  const metadataPath = proofPath.replace(/\.bin$/, ".json");
  const artifact = {
    version: 2,
    kind: "antseed-wash-trading-child-proof",
    securityMode: "production",
    childKind: "reciprocal",
    sourceClaimId: claimId,
    programId,
    programVKey,
    publicValues: "0x1234",
    proofPath,
    verified: true,
  };
  await writeFile(proofPath, Buffer.from([1, 2, 3]));
  await writeFile(metadataPath, JSON.stringify(artifact));
  try {
    await run({ artifact, metadataPath, proofPath });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("accepts a verified version 2 paid child checkpoint", async () => {
  await withCheckpoint(async ({ artifact, proofPath }) => {
    assert.deepEqual(await loadCurrentChildProof(proofPath, entry, guests), artifact);
  });
});

test("rejects stale or incomplete paid child checkpoints", async () => {
  const invalidArtifacts = [
    { version: 1 },
    { kind: "wrong-kind" },
    { securityMode: "development" },
    { childKind: "closed-loop" },
    { sourceClaimId: `0x${"4".repeat(64)}` },
    { programVKey: `0x${"5".repeat(64)}` },
    { verified: false },
    { programId: "0x12" },
    { publicValues: "0x" },
    { proofPath: "/tmp/not-the-paid-proof.bin" },
  ];

  for (const mutation of invalidArtifacts) {
    await withCheckpoint(async ({ artifact, metadataPath, proofPath }) => {
      await writeFile(metadataPath, JSON.stringify({ ...artifact, ...mutation }));
      await assert.rejects(
        loadCurrentChildProof(proofPath, entry, guests),
        /stale or invalid paid child checkpoint/,
      );
    });
  }

  await withCheckpoint(async ({ metadataPath, proofPath }) => {
    await writeFile(proofPath, Buffer.alloc(0));
    assert.ok((await readFile(metadataPath)).length > 0);
    await assert.rejects(
      loadCurrentChildProof(proofPath, entry, guests),
      /incomplete paid child checkpoint/,
    );
  });
});

test("accepts the existing paid canary checkpoint when present", async (context) => {
  const proofPath = resolve(
    "out/volume-only-historical-production/children/015-0x6823dd5771573fa4f0aafa03834fc6fcd8196405e7876df98500cd9d441ccdcf.proof.bin",
  );
  try {
    await readFile(proofPath);
  } catch {
    context.skip("paid canary checkpoint is not present");
    return;
  }
  const canaryEntry = {
    kind: "reciprocal",
    claim: { claimId: "0x6823dd5771573fa4f0aafa03834fc6fcd8196405e7876df98500cd9d441ccdcf" },
  };
  const canaryGuests = {
    reciprocal: { programVKey: "0x00cf7dec75c4c5b920f17ec0935971e03f1880d335e00e5cb430a964d9d03c58" },
  };
  const artifact = await loadCurrentChildProof(proofPath, canaryEntry, canaryGuests);
  assert.equal(artifact.verified, true);
});

test("rotates only the approved quote digest for a stable paid run", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wash-paid-run-"));
  const path = join(directory, "full.json");
  const original = {
    version: 1,
    kind: "antseed-wash-trading-production-run",
    sources: {
      proofBundleSha256: `0x${"4".repeat(64)}`,
      proofPlanSha256: `0x${"5".repeat(64)}`,
      guestAttestationSha256: `0x${"6".repeat(64)}`,
      quoteDigest: `0x${"7".repeat(64)}`,
    },
    networkLimits: { maxPricePerPguWei: "660000000" },
  };
  const replacement = structuredClone(original);
  replacement.sources.quoteDigest = `0x${"8".repeat(64)}`;
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
