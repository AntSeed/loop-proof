import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadCurrentSellerProof, preflightSellerInputs, writeStableRunConfig } from "./prove-approved-batch.mjs";

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
    evidenceFormat: "single-bundle-v1",
    securityMode: "production",
    seller,
    sellerProgramVKey,
    periodStartBlock: 10,
    periodEndBlock: 19,
    claimCount: 1,
    sourceClaimIds: [`0x${"6".repeat(64)}`],
    provenWashVolumeRaw: "100",
    totalSellerVolumeRaw: "200",
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
    assert.deepEqual(await loadCurrentSellerProof(path, seller, period, 1, sellerProgramVKey), artifact);
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
    { claimCount: 2 },
    { evidenceFormat: undefined },
    { sourceClaimIds: [] },
    { sourceClaimIds: "a" },
    { sourceClaimIds: ["first", "second"] },
    { proofBytes: "0x" },
    { requestId: null },
    { proved: false },
    { verified: false },
    { totalSellerVolumeRaw: undefined },
    { totalSellerVolumeRaw: "0" },
  ];
  for (const mutation of invalidArtifacts) {
    await withCheckpoint(async ({ artifact, path }) => {
      await writeFile(path, JSON.stringify({ ...artifact, ...mutation }));
      await assert.rejects(
        loadCurrentSellerProof(path, seller, period, 1, sellerProgramVKey),
        /stale or invalid paid direct seller checkpoint/,
      );
    });
  }
});

test("paid preflight attempts every seller without enabling paid proving", async () => {
  const directory = await mkdtemp(join(tmpdir(), "wash-native-preflight-"));
  const sellers = [seller, `0x${"4".repeat(40)}`, `0x${"5".repeat(40)}`];
  const attempts = [];
  try {
    await assert.rejects(preflightSellerInputs({
      prover: "test-prover", sellers, period, artifactDir: directory,
      totalVolumeWitnessDir: join(directory, "boundaries"),
      evidenceBySeller: new Map(sellers.map(value => [value, { kind: "closed-loop", witnessPath: "claim.json" }])),
      runVerifier: async (_prover, args) => {
        assert.equal(args[0], "--witness-only");
        assert.ok(!args.includes("--production"));
        assert.ok(!args.includes("--claim"));
        assert.equal(args.filter(argument => argument === "--evidence").length, 1);
        const current = args[args.indexOf("--seller") + 1];
        assert.equal(args[args.indexOf("--total-volume-witness") + 1], join(directory, "boundaries", `${current}.json`));
        attempts.push(current);
        if (current === sellers[1]) throw new Error("not a staked agent at period end");
        await writeFile(args[args.indexOf("--output") + 1], JSON.stringify({
          kind: "antseed-wash-trading-seller-witness", verified: true, proverNetworkSubmitted: false,
          evidenceFormat: "single-bundle-v1", sourceClaimIds: ["source"],
          seller: current, periodStartBlock: 10, periodEndBlock: 19, claimCount: 1,
          provenWashVolumeRaw: "100", totalSellerVolumeRaw: "200",
        }));
      },
    }), /1 seller inputs failed native preflight; no paid requests submitted/);
    assert.deepEqual(attempts, sellers);
    const summary = JSON.parse(await readFile(join(directory, "summary.json"), "utf8"));
    assert.equal(summary.complete, false);
    assert.equal(summary.sellers.length, 2);
    assert.equal(summary.failures[0].seller, sellers[1]);
    assert.match(summary.failures[0].error, /not a staked agent/);
  } finally {
    await rm(directory, { recursive: true, force: true });
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
