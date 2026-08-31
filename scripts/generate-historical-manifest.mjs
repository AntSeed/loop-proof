#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

export function historicalManifestFromBundle(bundle) {
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle"
      || bundle.chainId !== 8_453 || !Array.isArray(bundle.claims) || bundle.claims.length === 0) {
    throw new Error("invalid historical proof bundle");
  }
  const sourceIds = new Set();
  const sellers = new Set();
  const reportRoot = merkleRoot(bundle.claims.map((claim) => normalizeHash(claim.leafHash, "claim leafHash")));
  if (reportRoot !== normalizeHash(bundle.reportRoot, "reportRoot")) {
    throw new Error(`bundle report root mismatch: calculated ${reportRoot}`);
  }
  const claims = bundle.claims.map((claim) => {
    const sourceClaimId = normalizeHash(claim.claimId, "claimId");
    if (sourceIds.has(sourceClaimId)) throw new Error(`duplicate source claim ${sourceClaimId}`);
    sourceIds.add(sourceClaimId);
    const subjects = claimSubjects(claim).map(({ seller, volume }) => {
      const normalizedSeller = normalizeAddress(seller);
      if (sellers.has(normalizedSeller)) {
        throw new Error(`seller ${normalizedSeller} appears in more than one approved claim`);
      }
      sellers.add(normalizedSeller);
      const provenWashVolume = BigInt(volume);
      if (provenWashVolume <= 0n || provenWashVolume > (1n << 128n) - 1n) {
        throw new Error(`${sourceClaimId}: invalid proven wash volume`);
      }
      return { seller: normalizedSeller, proven_wash_volume: provenWashVolume.toString() };
    });
    subjects.sort((left, right) => left.seller.localeCompare(right.seller));
    return {
      source_claim_id: sourceClaimId,
      predicate_id: claim.type === "P0_CLOSED_LOOP" ? 1 : 2,
      period_start_block: claim.period?.startBlock ?? bundle.period.startBlock,
      period_end_block: (claim.period?.endBlockExclusive ?? bundle.period.endBlockExclusive) - 1,
      subjects,
    };
  });
  claims.sort((left, right) => left.source_claim_id.localeCompare(right.source_claim_id));
  return {
    report_root: reportRoot,
    period_start_block: bundle.period.startBlock,
    period_end_block: bundle.period.endBlockExclusive - 1,
    closed_loop_program_vkey: `0x${"00".repeat(32)}`,
    reciprocal_program_vkey: `0x${"00".repeat(32)}`,
    claims,
    block_refs: [],
  };
}

function claimSubjects(claim) {
  if (claim.type === "P0_CLOSED_LOOP") {
    if (claim.subjects?.length !== 1) throw new Error(`${claim.claimId}: invalid closed-loop subjects`);
    return [{ seller: claim.subjects[0], volume: claim.metrics?.qualifiedVolumeRaw }];
  }
  if (claim.type === "P0_RECIPROCAL") {
    if (!claim.walletA || !claim.walletB) throw new Error(`${claim.claimId}: invalid reciprocal subjects`);
    return [
      { seller: claim.walletA, volume: claim.metrics?.volumeBToARaw },
      { seller: claim.walletB, volume: claim.metrics?.volumeAToBRaw },
    ];
  }
  throw new Error(`${claim.claimId}: unsupported claim type ${claim.type}`);
}

function normalizeHash(value, label) {
  if (!/^0x[0-9a-f]{64}$/i.test(value ?? "")) throw new Error(`invalid ${label}`);
  return value.toLowerCase();
}

function normalizeAddress(value) {
  if (!/^0x[0-9a-f]{40}$/i.test(value ?? "")) throw new Error(`invalid seller address ${value}`);
  return value.toLowerCase();
}

function merkleRoot(hashes) {
  let level = [...hashes].sort();
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = Buffer.from(level[index].slice(2), "hex");
      const right = Buffer.from((level[index + 1] ?? level[index]).slice(2), "hex");
      next.push(`0x${createHash("sha256").update(Buffer.concat([Buffer.from([1]), left, right])).digest("hex")}`);
    }
    level = next;
  }
  return level[0];
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const index = args.indexOf(flag);
    return index < 0 ? null : args[index + 1];
  };
  const bundlePath = value("--bundle");
  const outputPath = value("--output");
  if (!bundlePath || !outputPath) {
    throw new Error("usage: generate-historical-manifest.mjs --bundle proof-bundle.json --output manifest.json");
  }
  const manifest = historicalManifestFromBundle(JSON.parse(await readFile(resolve(bundlePath), "utf8")));
  await writeFile(resolve(outputPath), `${JSON.stringify(manifest, null, 2)}\n`);
}
