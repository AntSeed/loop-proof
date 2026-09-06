#!/usr/bin/env node
import { readdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function reconcileDevelopmentProofResults({ discovery, bundle, sellerProofs, diagnostics = [] }) {
  if (discovery?.version !== 1 || discovery.kind !== "antseed-p0-loop-discovery" || !Array.isArray(discovery.candidates)) {
    throw new Error("invalid P0 discovery artifact");
  }
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle" || !Array.isArray(bundle.claims)) {
    throw new Error("invalid approved proof bundle");
  }
  const claims = new Map(bundle.claims.map((claim) => [claim.claimId.toLowerCase(), claim]));
  const proofsBySeller = new Map();
  let sellerProgramVKey = null;
  for (const proof of sellerProofs) {
    if (proof?.version !== 3 || proof.kind !== "antseed-wash-trading-seller-proof"
        || proof.proofArchitecture !== "direct-seller-v1" || proof.securityMode !== "development"
        || proof.evidenceFormat !== "single-bundle-v1" || proof.claimCount !== 1
        || !/^[1-9][0-9]*$/.test(proof.totalSellerVolumeRaw ?? "")
        || proof.proved !== true || proof.verified !== true
        || !Array.isArray(proof.sourceClaimIds) || proof.sourceClaimIds.length !== 1) {
      throw new Error("invalid development direct seller proof artifact");
    }
    const seller = normalizeAddress(proof.seller);
    if (proofsBySeller.has(seller)) throw new Error(`multiple proofs for seller ${seller}`);
    for (const claimId of proof.sourceClaimIds) {
      const claim = claims.get(String(claimId).toLowerCase());
      if (!claim || !claim.subjects.map(normalizeAddress).includes(seller)) {
        throw new Error(`${seller}: proof references an unapproved seller claim ${claimId}`);
      }
    }
    const vkey = normalizeHash(proof.sellerProgramVKey);
    if (sellerProgramVKey != null && sellerProgramVKey !== vkey) {
      throw new Error("development seller proofs use different program vkeys");
    }
    sellerProgramVKey = vkey;
    proofsBySeller.set(seller, proof);
  }

  const diagnosticsBySeller = new Map(diagnostics.map((entry) => [normalizeAddress(entry.seller), entry]));
  const candidates = discovery.candidates.map((candidate) => {
    const seller = normalizeAddress(candidate.seller);
    const proof = proofsBySeller.get(seller);
    if (candidate.state !== "proof_candidate" || !proof) return candidate;
    return {
      ...candidate,
      state: "proof_validated",
      proof: {
        proofArchitecture: proof.proofArchitecture,
        securityMode: proof.securityMode,
        sourceClaimIds: proof.sourceClaimIds,
        sellerProgramVKey: proof.sellerProgramVKey,
        publicValues: proof.publicValues,
        proofBytes: proof.proofBytes,
        proofPath: proof.proofPath ?? null,
        provenWashVolumeRaw: proof.provenWashVolumeRaw,
        totalSellerVolumeRaw: proof.totalSellerVolumeRaw,
        evidenceDigest: proof.evidenceDigest,
        blockAuthenticationRoot: proof.blockAuthenticationRoot,
      },
    };
  });
  const states = ["not_eligible", "incomplete", "complete_no_loop", "proof_candidate", "predicate_rejected", "proof_validated"];
  const reconciled = {
    ...discovery,
    counts: Object.fromEntries(states.map((state) => [state, candidates.filter((candidate) => candidate.state === state).length])),
    candidates,
  };
  const investigated = candidates
    .filter((candidate) => ["complete_no_loop", "predicate_rejected", "proof_validated"].includes(candidate.state))
    .map((candidate) => sellerResult(candidate, diagnosticsBySeller.get(normalizeAddress(candidate.seller))))
    .sort((left, right) => left.seller.localeCompare(right.seller));
  return {
    discovery: reconciled,
    report: {
      version: 2,
      kind: "antseed-wash-trading-development-validation-report",
      proofArchitecture: "direct-seller-v1",
      securityMode: "development",
      reportRoot: bundle.reportRoot,
      sellerProgramVKey,
      directSellerProofCount: sellerProofs.length,
      totalSellerVolumeRaw: sellerProofs.reduce((total, proof) => total + BigInt(proof.totalSellerVolumeRaw), 0n).toString(),
      totalProvenWashVolumeRaw: sellerProofs
        .reduce((total, proof) => total + BigInt(proof.provenWashVolumeRaw), 0n)
        .toString(),
      investigatedSellerCount: investigated.length,
      sellers: investigated,
    },
  };
}

function sellerResult(candidate, diagnostics) {
  const selectedSettlementRaw = diagnostics?.selectedSettlementRaw ?? candidate.proof?.provenWashVolumeRaw ?? "0";
  const sellerVolumeRaw = diagnostics?.sellerVolumeRaw ?? candidate.eligibility?.sellerVolumeRaw ?? "0";
  const selectedShareBps = diagnostics?.selectedShareBps
    ?? (BigInt(sellerVolumeRaw) === 0n ? 0 : Number(BigInt(selectedSettlementRaw) * 10_000n / BigInt(sellerVolumeRaw)));
  return {
    seller: candidate.seller,
    displayName: candidate.displayName ?? null,
    state: candidate.state,
    recipientTracesRequested: candidate.traceCoverage.requested,
    recipientTracesCompleted: candidate.traceCoverage.completed,
    relayPathCount: candidate.pathCount,
    destinations: [...new Set((candidate.convergences ?? []).map((entry) => entry.destination))].sort(),
    retainedFundingRaw: diagnostics?.retainedFundingRaw ?? null,
    selectedSettlementRaw,
    bottleneckReturnRaw: diagnostics?.bottleneckReturnRaw ?? candidate.bottleneckReturnRaw,
    maximumProvableSellerVolumeShareBps: selectedShareBps,
    proof: candidate.proof ?? null,
    rejectionReason: candidate.state === "complete_no_loop"
      ? "no_fragmented_relay_convergence"
      : candidate.state === "predicate_rejected" ? diagnostics?.deficits ?? "predicate_rejected" : null,
  };
}

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const index = args.indexOf(flag);
    return index < 0 ? null : args[index + 1];
  };
  const discoveryPath = resolve(required(value("--discovery"), "--discovery"));
  const bundlePath = resolve(required(value("--bundle"), "--bundle"));
  const sellerDirectory = resolve(required(value("--sellers"), "--sellers"));
  const diagnosticsPath = value("--diagnostics") ? resolve(value("--diagnostics")) : null;
  const outputPath = resolve(required(value("--output"), "--output"));
  const sellerProofs = await Promise.all((await readdir(sellerDirectory))
    .filter((name) => name.endsWith(".json") && /^0x[0-9a-f]{40}\.json$/i.test(name))
    .sort()
    .map(async (name) => JSON.parse(await readFile(join(sellerDirectory, name), "utf8"))));
  const result = reconcileDevelopmentProofResults({
    discovery: JSON.parse(await readFile(discoveryPath, "utf8")),
    bundle: JSON.parse(await readFile(bundlePath, "utf8")),
    sellerProofs,
    diagnostics: diagnosticsPath ? JSON.parse(await readFile(diagnosticsPath, "utf8")).diagnostics ?? [] : [],
  });
  await writeFile(discoveryPath, `${JSON.stringify(result.discovery, null, 2)}\n`);
  for (const candidate of result.discovery.candidates) {
    const path = join(dirname(discoveryPath), "sellers", `${candidate.seller}.json`);
    try {
      await readFile(path);
      await writeFile(path, `${JSON.stringify(candidate, null, 2)}\n`);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  await writeFile(outputPath, `${JSON.stringify(result.report, null, 2)}\n`);
  console.log(`${basename(outputPath)}: ${result.report.investigatedSellerCount} investigated sellers`);
}

function normalizeAddress(value) {
  if (!/^0x[0-9a-f]{40}$/i.test(value ?? "")) throw new Error(`invalid seller address ${value}`);
  return value.toLowerCase();
}

function normalizeHash(value) {
  if (!/^0x[0-9a-f]{64}$/i.test(value ?? "")) throw new Error(`invalid bytes32 ${value}`);
  return value.toLowerCase();
}

function required(value, flag) {
  if (!value) throw new Error(`missing ${flag}`);
  return value;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
