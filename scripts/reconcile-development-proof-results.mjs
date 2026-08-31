#!/usr/bin/env node
import { readdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function reconcileDevelopmentProofResults({ discovery, bundle, childProofs, aggregate, diagnostics = [] }) {
  if (discovery?.version !== 1 || discovery.kind !== "antseed-p0-loop-discovery" || !Array.isArray(discovery.candidates)) {
    throw new Error("invalid P0 discovery artifact");
  }
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle" || !Array.isArray(bundle.claims)) {
    throw new Error("invalid approved proof bundle");
  }
  if (aggregate?.version !== 1 || aggregate.kind !== "antseed-wash-trading-aggregate-proof"
      || aggregate.securityMode !== "development") {
    throw new Error("invalid development aggregate artifact");
  }

  const claims = new Map(bundle.claims.map((claim) => [claim.claimId.toLowerCase(), claim]));
  const proofsBySeller = new Map();
  for (const proof of childProofs) {
    if (proof?.version !== 1 || proof.kind !== "antseed-wash-trading-development-child-proof"
        || proof.securityMode !== "development" || proof.verified !== true) {
      throw new Error("invalid development child proof artifact");
    }
    const claim = claims.get(String(proof.sourceClaimId).toLowerCase());
    if (!claim) throw new Error(`proof references unapproved claim ${proof.sourceClaimId}`);
    for (const seller of claim.subjects ?? []) {
      const normalized = normalizeAddress(seller);
      if (proofsBySeller.has(normalized)) throw new Error(`multiple proofs for seller ${normalized}`);
      proofsBySeller.set(normalized, { proof, claim });
    }
  }
  if (aggregate.childCount !== childProofs.length || aggregate.sourceClaimCount !== childProofs.length) {
    throw new Error("aggregate does not contain every supplied child proof");
  }

  const diagnosticsBySeller = new Map(diagnostics.map((entry) => [normalizeAddress(entry.seller), entry]));
  const candidates = discovery.candidates.map((candidate) => {
    const seller = normalizeAddress(candidate.seller);
    const validated = proofsBySeller.get(seller);
    if (candidate.state !== "proof_candidate" || !validated) return candidate;
    return {
      ...candidate,
      state: "proof_validated",
      proof: {
        securityMode: validated.proof.securityMode,
        sourceClaimId: validated.proof.sourceClaimId,
        programId: validated.proof.programId,
        programVKey: validated.proof.programVKey,
        publicValues: validated.proof.publicValues,
        proofBytes: validated.proof.proofBytes,
        proofPath: validated.proof.proofPath,
        provenWashVolumeRaw: validated.claim.metrics.qualifiedVolumeRaw,
        aggregateProgramId: aggregate.aggregatorProgramId,
        aggregateProgramVKey: aggregate.aggregatorProgramVKey,
        aggregateReportRoot: aggregate.reportRoot,
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
      version: 1,
      kind: "antseed-wash-trading-development-validation-report",
      securityMode: "development",
      reportRoot: aggregate.reportRoot,
      aggregateProgramId: aggregate.aggregatorProgramId,
      aggregateProgramVKey: aggregate.aggregatorProgramVKey,
      aggregateProvenWashVolumeRaw: aggregate.provenWashVolumeRaw,
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
      : candidate.state === "predicate_rejected"
        ? diagnostics?.deficits ?? "predicate_rejected"
        : null,
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
  const childDirectory = resolve(required(value("--children"), "--children"));
  const aggregatePath = resolve(required(value("--aggregate"), "--aggregate"));
  const diagnosticsPath = value("--diagnostics") ? resolve(value("--diagnostics")) : null;
  const outputPath = resolve(required(value("--output"), "--output"));
  const childProofs = await Promise.all((await readdir(childDirectory))
    .filter((name) => name.endsWith(".proof.json"))
    .sort()
    .map(async (name) => JSON.parse(await readFile(join(childDirectory, name), "utf8"))));
  const result = reconcileDevelopmentProofResults({
    discovery: JSON.parse(await readFile(discoveryPath, "utf8")),
    bundle: JSON.parse(await readFile(bundlePath, "utf8")),
    childProofs,
    aggregate: JSON.parse(await readFile(aggregatePath, "utf8")),
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
