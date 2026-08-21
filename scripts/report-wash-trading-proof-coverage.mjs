#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { createHash } from "node:crypto";

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
  const bundlePath = value("--bundle");
  const planPath = value("--plan");
  const resultsPath = value("--results");
  const outPath = value("--out");
  if (!bundlePath || !planPath || !outPath) throw new Error("usage: node report-wash-trading-proof-coverage.mjs --bundle proof-bundle.json --plan proof-plan.json [--results proof-results.json] --out proof-coverage.json");
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  const results = resultsPath ? JSON.parse(await readFile(resultsPath, "utf8")) : null;
  const report = buildCoverageReport(bundle, plan, results);
  await writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`wrote coverage for ${report.claims.resultCount}/${report.claims.reportCount} claims to ${outPath}`);
}

export function buildCoverageReport(bundle, plan, results = null) {
  if (bundle?.version !== 1 || plan?.version !== 2 || bundle.reportRoot !== plan.reportRoot) throw new Error("bundle and plan do not share the current report root");
  const bundleClaims = new Map(bundle.claims.map((claim) => [claim.claimId, claim]));
  const plannedClaims = new Map(plan.claims.map((claim) => [claim.claimId, claim]));
  if (bundleClaims.size !== bundle.claims.length) throw new Error("proof bundle contains duplicate claim IDs");
  if (plannedClaims.size !== plan.claimCount || plannedClaims.size !== plan.claims.length) throw new Error("proof plan contains duplicate claim IDs or an invalid claim count");
  const resultEntries = new Map((results?.entries ?? []).map((entry) => [entry.claimId, entry]));
  if (results && (results.version !== 2
      || results.kind !== "antseed-wash-trading-proof-results"
      || results.reportRoot !== bundle.reportRoot
      || results.chainId !== bundle.chainId
      || !Array.isArray(results.entries)
      || resultEntries.size !== results.entries.length)) {
    throw new Error("proof results do not match the bundle or contain duplicate claim IDs");
  }
  if (results && !["development", "production"].includes(results.securityMode)) throw new Error("proof results use an unknown security mode");
  for (const [claimId, result] of resultEntries) {
    const planned = plannedClaims.get(claimId);
    if (!planned) throw new Error(`${claimId}: result is absent from proof plan`);
    validateResultEntry(result, planned, results.securityMode);
  }

  let cohortReportVolume = 0n;
  let reciprocalReportVolume = 0n;
  for (const claim of bundle.claims) {
    if (claim.type === "P0_RECIPROCAL") reciprocalReportVolume += BigInt(claim.metrics.volumeAToBRaw) + BigInt(claim.metrics.volumeBToARaw);
    else cohortReportVolume += BigInt(claim.metrics.qualifiedVolumeRaw);
  }

  const selectedLogs = new Map();
  const perClaim = [];
  for (const [claimId, planned] of plannedClaims) {
    const claim = bundleClaims.get(claimId);
    if (!claim) throw new Error(`${claimId}: planned claim is absent from bundle`);
    if (planned.type !== claim.type || JSON.stringify(planned.subjects) !== JSON.stringify(claim.subjects)) {
      throw new Error(`${claimId}: proof plan identity differs from bundle`);
    }
    let selectedVolume = 0n;
    let selectedSettlements = 0;
    for (const evidence of planned.selectedEvidence) {
      if (!["SETTLEMENT", "RECIPROCAL_SETTLEMENT"].includes(evidence.evidenceType)) continue;
      const dependency = JSON.parse(evidence.dependencyLeaf);
      const receiptLogIndex = evidence.receiptLogIndex ?? dependency.logIndex;
      if (!Number.isSafeInteger(receiptLogIndex) || receiptLogIndex < 0) throw new Error(`${claimId}: settlement lacks an authenticated receipt log index`);
      const identity = `${dependency.transactionHash}:${receiptLogIndex}`.toLowerCase();
      const amount = BigInt(dependency.amountRaw);
      selectedVolume += amount;
      selectedSettlements += 1;
      const existing = selectedLogs.get(identity);
      if (existing != null && existing !== amount) throw new Error(`${claimId}: conflicting amount for ${identity}`);
      selectedLogs.set(identity, amount);
    }
    const result = resultEntries.get(claimId);
    perClaim.push({
      claimId,
      claimType: claim.type,
      subjects: claim.subjects,
      resultStatus: result ? results.securityMode : "planned",
      reportClassifiedVolumeRaw: reportVolume(claim).toString(),
      authenticatedSelectedVolumeRaw: selectedVolume.toString(),
      authenticatedSettlementCount: selectedSettlements,
      selectedEvidenceCount: planned.selectedEvidence.length,
      selectedBlockCount: planned.selectedBlocks.length,
      materializationBlockCount: planned.materializationBlocks.length,
      optimizationMode: planned.optimizationMode ?? null,
      instructionCount: result?.instructionCount ?? null,
      programVKey: result?.programVKey ?? null,
    });
  }
  const uniqueSelectedVolume = [...selectedLogs.values()].reduce((total, amount) => total + amount, 0n);
  const cohortSelectedVolume = perClaim.filter((claim) => claim.claimType !== "P0_RECIPROCAL")
    .reduce((total, claim) => total + BigInt(claim.authenticatedSelectedVolumeRaw), 0n);
  const reciprocalSelectedVolume = perClaim.filter((claim) => claim.claimType === "P0_RECIPROCAL")
    .reduce((total, claim) => total + BigInt(claim.authenticatedSelectedVolumeRaw), 0n);
  const completed = results == null ? 0 : perClaim.filter((claim) => resultEntries.has(claim.claimId)).length;
  return {
    version: 1,
    kind: "antseed-wash-trading-proof-coverage",
    chainId: bundle.chainId,
    reportRoot: bundle.reportRoot,
    period: bundle.period,
    securityMode: results?.securityMode ?? "planned",
    claims: {
      reportCount: bundle.claims.length,
      planCount: plannedClaims.size,
      resultCount: completed,
      byType: countByType(perClaim),
    },
    reportRootClassifiedVolume: {
      cohortQualifiedVolumeRaw: cohortReportVolume.toString(),
      reciprocalDirectionalVolumeRaw: reciprocalReportVolume.toString(),
      combinedRawNotDeduplicated: (cohortReportVolume + reciprocalReportVolume).toString(),
      note: "Cohort and reciprocal policy totals may overlap and must not be presented as a deduplicated global total.",
    },
    authenticatedSelectedVolume: {
      uniqueAcrossAllClaimsRaw: uniqueSelectedVolume.toString(),
      cohortRawBeforeCrossPolicyDeduplication: cohortSelectedVolume.toString(),
      reciprocalRawBeforeCrossPolicyDeduplication: reciprocalSelectedVolume.toString(),
      uniqueSettlementLogCount: selectedLogs.size,
      cohortCoverageBps: ratioBps(cohortSelectedVolume, cohortReportVolume),
      reciprocalCoverageBps: ratioBps(reciprocalSelectedVolume, reciprocalReportVolume),
      productionProvenRaw: results?.securityMode === "production" && completed === plannedClaims.size ? uniqueSelectedVolume.toString() : "0",
      developmentValidatedRaw: results?.securityMode === "development" && completed === plannedClaims.size ? uniqueSelectedVolume.toString() : "0",
    },
    interpretation: [
      "Every completed claim proves its compact enforcement predicate and approved-report membership.",
      "Authenticated selected volume is the unique USDC settlement amount actually included in the compact proofs.",
      "Report-root classified volume is governance-approved completeness data; the report bundle does not authenticate every contributing settlement.",
      "Development executions are validation tests and cannot be submitted as production SP1 proofs.",
    ],
    perClaim,
  };
}

function validateResultEntry(result, planned, securityMode) {
  if (result.claimType !== planned.type || JSON.stringify(result.subjects) !== JSON.stringify(planned.subjects)) {
    throw new Error(`${planned.claimId}: result identity differs from proof plan`);
  }
  if (!/^0x[0-9a-f]{64}$/i.test(result.programVKey ?? "")) throw new Error(`${planned.claimId}: invalid SP1 program vkey`);
  if (!/^0x[0-9a-f]+$/i.test(result.journalBytes ?? "") || !/^0x[0-9a-f]{64}$/i.test(result.journalDigest ?? "")) {
    throw new Error(`${planned.claimId}: invalid journal encoding`);
  }
  const digest = `0x${createHash("sha256").update(Buffer.from(result.journalBytes.slice(2), "hex")).digest("hex")}`;
  if (digest.toLowerCase() !== result.journalDigest.toLowerCase()) throw new Error(`${planned.claimId}: journal digest mismatch`);
  if (securityMode === "production" && (!result.proofBytes || result.proofBytes === "0x")) throw new Error(`${planned.claimId}: SP1 proof bytes missing`);
  const plannedDependencies = planned.selectedEvidence.map((entry) => entry.dependencyId);
  const resultDependencies = (result.selectedEvidence ?? []).map((entry) => entry.dependencyId);
  if (JSON.stringify(resultDependencies) !== JSON.stringify(plannedDependencies)
      || JSON.stringify(result.selectedBlocks) !== JSON.stringify(planned.selectedBlocks)) {
    throw new Error(`${planned.claimId}: result evidence differs from proof plan`);
  }
}

function reportVolume(claim) {
  return claim.type === "P0_RECIPROCAL"
    ? BigInt(claim.metrics.volumeAToBRaw) + BigInt(claim.metrics.volumeBToARaw)
    : BigInt(claim.metrics.qualifiedVolumeRaw);
}

function countByType(claims) {
  const result = {};
  for (const claim of claims) result[claim.claimType] = (result[claim.claimType] ?? 0) + 1;
  return result;
}

function ratioBps(numerator, denominator) {
  return denominator === 0n ? null : Number(numerator * 10_000n / denominator);
}

if (process.argv[1] && basename(process.argv[1]) === basename(new URL(import.meta.url).pathname)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
