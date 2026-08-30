#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { merkleMembership } from "./proof-planner.mjs";

export function mergeProofPlans(bundle, plans) {
  const plannedById = new Map(plans.flatMap((plan) => plan.claims).map((claim) => [claim.claimId.toLowerCase(), claim]));
  const leafHashes = bundle.claims.map((claim) => claim.leafHash);
  const claims = bundle.claims.map((approved) => {
    const planned = plannedById.get(approved.claimId.toLowerCase());
    if (!planned) throw new Error(`missing planned claim ${approved.claimId}`);
    return {
      ...planned,
      reportRoot: bundle.reportRoot,
      claimMembership: merkleMembership(leafHashes, approved.leafHash),
      selectedEvidence: planned.selectedEvidence.map(compactEvidence),
    };
  });
  const materializationBlockNumbers = [...new Set(claims.flatMap((claim) => claim.selectedBlocks))].sort((left, right) => left - right);
  return {
    version: 2,
    kind: "antseed-wash-trading-proof-plan",
    bundleVersion: bundle.version,
    chainId: bundle.chainId,
    reportRoot: bundle.reportRoot,
    period: bundle.period,
    claimCount: claims.length,
    claims,
    evidenceBlockSelection: {
      version: 1,
      chain_id: bundle.chainId,
      start_block: bundle.period.startBlock,
      end_block_exclusive: bundle.period.endBlockExclusive,
      materializationBlockNumbers,
    },
  };
}

function compactEvidence(evidence) {
  const { dependencyLeaf: _dependencyLeaf, dependencyMembership: _dependencyMembership, ...locator } = evidence;
  if (locator.evidenceType !== "RELAY_PATH") return locator;
  if (Array.isArray(locator.hops)) return { ...locator, hops: locator.hops.map(compactEvidence) };
  return {
    ...locator,
    sellerPayment: compactEvidence(locator.sellerPayment),
    relayForward: compactEvidence(locator.relayForward),
    funderReceipt: compactEvidence(locator.funderReceipt),
  };
}

const args = process.argv.slice(2);
const values = (flag) => args.flatMap((argument, index) => argument === flag ? [args[index + 1]] : []);
if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const bundlePath = values("--bundle")[0];
  const outPath = values("--out")[0];
  const planPaths = values("--plan");
  if (!bundlePath || !outPath || planPaths.length === 0) throw new Error("usage: --bundle FILE --plan FILE... --out FILE");
  const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
  const plans = await Promise.all(planPaths.map(async (path) => JSON.parse(await readFile(path, "utf8"))));
  const merged = mergeProofPlans(bundle, plans);
  await writeFile(outPath, `${JSON.stringify(merged, null, 2)}\n`);
  console.log(`merged ${merged.claimCount} claims across ${merged.evidenceBlockSelection.materializationBlockNumbers.length} blocks`);
}
