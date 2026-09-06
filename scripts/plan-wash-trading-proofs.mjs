#!/usr/bin/env node
import { planFile } from "./proof-planner.mjs";

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const bundlePath = value("--bundle");
const outPath = value("--out");
const rpcUrl = value("--rpc-url") ?? process.env.ANTSEED_BASE_RPC_URL ?? process.env.BASE_RPC_URL;
if (!bundlePath || !outPath || !rpcUrl) {
  console.error("usage: node scripts/plan-wash-trading-proofs.mjs --bundle proof-bundle.json --out proof-plan.json [--rpc-url URL]");
  process.exit(2);
}
const claimIds = args.flatMap((argument, index) => argument === "--claim-id" ? [args[index + 1]] : []);
const plan = await planFile({
  bundlePath,
  outPath,
  rpcUrl,
  concurrency: Number(value("--concurrency") ?? 20),
  claimConcurrency: Number(value("--claim-concurrency") ?? 1),
  claimIds: claimIds.length === 0 ? null : claimIds,
  onProgress: (message) => console.error(message),
});
console.log(`planned ${plan.claimCount} claims across ${plan.evidenceBlockSelection.materializationBlockNumbers.length} canonical Base blocks`);
