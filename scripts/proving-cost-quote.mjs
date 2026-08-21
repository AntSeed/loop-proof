#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";

const USD_SCALE = 1_000_000n;

export function buildCostQuote({ checkpointPlan, proofPlan, checkpointUnitUsd, historicalUnitUsd, p0UnitUsd, provider, expiresAt, now = new Date() }) {
  if (checkpointPlan?.version !== 1 || checkpointPlan.chain_id !== 8_453 || !Array.isArray(checkpointPlan.proofs) || checkpointPlan.proofs.length === 0) throw new Error("unsupported checkpoint plan");
  if (proofPlan?.version !== 1 || proofPlan.kind !== "antseed-wash-trading-proof-plan" || proofPlan.chainId !== 8_453 || proofPlan.claims?.length !== 26) throw new Error("proof plan must contain exactly 26 Base claims");
  if (typeof provider !== "string" || provider.length === 0) throw new Error("cost quote provider is required");
  const expiration = new Date(expiresAt);
  if (!Number.isFinite(expiration.getTime()) || expiration <= now) throw new Error("cost quote expiration must be in the future");
  const counts = { checkpointProofs: checkpointPlan.proofs.length, historicalChunks: 112, p0Claims: proofPlan.claims.length };
  const unitMicros = {
    checkpointProofUsd: parseUsd(checkpointUnitUsd, "checkpoint unit cost"),
    historicalChunkUsd: parseUsd(historicalUnitUsd, "historical unit cost"),
    p0ClaimUsd: parseUsd(p0UnitUsd, "P0 unit cost"),
  };
  const totalMicros = unitMicros.checkpointProofUsd * BigInt(counts.checkpointProofs)
    + unitMicros.historicalChunkUsd * BigInt(counts.historicalChunks)
    + unitMicros.p0ClaimUsd * BigInt(counts.p0Claims);
  const body = {
    version: 1,
    kind: "antseed-proof-cost-quote",
    chainId: 8_453,
    currency: "USD",
    provider,
    generatedAt: now.toISOString(),
    expiresAt: expiration.toISOString(),
    counts,
    unitMaxCostUsd: Object.fromEntries(Object.entries(unitMicros).map(([key, amount]) => [key, formatUsd(amount)])),
    aggregateMaxCostUsd: formatUsd(totalMicros),
    sources: {
      checkpointPlanSha256: sha256(canonicalJson(checkpointPlan)),
      proofPlanSha256: sha256(canonicalJson(proofPlan)),
    },
  };
  return { body, digest: quoteDigest(body) };
}

export function approveCostQuote(quote, approvedDigest, expectedCounts, now = new Date()) {
  if (quote?.body?.version !== 1 || quote.body.kind !== "antseed-proof-cost-quote" || quote.body.chainId !== 8_453 || quote.body.currency !== "USD") throw new Error("unsupported proving cost quote");
  const digest = quoteDigest(quote.body);
  if (quote.digest?.toLowerCase() !== digest.toLowerCase()) throw new Error("proving cost quote digest mismatch");
  if (approvedDigest?.toLowerCase() !== digest.toLowerCase()) throw new Error(`explicit approval requires --approve-cost-digest ${digest}`);
  if (new Date(quote.body.expiresAt) <= now) throw new Error("proving cost quote has expired");
  for (const [key, count] of Object.entries(expectedCounts)) if (quote.body.counts?.[key] !== count) throw new Error(`proving cost quote ${key} mismatch`);
  const expectedTotal = parseUsd(quote.body.unitMaxCostUsd.checkpointProofUsd, "checkpoint unit cost") * BigInt(quote.body.counts.checkpointProofs)
    + parseUsd(quote.body.unitMaxCostUsd.historicalChunkUsd, "historical unit cost") * BigInt(quote.body.counts.historicalChunks)
    + parseUsd(quote.body.unitMaxCostUsd.p0ClaimUsd, "P0 unit cost") * BigInt(quote.body.counts.p0Claims);
  if (formatUsd(expectedTotal) !== quote.body.aggregateMaxCostUsd) throw new Error("proving cost quote aggregate is invalid");
  return quote;
}

function quoteDigest(body) {
  return sha256(canonicalJson(body));
}

function parseUsd(value, label) {
  if (typeof value !== "string" || !/^\d+(?:\.\d{1,6})?$/.test(value)) throw new Error(`${label} must be a nonnegative USD amount with at most six decimals`);
  const [whole, fraction = ""] = value.split(".");
  return BigInt(whole) * USD_SCALE + BigInt(fraction.padEnd(6, "0"));
}

function formatUsd(micros) {
  const whole = micros / USD_SCALE;
  const fraction = (micros % USD_SCALE).toString().padStart(6, "0");
  return `${whole}.${fraction}`;
}

function sha256(value) {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
  const required = ["--checkpoint-plan", "--proof-plan", "--checkpoint-unit-usd", "--historical-unit-usd", "--p0-unit-usd", "--provider", "--expires-at", "--out"];
  for (const flag of required) if (!value(flag)) throw new Error(`missing ${flag}`);
  const checkpointPlan = JSON.parse(await readFile(value("--checkpoint-plan"), "utf8"));
  const proofPlan = JSON.parse(await readFile(value("--proof-plan"), "utf8"));
  const quote = buildCostQuote({
    checkpointPlan,
    proofPlan,
    checkpointUnitUsd: value("--checkpoint-unit-usd"),
    historicalUnitUsd: value("--historical-unit-usd"),
    p0UnitUsd: value("--p0-unit-usd"),
    provider: value("--provider"),
    expiresAt: value("--expires-at"),
  });
  await writeFile(value("--out"), `${JSON.stringify(quote, null, 2)}\n`);
  console.log(`aggregateMaxCostUsd ${quote.body.aggregateMaxCostUsd}`);
  console.log(`costQuoteDigest ${quote.digest}`);
}

if (process.argv[1] && basename(process.argv[1]) === basename(new URL(import.meta.url).pathname)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
