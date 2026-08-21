#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";

const USD_SCALE = 1_000_000n;

export function buildCostQuote({ accumulatorManifest, proofPlan, epochUnitUsd, aggregateUnitUsd, p0UnitUsd, provider, expiresAt, now = new Date() }) {
  validateAccumulatorManifest(accumulatorManifest);
  if (proofPlan?.version !== 2 || proofPlan.kind !== "antseed-wash-trading-proof-plan" || proofPlan.chainId !== 8_453 || proofPlan.claims?.length !== 26) throw new Error("proof plan must contain exactly 26 Base claims");
  if (typeof provider !== "string" || provider.length === 0) throw new Error("cost quote provider is required");
  const expiration = new Date(expiresAt);
  if (!Number.isFinite(expiration.getTime()) || expiration <= now) throw new Error("cost quote expiration must be in the future");
  const counts = { epochProofs: accumulatorManifest.epochCount, aggregateProofs: 1, p0Claims: proofPlan.claims.length };
  const unitMicros = {
    epochProofUsd: parseUsd(epochUnitUsd, "epoch proof unit cost"),
    aggregateProofUsd: parseUsd(aggregateUnitUsd, "aggregate proof unit cost"),
    p0ClaimUsd: parseUsd(p0UnitUsd, "P0 unit cost"),
  };
  const totalMicros = unitMicros.epochProofUsd * BigInt(counts.epochProofs)
    + unitMicros.aggregateProofUsd * BigInt(counts.aggregateProofs)
    + unitMicros.p0ClaimUsd * BigInt(counts.p0Claims);
  const body = {
    version: 3,
    kind: "antseed-sp1-proof-cost-quote",
    chainId: 8_453,
    currency: "USD",
    provider,
    generatedAt: now.toISOString(),
    expiresAt: expiration.toISOString(),
    counts,
    unitMaxCostUsd: Object.fromEntries(Object.entries(unitMicros).map(([key, amount]) => [key, formatUsd(amount)])),
    aggregateMaxCostUsd: formatUsd(totalMicros),
    sources: {
      accumulatorManifestSha256: sha256(canonicalJson(accumulatorManifest)),
      proofPlanSha256: sha256(canonicalJson(proofPlan)),
    },
  };
  return { body, digest: quoteDigest(body) };
}

export function approveCostQuote(quote, approvedDigest, expectedCounts, now = new Date()) {
  if (quote?.body?.version !== 3 || quote.body.kind !== "antseed-sp1-proof-cost-quote" || quote.body.chainId !== 8_453 || quote.body.currency !== "USD") throw new Error("unsupported proving cost quote");
  const digest = quoteDigest(quote.body);
  if (quote.digest?.toLowerCase() !== digest.toLowerCase()) throw new Error("proving cost quote digest mismatch");
  if (approvedDigest?.toLowerCase() !== digest.toLowerCase()) throw new Error(`explicit approval requires --approve-cost-digest ${digest}`);
  if (new Date(quote.body.expiresAt) <= now) throw new Error("proving cost quote has expired");
  for (const [key, count] of Object.entries(expectedCounts)) if (quote.body.counts?.[key] !== count) throw new Error(`proving cost quote ${key} mismatch`);
  const expectedTotal = parseUsd(quote.body.unitMaxCostUsd.epochProofUsd, "epoch proof unit cost") * BigInt(quote.body.counts.epochProofs)
    + parseUsd(quote.body.unitMaxCostUsd.aggregateProofUsd, "aggregate proof unit cost") * BigInt(quote.body.counts.aggregateProofs)
    + parseUsd(quote.body.unitMaxCostUsd.p0ClaimUsd, "P0 unit cost") * BigInt(quote.body.counts.p0Claims);
  if (formatUsd(expectedTotal) !== quote.body.aggregateMaxCostUsd) throw new Error("proving cost quote aggregate is invalid");
  return quote;
}

function validateAccumulatorManifest(manifest) {
  if (manifest?.version !== 3 || manifest.kind !== "antseed-sp1-history-accumulator-artifacts" || manifest.chainId !== 8_453
      || !Number.isInteger(manifest.epochCount) || manifest.epochCount <= 0 || manifest.epochs?.length !== manifest.epochCount) {
    throw new Error("unsupported accumulator manifest");
  }
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
  const required = ["--accumulator-manifest", "--proof-plan", "--epoch-unit-usd", "--aggregate-unit-usd", "--p0-unit-usd", "--provider", "--expires-at", "--out"];
  for (const flag of required) if (!value(flag)) throw new Error(`missing ${flag}`);
  const accumulatorManifest = JSON.parse(await readFile(value("--accumulator-manifest"), "utf8"));
  const proofPlan = JSON.parse(await readFile(value("--proof-plan"), "utf8"));
  const quote = buildCostQuote({
    accumulatorManifest,
    proofPlan,
    epochUnitUsd: value("--epoch-unit-usd"),
    aggregateUnitUsd: value("--aggregate-unit-usd"),
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
