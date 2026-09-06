#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";

const USD_SCALE = 1_000_000n;
const MAX_U64 = 18_446_744_073_709_551_615n;

export function buildCostQuote({
  proofBundle,
  proofPlanSha256,
  sellerProofUnitUsd,
  maxPricePerPguWei,
  proofTimeoutSeconds,
  auctionTimeoutSeconds,
  provider,
  expiresAt,
  seller = null,
  now = new Date(),
}) {
  validateBundle(proofBundle);
  if (!/^0x[0-9a-f]{64}$/i.test(proofPlanSha256 ?? "")) throw new Error("proof plan sha256 is required");
  if (typeof provider !== "string" || provider.length === 0) throw new Error("cost quote provider is required");
  const expiration = new Date(expiresAt);
  if (!Number.isFinite(expiration.getTime()) || expiration <= now) throw new Error("cost quote expiration must be in the future");
  const normalizedSeller = seller == null ? null : normalizeSeller(seller);
  const allSellers = new Set(proofBundle.claims.flatMap((claim) => claim.subjects ?? []).map(normalizeSeller));
  if (allSellers.size === 0) throw new Error("proof bundle has no sellers");
  if (normalizedSeller != null && !allSellers.has(normalizedSeller)) throw new Error(`${normalizedSeller}: seller is not approved`);
  const counts = { sellerProofs: normalizedSeller == null ? allSellers.size : 1 };
  const hasUsdLimits = sellerProofUnitUsd != null;
  const sellerProofUsd = hasUsdLimits ? parseUsd(sellerProofUnitUsd, "seller proof unit cost") : null;
  const maxPrice = parseU64(maxPricePerPguWei, "max price per PGU");
  if (maxPrice === 0n) throw new Error("max price per PGU must be nonzero");
  const proofTimeout = positiveInteger(proofTimeoutSeconds, "proof timeout");
  const auctionTimeout = positiveInteger(auctionTimeoutSeconds, "auction timeout");
  const body = {
    version: 6,
    kind: "antseed-sp1-proof-cost-quote",
    chainId: 8_453,
    approvalMode: hasUsdLimits ? "usd-and-network-limits" : "network-price-cap-only",
    currency: hasUsdLimits ? "USD" : null,
    provider,
    generatedAt: now.toISOString(),
    expiresAt: expiration.toISOString(),
    scope: { seller: normalizedSeller },
    counts,
    unitMaxCostUsd: hasUsdLimits
      ? { sellerProofUsd: formatUsd(sellerProofUsd) }
      : null,
    aggregateMaxCostUsd: hasUsdLimits
      ? formatUsd(sellerProofUsd * BigInt(counts.sellerProofs))
      : null,
    networkLimits: {
      maxPricePerPguWei: maxPrice.toString(),
      proofTimeoutSeconds: proofTimeout,
      auctionTimeoutSeconds: auctionTimeout,
    },
    sources: {
      proofBundleSha256: sha256(canonicalJson(proofBundle)),
      proofPlanSha256,
    },
  };
  return { body, digest: quoteDigest(body) };
}

export function approveCostQuote(quote, approvedDigest, expected, now = new Date()) {
  if (quote?.body?.version !== 6 || quote.body.kind !== "antseed-sp1-proof-cost-quote"
      || quote.body.chainId !== 8_453) throw new Error("unsupported proving cost quote");
  const digest = quoteDigest(quote.body);
  if (quote.digest?.toLowerCase() !== digest.toLowerCase()) throw new Error("proving cost quote digest mismatch");
  if (approvedDigest?.toLowerCase() !== digest.toLowerCase()) throw new Error(`explicit approval requires --approve-cost-digest ${digest}`);
  if (new Date(quote.body.expiresAt) <= now) throw new Error("proving cost quote has expired");
  for (const [key, count] of Object.entries(expected.counts)) {
    if (quote.body.counts?.[key] !== count) throw new Error(`proving cost quote ${key} mismatch`);
  }
  const expectedSeller = expected.seller == null ? null : normalizeSeller(expected.seller);
  if (quote.body.scope?.seller !== expectedSeller) throw new Error("proving cost quote seller scope mismatch");
  const approvalMode = quote.body.approvalMode ?? "usd-and-network-limits";
  if (approvalMode === "usd-and-network-limits") {
    if (quote.body.currency !== "USD") throw new Error("USD proving cost quote has invalid currency");
    const expectedTotal = parseUsd(quote.body.unitMaxCostUsd?.sellerProofUsd, "seller proof unit cost")
      * BigInt(quote.body.counts.sellerProofs);
    if (formatUsd(expectedTotal) !== quote.body.aggregateMaxCostUsd) throw new Error("proving cost quote aggregate is invalid");
  } else if (approvalMode === "network-price-cap-only") {
    if (quote.body.currency !== null || quote.body.unitMaxCostUsd !== null || quote.body.aggregateMaxCostUsd !== null) {
      throw new Error("network-price-cap-only quote must not claim USD limits");
    }
  } else {
    throw new Error("unsupported proving cost approval mode");
  }
  const limits = quote.body.networkLimits;
  parseU64(limits?.maxPricePerPguWei, "max price per PGU");
  positiveInteger(limits?.proofTimeoutSeconds, "proof timeout");
  positiveInteger(limits?.auctionTimeoutSeconds, "auction timeout");
  return quote;
}

export async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return `0x${hash.digest("hex")}`;
}

function quoteDigest(body) { return sha256(canonicalJson(body)); }
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
function parseU64(value, label) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`${label} must be an unsigned integer string`);
  const parsed = BigInt(value);
  if (parsed > MAX_U64) throw new Error(`${label} exceeds uint64`);
  return parsed;
}
function positiveInteger(value, label) {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${label} must be a positive integer`);
  return parsed;
}
function normalizeSeller(value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{40}$/i.test(value)) throw new Error(`${value}: invalid seller address`);
  return value.toLowerCase();
}
function validateBundle(bundle) {
  if (bundle?.version !== 1 || bundle.kind !== "antseed-wash-trading-proof-bundle" || bundle.chainId !== 8_453
      || !Array.isArray(bundle.claims) || bundle.claims.length === 0) {
    throw new Error("proof bundle must contain a nonempty approved Base claim set");
  }
}
function sha256(value) { return `0x${createHash("sha256").update(value).digest("hex")}`; }
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

async function main() {
  const args = process.argv.slice(2);
  const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
  const required = ["--bundle", "--proof-plan", "--max-price-per-pgu-wei", "--proof-timeout-seconds", "--auction-timeout-seconds", "--provider", "--expires-at", "--out"];
  for (const flag of required) if (!value(flag)) throw new Error(`missing ${flag}`);
  const networkPriceCapOnly = args.includes("--network-price-cap-only");
  if (!networkPriceCapOnly) {
    for (const flag of ["--seller-proof-unit-usd"]) if (!value(flag)) throw new Error(`missing ${flag}`);
  }
  const proofBundle = JSON.parse(await readFile(value("--bundle"), "utf8"));
  const quote = buildCostQuote({
    proofBundle,
    proofPlanSha256: await sha256File(value("--proof-plan")),
    sellerProofUnitUsd: networkPriceCapOnly ? null : value("--seller-proof-unit-usd"),
    maxPricePerPguWei: value("--max-price-per-pgu-wei"),
    proofTimeoutSeconds: value("--proof-timeout-seconds"),
    auctionTimeoutSeconds: value("--auction-timeout-seconds"),
    provider: value("--provider"),
    expiresAt: value("--expires-at"),
    seller: value("--seller"),
  });
  await writeFile(value("--out"), `${JSON.stringify(quote, null, 2)}\n`);
  console.log(`costQuoteDigest ${quote.digest}`);
  console.log(`aggregateMaxCostUsd ${quote.body.aggregateMaxCostUsd}`);
  console.log(`maxPricePerPguWei ${quote.body.networkLimits.maxPricePerPguWei}`);
}

if (process.argv[1] && basename(process.argv[1]) === basename(new URL(import.meta.url).pathname)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
