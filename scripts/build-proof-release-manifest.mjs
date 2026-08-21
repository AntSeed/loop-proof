#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const artifactFlags = ["--state-plan", "--volume-baseline", "--volume-report", "--proof-plan", "--proof-results", "--accumulator-manifest", "--p0-manifest", "--guest-attestation", "--cost-quote"];
const required = [...artifactFlags, "--contracts-repo", "--signing-key", "--out"];
for (const flag of required) if (!value(flag)) throw new Error(`missing ${flag}`);

const files = Object.fromEntries(artifactFlags.map((flag) => [flag.slice(2).replaceAll("-", "_"), resolve(value(flag))]));
const contractsRepo = resolve(value("--contracts-repo"));
const proofRepo = resolve(new URL("..", import.meta.url).pathname);
assertClean(proofRepo, "proof repository");
assertClean(contractsRepo, "contracts repository");

const [statePlan, baseline, volumeReport, proofPlan, proofResults, accumulator, p0, guests, costQuote] = await Promise.all([
  readJson(files.state_plan), readJson(files.volume_baseline), readJson(files.volume_report), readJson(files.proof_plan), readJson(files.proof_results),
  readJson(files.accumulator_manifest), readJson(files.p0_manifest), readJson(files.guest_attestation), readJson(files.cost_quote),
]);
validateReleaseInputs({ statePlan, baseline, volumeReport, proofPlan, proofResults, accumulator, p0, guests, costQuote });

const body = {
  version: 2,
  kind: "antseed-sp1-proof-release",
  chainId: 8_453,
  sources: {
    proofCommit: git(proofRepo, ["rev-parse", "HEAD"]),
    contractsCommit: git(contractsRepo, ["rev-parse", "HEAD"]),
    proofCargoLockSha256: await digestFile(resolve(proofRepo, "Cargo.lock")),
    checkpointCargoLockSha256: await digestFile(resolve(proofRepo, "checkpoint/Cargo.lock")),
    contractsLockSha256: await digestFile(resolve(contractsRepo, "packages/contracts/foundry.lock"), true),
  },
  tools: {
    rustc: commandVersion("rustc", ["--version"]),
    cargo: commandVersion("cargo", ["--version"]),
    forge: commandVersion("forge", ["--version"]),
    node: process.version,
  },
  guests: guests.guests,
  artifacts: Object.fromEntries(await Promise.all(Object.entries(files).map(async ([name, path]) => [name, { path, sha256: await digestFile(path) }]))),
  statePlanDigest: sha256(canonicalJson(statePlan)),
  volumeBaselineDigest: baseline.attestation.digest,
  volumeReportDigest: sha256(canonicalJson(volumeReport)),
  costQuoteDigest: costQuote.digest,
  reportRoot: proofPlan.reportRoot,
  historicalMmrRoot: accumulator.accumulator.mmrRoot,
  journalDigests: proofResults.entries.map((entry) => ({ claimId: entry.claimId, journalDigest: entry.journalDigest })),
  counts: { claims: proofPlan.claims.length, proofResults: proofResults.entries.length, epochProofs: accumulator.epochCount, aggregateProofs: 1 },
};
const privateKey = createPrivateKey(await readFile(value("--signing-key"), "utf8"));
const digest = sha256(canonicalJson(body));
const release = {
  body,
  attestation: {
    algorithm: "ed25519",
    digest,
    publicKey: createPublicKey(privateKey).export({ type: "spki", format: "pem" }),
    signature: sign(null, Buffer.from(digest.slice(2), "hex"), privateKey).toString("base64"),
  },
};
await writeFile(value("--out"), `${JSON.stringify(release, null, 2)}\n`, { mode: 0o600 });
console.log(`releaseDigest ${digest}`);

function validateReleaseInputs({ statePlan, baseline, volumeReport, proofPlan, proofResults, accumulator, p0, guests, costQuote }) {
  if (statePlan?.version !== 1 || statePlan?.kind !== "antseed-base-state-plan" || statePlan.chainId !== 8_453 || statePlan.entries.length === 0) throw new Error("state plan is incomplete");
  verifySignedBaseline(baseline);
  if (baseline.body.claimCount !== 26 || baseline.body.claims.length !== 26) throw new Error("signed 26-claim volume baseline is required");
  if (volumeReport?.version !== 2 || volumeReport.kind !== "antseed-proof-volume-report" || volumeReport.ok !== true
      || volumeReport.claimCount !== 26 || volumeReport.claims?.length !== 26 || volumeReport.differences?.length !== 0
      || volumeReport.baselineDigest !== baseline.attestation.digest) throw new Error("clean 26-claim final volume report is required");
  if (proofPlan?.version !== 2 || proofPlan?.claimCount !== 26 || proofPlan.claims?.length !== 26) throw new Error("proof plan must contain exactly 26 claims");
  if (proofResults?.version !== 2 || proofResults?.kind !== "antseed-wash-trading-proof-results" || proofResults.securityMode !== "production"
      || proofResults.entries?.length !== 26 || proofResults.entries.some((entry) => !entry.proofBytes || !entry.programVKey)) throw new Error("26 production SP1 proof results are required");
  if (accumulator?.version !== 3 || accumulator.kind !== "antseed-sp1-history-accumulator-artifacts"
      || accumulator.epochCount !== accumulator.epochs?.length || accumulator.epochs.some((epoch) => epoch.status !== "proven")
      || accumulator.accumulator?.status !== "proven" || accumulator.accumulator?.proofMode !== "groth16"
      || !accumulator.accumulator.mmrRoot) throw new Error("history accumulator proofs are incomplete or not Groth16");
  if (p0?.version !== 2 || p0?.kind !== "antseed-sp1-p0-proof-artifacts" || p0.claims?.length !== 26 || p0.claims.some((claim) => claim?.status !== "proven")) throw new Error("P0 SP1 proof artifacts are incomplete");
  if (guests?.version !== 2 || guests?.kind !== "antseed-sp1-program-build-attestation" || guests.sp1Version !== "6.1.0" || guests.reproducible !== true
      || !guests.guests || Object.keys(guests.guests).sort().join(",") !== "accumulator,closedCycle,historyEpoch,reciprocal") {
    throw new Error("reproducible four-guest build attestation is required");
  }
  if (costQuote?.body?.version !== 3 || costQuote?.body?.kind !== "antseed-sp1-proof-cost-quote"
      || costQuote.body.counts?.epochProofs !== accumulator.epochCount || costQuote.body.counts?.aggregateProofs !== 1
      || costQuote.body.counts?.p0Claims !== 26
      || sha256(canonicalJson(costQuote.body)) !== costQuote.digest) throw new Error("aggregate proving cost quote is required");
  const plannedClaims = claimIdSet(proofPlan.claims);
  for (const [label, entries] of [["baseline", baseline.body.claims], ["proof results", proofResults.entries], ["P0 artifacts", p0.claims], ["volume report", volumeReport.claims]]) {
    const actual = claimIdSet(entries);
    if (actual.size !== plannedClaims.size || [...plannedClaims].some((claimId) => !actual.has(claimId))) throw new Error(`${label} claim set differs from proof plan`);
  }
  for (const entry of proofResults.entries) {
    if (sha256(Buffer.from(entry.journalBytes.slice(2), "hex")) !== entry.journalDigest.toLowerCase()) throw new Error(`${entry.claimId}: journal digest mismatch`);
  }
}

function verifySignedBaseline(baseline) {
  if (baseline?.attestation?.algorithm !== "ed25519" || !baseline.attestation.publicKey || !baseline.attestation.signature) throw new Error("signed volume baseline is required");
  const digest = sha256(canonicalJson(baseline.body));
  if (digest !== baseline.attestation.digest) throw new Error("volume baseline digest mismatch");
  if (!verify(null, Buffer.from(digest.slice(2), "hex"), baseline.attestation.publicKey, Buffer.from(baseline.attestation.signature, "base64"))) throw new Error("volume baseline signature is invalid");
}

function claimIdSet(entries) {
  const ids = new Set();
  for (const entry of entries) {
    const claimId = entry?.claimId?.toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(claimId ?? "") || ids.has(claimId)) throw new Error("invalid or duplicate claim ID in release inputs");
    ids.add(claimId);
  }
  return ids;
}

function assertClean(repo, label) {
  if (git(repo, ["status", "--porcelain"]) !== "") throw new Error(`${label} must be clean before release attestation`);
}

function git(repo, gitArgs) {
  return execFileSync("git", ["-C", repo, ...gitArgs], { encoding: "utf8" }).trim();
}

function commandVersion(command, commandArgs) {
  return execFileSync(command, commandArgs, { encoding: "utf8" }).trim().split("\n")[0];
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function digestFile(path, optional = false) {
  try { return sha256(await readFile(path)); }
  catch (error) { if (optional && error.code === "ENOENT") return null; throw error; }
}

function sha256(valueToHash) {
  return `0x${createHash("sha256").update(valueToHash).digest("hex")}`;
}

function canonicalJson(valueToEncode) {
  if (valueToEncode === null || typeof valueToEncode !== "object") return JSON.stringify(valueToEncode);
  if (Array.isArray(valueToEncode)) return `[${valueToEncode.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(valueToEncode).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(valueToEncode[key])}`).join(",")}}`;
}
