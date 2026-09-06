import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../predicate/src/lib.rs", import.meta.url), "utf8");

function constant(name) {
  const match = source.match(new RegExp(`^pub const ${name}: (?:u64|usize) = ([\\d_]+);$`, "m"));
  if (!match) throw new Error(`missing literal predicate constant: ${name}`);
  return BigInt(match[1].replaceAll("_", ""));
}

export const ALPHA_FUND_BPS = constant("ALPHA_FUND_BPS");
export const ALPHA_RETURN_BPS = constant("ALPHA_RETURN_BPS");
export const EPSILON_LEDGER_BPS = constant("EPSILON_LEDGER_BPS");
export const RHO_HOP_BPS = constant("RHO_HOP_BPS");
export const T_PATH_SECONDS = Number(constant("T_PATH_SECONDS"));
export const MAX_RETURN_PATHS = Number(constant("MAX_RETURN_PATHS"));
export const PREDICATE_POLICY = Object.freeze({
  alphaFundBps: Number(ALPHA_FUND_BPS),
  alphaReturnBps: Number(ALPHA_RETURN_BPS),
  epsilonLedgerBps: Number(EPSILON_LEDGER_BPS),
  rhoHopBps: Number(RHO_HOP_BPS),
  pathSeconds: T_PATH_SECONDS,
  maxReturnPaths: MAX_RETURN_PATHS,
});
export const PREDICATE_POLICY_HASH = createHash("sha256").update(JSON.stringify(PREDICATE_POLICY)).digest("hex");

export function isCurrentPolicyCheckpoint(checkpoint) {
  return checkpoint?.version === 3 && checkpoint.predicatePolicyHash === PREDICATE_POLICY_HASH;
}
