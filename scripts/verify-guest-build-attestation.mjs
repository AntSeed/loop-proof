#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const path = process.argv[2];
if (!path) throw new Error("usage: verify-guest-build-attestation.mjs guest-attestation.json");
const attestation = JSON.parse(await readFile(path, "utf8"));
if (attestation?.version !== 3 || attestation.kind !== "antseed-sp1-program-build-attestation"
    || attestation.sp1Version !== "6.1.0" || attestation.reproducible !== true
    || !/^0x[0-9a-f]{64}$/i.test(attestation.sourceDigest ?? "")) throw new Error("unsupported guest build attestation");
for (const guest of ["closed-loop", "reciprocal"]) {
  const value = attestation.guests?.[guest];
  if (!/^0x[0-9a-f]{64}$/i.test(value?.programVKey ?? "") || !/^0x[0-9a-f]{64}$/i.test(value?.elfSha256 ?? "")
      || !Number.isSafeInteger(value?.elfBytes) || value.elfBytes <= 0) throw new Error(`${guest}: invalid reproducible build metadata`);
}
console.log("guest build attestation valid");
