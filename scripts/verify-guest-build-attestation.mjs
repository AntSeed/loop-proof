#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const first = JSON.parse(await readFile(value("--first"), "utf8"));
const second = JSON.parse(await readFile(value("--second"), "utf8"));
const out = value("--out");
if (!out) throw new Error("usage: verify-guest-build-attestation.mjs --first build-a.json --second build-b.json --out attestation.json");
for (const build of [first, second]) {
  if (build?.version !== 1 || build?.kind !== "antseed-guest-build" || !build.guests) throw new Error("unsupported guest build manifest");
}
const names = ["closedCycle", "reciprocal", "accumulator", "historyEpoch"];
for (const name of names) {
  const left = first.guests[name];
  const right = second.guests[name];
  if (!left || !right || left.imageId !== right.imageId || left.elfSha256 !== right.elfSha256) throw new Error(`${name} guest build is not reproducible`);
}
const attestation = { version: 1, kind: "antseed-guest-build-attestation", reproducible: true, builds: [first.buildId, second.buildId], guests: first.guests };
await writeFile(out, `${JSON.stringify(attestation, null, 2)}\n`);
