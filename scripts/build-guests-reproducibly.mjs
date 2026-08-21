#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const workDir = resolve(value("--work-dir") ?? "../guest-repro-builds");
const out = value("--out");
if (!out) throw new Error("usage: build-guests-reproducibly.mjs --work-dir /outside/repo --out guest-attestation.json");
if (workDir === process.cwd() || workDir.startsWith(`${process.cwd()}/`)) throw new Error("guest reproducibility work directory must be outside the proof repository");
await mkdir(workDir, { recursive: true });
const runDir = await mkdtemp(join(workDir, "attestation-"));
await mkdir(dirname(resolve(out)), { recursive: true });

const builds = [];
for (const label of ["a", "b"]) {
  const target = join(runDir, `build-${label}`);
  const proofTarget = join(target, "proof");
  const checkpointTarget = join(target, "checkpoint");
  await run("cargo", ["build", "-p", "loop-host", "--bins"], process.cwd(), { CARGO_TARGET_DIR: proofTarget });
  await run("cargo", ["build", "-p", "checkpoint-host", "--bins"], resolve("checkpoint"), { CARGO_TARGET_DIR: checkpointTarget });
  const build = {
    version: 1,
    kind: "antseed-guest-build",
    buildId: `build-${label}`,
    guests: {
      closedCycle: await collectGuest(proofTarget, "closed-cycle-methods", "CLOSED_CYCLE_GUEST"),
      reciprocal: await collectGuest(proofTarget, "reciprocal-methods", "RECIPROCAL_GUEST"),
      checkpoint: await collectGuest(checkpointTarget, "checkpoint-methods", "CHECKPOINT_GUEST"),
      historicalChunk: await collectGuest(checkpointTarget, "history-methods", "HISTORY_GUEST"),
    },
  };
  builds.push(build);
  await writeFile(join(runDir, `build-${label}.json`), `${JSON.stringify(build, null, 2)}\n`);
}

for (const name of Object.keys(builds[0].guests)) {
  const left = builds[0].guests[name];
  const right = builds[1].guests[name];
  if (left.imageId !== right.imageId || left.elfSha256 !== right.elfSha256) throw new Error(`${name} guest is not reproducible`);
}
await writeFile(out, `${JSON.stringify({
  version: 1,
  kind: "antseed-guest-build-attestation",
  reproducible: true,
  builds: builds.map((build) => ({ buildId: build.buildId, targetDir: join(runDir, build.buildId) })),
  guests: builds[0].guests,
}, null, 2)}\n`);

async function collectGuest(targetDir, cratePrefix, constantPrefix) {
  const buildDir = join(targetDir, "debug", "build");
  const candidates = (await readdir(buildDir, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && entry.name.startsWith(`${cratePrefix}-`))
    .map((entry) => join(buildDir, entry.name, "out", "methods.rs"));
  for (const candidate of candidates) {
    let source;
    try { source = await readFile(candidate, "utf8"); }
    catch (error) { if (error.code === "ENOENT") continue; throw error; }
    const idMatch = source.match(new RegExp(`${constantPrefix}_ID: \\[u32; 8\\] = \\[([^\\]]+)\\]`));
    const pathMatch = source.match(new RegExp(`${constantPrefix}_PATH: &str = "([^"]+)"`));
    if (!idMatch || !pathMatch) continue;
    const words = idMatch[1].split(",").map((word) => Number(word.trim()));
    const bytes = Buffer.alloc(32);
    words.forEach((word, index) => bytes.writeUInt32LE(word >>> 0, index * 4));
    const elf = await readFile(pathMatch[1]);
    return { imageId: `0x${bytes.toString("hex")}`, elfSha256: `0x${createHash("sha256").update(elf).digest("hex")}`, elfBytes: elf.length };
  }
  throw new Error(`generated methods for ${cratePrefix} were not found`);
}

function run(command, commandArgs, cwd, extraEnv) {
  console.log(`${basename(cwd)}: ${command} ${commandArgs.join(" ")}`);
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, { cwd, stdio: "inherit", env: { ...process.env, ...extraEnv } });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${code}`)));
  });
}
