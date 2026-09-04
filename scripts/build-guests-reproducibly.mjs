#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const args = process.argv.slice(2);
const value = (flag) => { const index = args.indexOf(flag); return index < 0 ? null : args[index + 1]; };
const out = value("--out");
const workDir = resolve(value("--work-dir") ?? "../guest-repro-builds");
if (!out) throw new Error("usage: build-guests-reproducibly.mjs --work-dir /outside/repo --out guest-attestation.json");
if (workDir === process.cwd() || workDir.startsWith(`${process.cwd()}/`)) throw new Error("reproducibility work directory must be outside the proof repository");
await mkdir(workDir, { recursive: true });
await mkdir(dirname(resolve(out)), { recursive: true });
const runDir = await mkdtemp(join(workDir, "conserved-loop-"));
const artifactDir = join(dirname(resolve(out)), "guests");
await mkdir(artifactDir, { recursive: true });
const builds = [];
for (const label of ["a", "b"]) {
  const source = join(runDir, `source-${label}`);
  await exec("rsync", ["-a", "--delete", "--exclude", ".git", "--exclude", "out", "--exclude", "target", "--exclude", "program/*/target", `${process.cwd()}/`, `${source}/`]);
  await run(join(source, "scripts/build-guests.sh"), [], source);
  const guests = {};
  for (const guest of ["seller"]) {
    const elf = join(source, `program/${guest}/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/${guest}-guest`);
    const bytes = await readFile(elf);
    guests[guest] = { elfSha256: sha256(bytes), elfBytes: (await stat(elf)).size };
  }
  builds.push({ buildId: label, source, guests });
}
const guests = {};
for (const guest of ["seller"]) {
  if (JSON.stringify(builds[0].guests[guest]) !== JSON.stringify(builds[1].guests[guest])) throw new Error(`${guest} guest build is not reproducible`);
  const sourceElf = join(builds[0].source, `program/${guest}/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/${guest}-guest`);
  const artifactElf = join(artifactDir, `${guest}-guest`);
  await copyFile(sourceElf, artifactElf);
  console.error(`deriving ${guest} vkey from the verified reproducible ELF`);
  const { stdout } = await exec("cargo", ["run", "-q", "-p", "loop-host", "--features", "sp1", "--", "vkey", "--elf", artifactElf], { cwd: process.cwd() });
  const programVKey = stdout.trim().split(/\s+/).at(-1);
  if (!/^0x[0-9a-f]{64}$/i.test(programVKey)) throw new Error(`${guest}: invalid vkey output`);
  guests[guest] = { programVKey, ...builds[0].guests[guest] };
}
const attestation = {
  version: 4,
  kind: "antseed-sp1-program-build-attestation",
  sp1Version: "6.1.0",
  reproducible: true,
  sourceDigest: await sourceDigest(),
  builds: builds.map(({ buildId, source }) => ({ buildId, source })),
  guests,
};
await writeFile(out, `${JSON.stringify(attestation, null, 2)}\n`);
console.log(`wrote ${out}`);

async function sourceDigest() {
  const { stdout } = await exec("git", ["diff", "--binary", "HEAD"], { cwd: process.cwd(), maxBuffer: 100 * 1024 * 1024 });
  const head = (await exec("git", ["rev-parse", "HEAD"], { cwd: process.cwd() })).stdout.trim();
  return sha256(Buffer.from(`${head}\n${stdout}`));
}
function sha256(bytes) { return `0x${createHash("sha256").update(bytes).digest("hex")}`; }
function run(command, commandArgs, cwd) {
  console.error(`${basename(cwd)}: ${command} ${commandArgs.join(" ")}`);
  return new Promise((resolveRun, reject) => {
    const child = execFile(command, commandArgs, { cwd }, (error) => error ? reject(error) : resolveRun());
    child.stdout?.pipe(process.stdout);
    child.stderr?.pipe(process.stderr);
  });
}
