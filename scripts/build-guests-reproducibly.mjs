#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
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
  const proofMetadataPath = join(target, "proof-programs.json");
  const checkpointMetadataPath = join(target, "checkpoint-programs.json");
  await run(join(proofTarget, "debug", "wash-trading-prove"), ["--program-metadata", proofMetadataPath], process.cwd(), {});
  await run(join(checkpointTarget, "debug", "checkpoint-host"), ["program-metadata", "--out", checkpointMetadataPath], resolve("checkpoint"), {});
  const proofMetadata = JSON.parse(await readFile(proofMetadataPath, "utf8"));
  const checkpointMetadata = JSON.parse(await readFile(checkpointMetadataPath, "utf8"));
  validateMetadata(proofMetadata, ["closedCycle", "reciprocal"]);
  validateMetadata(checkpointMetadata, ["accumulator", "historyEpoch"]);
  const build = {
    version: 2,
    kind: "antseed-sp1-program-build",
    buildId: `build-${label}`,
    guests: {
      closedCycle: proofMetadata.programs.closedCycle,
      reciprocal: proofMetadata.programs.reciprocal,
      accumulator: checkpointMetadata.programs.accumulator,
      historyEpoch: checkpointMetadata.programs.historyEpoch,
    },
  };
  builds.push(build);
  await writeFile(join(runDir, `build-${label}.json`), `${JSON.stringify(build, null, 2)}\n`);
}

for (const name of Object.keys(builds[0].guests)) {
  const left = builds[0].guests[name];
  const right = builds[1].guests[name];
  if (left.programVKey !== right.programVKey || left.recursionVKey !== right.recursionVKey || left.elfSha256 !== right.elfSha256 || left.elfBytes !== right.elfBytes) {
    throw new Error(`${name} SP1 program is not reproducible`);
  }
}
await writeFile(out, `${JSON.stringify({
  version: 2,
  kind: "antseed-sp1-program-build-attestation",
  sp1Version: "6.1.0",
  reproducible: true,
  builds: builds.map((build) => ({ buildId: build.buildId, targetDir: join(runDir, build.buildId) })),
  guests: builds[0].guests,
}, null, 2)}\n`);

function validateMetadata(metadata, expectedPrograms) {
  if (metadata?.version !== 1 || metadata.kind !== "antseed-sp1-program-metadata" || metadata.sp1Version !== "6.1.0") throw new Error("unsupported SP1 program metadata");
  for (const name of expectedPrograms) {
    const program = metadata.programs?.[name];
    if (!/^0x[0-9a-f]{64}$/i.test(program?.programVKey ?? "") || !/^0x[0-9a-f]{64}$/i.test(program?.elfSha256 ?? "") || !Number.isInteger(program?.elfBytes) || program.elfBytes <= 0) {
      throw new Error(`${name} SP1 program metadata is invalid`);
    }
    if (name === "historyEpoch" && !/^0x[0-9a-f]{64}$/i.test(program.recursionVKey ?? "")) throw new Error("historyEpoch recursion vkey is invalid");
  }
}

function run(command, commandArgs, cwd, extraEnv) {
  console.log(`${basename(cwd)}: ${command} ${commandArgs.join(" ")}`);
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, { cwd, stdio: "inherit", env: { ...process.env, ...extraEnv } });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? resolveRun() : reject(new Error(`${command} exited with ${code}`)));
  });
}
