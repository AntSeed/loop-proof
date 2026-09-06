#!/usr/bin/env bash
# Reproducible SP1 guest builds (AIP-4 REQUIRES reproducibility so anyone can
# independently re-derive the pinned vkeys from source).
#
# Requires the SP1 toolchain (`curl -L https://sp1up.succinct.xyz | bash &&
# sp1up`) and Docker for the bit-reproducible build environment.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${SP1_DOCKER_TAG:-v6.1.0}"
for guest in seller; do
  echo "── building $guest guest (dockerized, reproducible; tag $TAG)"
  (cd "program/$guest" && cargo prove build --docker --tag "$TAG" --workspace-directory ../..)
done

echo
echo "── elf digests"
for guest in seller; do
  elf="program/$guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/$guest-guest"
  shasum -a 256 "$elf"
done
