#!/bin/bash
# End-to-end test: builds apt-attest's package and runs test/e2e/inside.sh in a
# disposable Ubuntu container (docker, or podman with ENGINE=podman).
# Usage: test/e2e/run.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
engine=${ENGINE:-docker}
image=${IMAGE:-ubuntu:24.04}
pv=pidvault_0.6.0-1_amd64.deb
pv_sha256=b9a2a2189cb75b23262dca925dff67fe0d61ae8b2f220c2d039a10d992c8ae80

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} scripts/build-deb.sh 0.0.0~e2e amd64 >/dev/null
cp dist/apt-attest_0.0.0~e2e-1_amd64.deb "$work/"
curl -fsSL -o "$work/$pv" "https://github.com/torstei/pidvault/releases/download/v0.6.0/$pv"
echo "$pv_sha256  $work/$pv" | sha256sum --check --quiet
cp "internal/attest/testdata/$pv.sigstore.json" test/e2e/inside.sh examples/pidvault.toml "$work/"

"$engine" run --rm -v "$work:/e2e:ro" "$image" \
    bash /e2e/inside.sh /e2e/apt-attest_0.0.0~e2e-1_amd64.deb "/e2e/$pv" "/e2e/$pv.sigstore.json"
