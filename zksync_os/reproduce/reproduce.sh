#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZKSYNC_OS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$ZKSYNC_OS_DIR")"

# SYSCOIN: We review both lockfiles. Resolving the host graph again here would
# discard its release pins before the reproducible guest build starts.
for lockfile in "$REPO_ROOT/Cargo.lock" "$ZKSYNC_OS_DIR/Cargo.lock"; do
    if [[ ! -s "$lockfile" ]]; then
        echo "Missing pinned Cargo lockfile $lockfile" >&2
        exit 1
    fi
done

cd "$ZKSYNC_OS_DIR"

TYPES=(
    for-tests
    evm-replay
    singleblock-batch
    singleblock-batch-logging-enabled
    multiblock-batch
    multiblock-batch-logging-enabled
)

for TYPE in "${TYPES[@]}"; do
    ./dump_bin.sh --type "$TYPE" --reproducible
done

# Copy dist/<app>/app.bin -> zksync_os/<app>.bin for backwards compatibility
# with downstream consumers (release workflow, zksync-era, etc.).
for TYPE in "${TYPES[@]}"; do
    APP="${TYPE//-/_}"
    cp -f "dist/${APP}/app.bin" "${APP}.bin"
    md5sum "${APP}.bin"
done
