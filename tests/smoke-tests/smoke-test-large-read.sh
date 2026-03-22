#!/bin/bash
# Smoke test: large file read through FUSE mount (pcl-26j)
#
# Regression test for bad-free heap corruption in psync_pagecache_free_request.
# A large read forces multiple psync_request_range_t allocations — one per
# non-contiguous page range — which are then freed via free_request_range().
# The old code called bare free() on pmem_malloc-allocated nodes; this build
# uses AddressSanitizer to catch any such mismatched free.
#
# Usage:
#   PCLOUD_USER=you@example.com bash tests/smoke-tests/smoke-test-large-read.sh
#
# Requirements:
#   - PCLOUD_USER env var set (credentials prompted at daemon start)
#   - A file >= 50 MB present in the pCloud root (REMOTE_FILE below)
#   - FUSE available on the host

set -euo pipefail

MOUNT="${HOME}/pCloudDrive"
ASAN_LOG="/tmp/pcloudcc_asan_large_read_$$.log"
REMOTE_FILE="${SMOKE_REMOTE_FILE:-}"   # override via env if needed
MIN_SIZE_MB=50

# ---- helpers ---------------------------------------------------------------

die() { echo "ERROR: $*" >&2; exit 1; }

cleanup() {
  echo "--- stopping daemon ---"
  echo "finalize" | ./pcloudcc -k 2>/dev/null || true
  sleep 1
  # Kill any stray daemon
  pkill -f "pcloudcc -d" 2>/dev/null || true
  echo "--- ASAN log ($ASAN_LOG) ---"
  cat "$ASAN_LOG" 2>/dev/null || echo "(empty)"
}
trap cleanup EXIT

# ---- sanity checks ---------------------------------------------------------

[[ -n "${PCLOUD_USER:-}" ]] || die "PCLOUD_USER not set"
[[ -x ./pcloudcc ]]         || die "pcloudcc binary not found — run make first"

# Verify the binary was built with ASAN
if ! readelf -d ./pcloudcc 2>/dev/null | grep -q "libasan\|asan"; then
  echo "WARNING: pcloudcc does not appear to be an ASAN build."
  echo "         For a meaningful test, rebuild with:"
  echo "           make clean && CFLAGS='-fsanitize=address -g -O1' \\"
  echo "                         CXXFLAGS='-fsanitize=address -g -O1' \\"
  echo "                         LDFLAGS='-fsanitize=address' make -j\$(nproc)"
  echo "         Continuing anyway — crash-level corruption may still surface."
fi

# ---- build env -------------------------------------------------------------

export ASAN_OPTIONS="log_path=${ASAN_LOG}:abort_on_error=0:detect_leaks=0"

# ---- start daemon ----------------------------------------------------------

echo "--- starting pcloudcc daemon ---"
./pcloudcc -u "$PCLOUD_USER" -d
sleep 3   # wait for mount and initial sync

[[ -d "$MOUNT" ]] || die "mount point $MOUNT does not exist after daemon start"

# ---- find a large remote file ----------------------------------------------

if [[ -z "$REMOTE_FILE" ]]; then
  echo "--- searching for a file >= ${MIN_SIZE_MB} MB in ${MOUNT} ---"
  REMOTE_FILE=$(find "$MOUNT" -maxdepth 3 -type f \
                  -size "+${MIN_SIZE_MB}M" -print -quit 2>/dev/null || true)
fi

if [[ -z "$REMOTE_FILE" ]]; then
  echo "SKIP: no file >= ${MIN_SIZE_MB} MB found in ${MOUNT}."
  echo "      Upload a large file first, or set SMOKE_REMOTE_FILE=/path/to/file."
  exit 0
fi

echo "--- reading: $REMOTE_FILE ---"
SIZE=$(stat -c%s "$REMOTE_FILE" 2>/dev/null || echo 0)
echo "    size: $((SIZE / 1024 / 1024)) MB"

# ---- read the file, exercising the page-cache request path -----------------

echo "--- streaming file to /dev/null ---"
dd if="$REMOTE_FILE" of=/dev/null bs=1M 2>&1 | tail -1
echo "--- read complete ---"

# Give ASAN a moment to flush any deferred reports
sleep 1

# ---- evaluate ASAN output --------------------------------------------------

ASAN_ERRORS=$(grep -c "ERROR: AddressSanitizer" "$ASAN_LOG" 2>/dev/null || true)
BAD_FREE_ERRORS=$(grep -c "attempting free on address" "$ASAN_LOG" 2>/dev/null || true)

echo ""
if [[ "$ASAN_ERRORS" -eq 0 ]]; then
  echo "PASS: no AddressSanitizer errors detected during large file read"
  exit 0
else
  echo "FAIL: $ASAN_ERRORS ASAN error(s) detected ($BAD_FREE_ERRORS bad-free)"
  echo "      See $ASAN_LOG for details"
  exit 1
fi
