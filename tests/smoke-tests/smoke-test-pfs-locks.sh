#!/bin/bash
# Concurrent write test for pfs_get_both_locks

MOUNT="$HOME/pCloudDrive"
TESTFILE="$MOUNT/test_concurrent_$$"

# Create test file
touch "$TESTFILE" || exit 1

# Function to write concurrently
write_worker() {
  local id=$1
  for i in {1..50}; do
    echo "worker $id line $i $(date +%s%N)" >> "$TESTFILE"
  done
}

# Launch 4 concurrent writers
for i in {1..4}; do
  write_worker $i &
done

# Wait for all to complete
wait

# Verify
lines=$(wc -l < "$TESTFILE")
echo "Total lines written: $lines (expected 200)"

# Cleanup
rm "$TESTFILE"

if [ "$lines" -eq 200 ]; then
  echo "PASS: concurrent writes completed without deadlock"
  exit 0
else
  echo "FAIL: line count mismatch"
  exit 1
fi
