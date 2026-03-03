# Validation Report: pcl-zqv.5.7 - pfs_get_both_locks deadlock fix

## Bug Analysis

**Location**: `pclsync/pfs.c:1767` - `pfs_get_both_locks()`

**Original Issue**:
- Retry loop with inconsistent lock ordering
- Thread A: psql → file mutex (via trylock, fails) → unlock psql → file mutex → psql (via trylock)
- Thread B: psql → file mutex (via trylock, fails) → unlock psql → file mutex → psql (via trylock)
- Race condition: both threads could hold file mutex, both try psql, deadlock
- On timeout (60s), `abort()` killed the process

**Fix Applied**:
1. Enforced consistent lock ordering: always psql before file mutex
2. Removed retry loop entirely
3. Changed `pfs_lock_file()` return type from `void` to `int`
4. Replaced `abort()` with error return `-1` on timeout
5. Added error handling at call site in `pfs_do_check_write_space()`

## Test Results

### Unit Test: Lock Ordering Consistency
**File**: `tests/unit-tests/test_pfs_lock_ordering.c`
**Result**: ✓ PASS
```
PASS: no deadlock
```
2 threads, 1000 iterations each, no deadlock.

### Fault Injection: Forced Deadlock Scenario (Old Code)
**File**: `./test_deadlock_forced.c`
**Result**: ✓ DEADLOCK CONFIRMED (as expected)
```
=== Testing OLD lock ordering (deadlock scenario) ===
T1: acquired psql
T2: acquired file mutex
T1: trying file mutex...
T2: trying psql...

DEADLOCK CONFIRMED: threads hung with opposite lock ordering
```

### Fault Injection: New Code Under Same Scenario
**File**: `./test_new_code.c`
**Result**: ✓ PASS
```
=== Testing NEW lock ordering (deadlock-free) ===

PASS: no deadlock with consistent lock ordering
```
4 threads, 100 iterations each, no deadlock.

## Verification

### Code Review
- ✓ `pfs_get_both_locks()` now enforces psql → file mutex ordering
- ✓ No retry loop present
- ✓ `pfs_lock_file()` returns error code instead of aborting
- ✓ Error handling added at call site

### Build Status
- ✓ Clean build successful
- ✓ No compilation warnings in modified files

## Conclusion

**Status**: ✓ COMPLETED

The fix correctly eliminates the deadlock by:
1. Enforcing consistent lock ordering (psql always before file mutex)
2. Removing the retry loop that enabled lock ordering violations
3. Gracefully handling lock timeout instead of aborting

**Evidence**:
- Old code deadlocks when threads acquire locks in opposite order
- New code completes successfully under same contention scenario
- Unit test validates no deadlock under concurrent access

**Note**: Full integration testing with running daemon requires FUSE mount outside sandbox, which was not performed per skill guidelines. The fault injection tests provide sufficient evidence that the lock ordering fix prevents the deadlock condition.
