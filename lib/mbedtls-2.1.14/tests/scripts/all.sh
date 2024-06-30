#!/bin/sh

# all.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2014-2017, ARM Limited, All Rights Reserved



################################################################
#### Documentation
################################################################

# Purpose
# -------
#
# To run all tests possible or available on the platform.
#
# Notes for users
# ---------------
#
# Warning: the test is destructive. It includes various build modes and
# configurations, and can and will arbitrarily change the current CMake
# configuration. The following files must be committed into git:
#    * include/mbedtls/config.h
#    * Makefile, library/Makefile, programs/Makefile, tests/Makefile
# After running this script, the CMake cache will be lost and CMake
# will no longer be initialised.
#
# The script assumes the presence of a number of tools:
#   * Basic Unix tools (Windows users note: a Unix-style find must be before
#     the Windows find in the PATH)
#   * Perl
#   * GNU Make
#   * CMake
#   * GCC and Clang (recent enough for using ASan with gcc and MemSan with clang, or valgrind)
#   * arm-gcc and mingw-gcc
#   * ArmCC 5 and ArmCC 6, unless invoked with --no-armcc
#   * OpenSSL and GnuTLS command line tools, recent enough for the
#     interoperability tests. If they don't support SSLv3 then a legacy
#     version of these tools must be present as well (search for LEGACY
#     below).
# See the invocation of check_tools below for details.
#
# This script must be invoked from the toplevel directory of a git
# working copy of Mbed TLS.
#
# Note that the output is not saved. You may want to run
#   script -c tests/scripts/all.sh
# or
#   tests/scripts/all.sh >all.log 2>&1
#
# Notes for maintainers
# ---------------------
#
# The tests are roughly in order from fastest to slowest. This doesn't
# have to be exact, but in general you should add slower tests towards
# the end and fast checks near the beginning.
#
# Sanity checks have the following form:
#   1. msg "short description of what is about to be done"
#   2. run sanity check (failure stops the script)
#
# Build or build-and-test steps have the following form:
#   1. msg "short description of what is about to be done"
#   2. cleanup
#   3. preparation (config.pl, cmake, ...) (failure stops the script)
#   4. make
#   5. Run tests if relevant. All tests must be prefixed with
#      if_build_successful for the sake of --keep-going.



################################################################
#### Initialization and command line parsing
################################################################

# Abort on errors (and uninitialised variables)
set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    err_msg "Must be run from mbed TLS root"
    exit 1
fi

CONFIG_H='include/mbedtls/config.h'
CONFIG_BAK="$CONFIG_H.bak"

MEMORY=0
FORCE=0
KEEP_GOING=0
RUN_ARMCC=1

# Default commands, can be overriden by the environment
: ${OPENSSL:="openssl"}
: ${OPENSSL_LEGACY:="$OPENSSL"}
: ${GNUTLS_CLI:="gnutls-cli"}
: ${GNUTLS_SERV:="gnutls-serv"}
: ${GNUTLS_LEGACY_CLI:="$GNUTLS_CLI"}
: ${GNUTLS_LEGACY_SERV:="$GNUTLS_SERV"}
: ${OUT_OF_SOURCE_DIR:=./mbedtls_out_of_source_build}

usage()
{
    cat <<EOF
Usage: $0 [OPTION]...
  -h|--help             Print this help.

General options:
  -f|--force            Force the tests to overwrite any modified files.
  -k|--keep-going       Run all tests and report errors at the end.
  -m|--memory           Additional optional memory tests.
     --armcc            Run ARM Compiler builds (on by default).
     --no-armcc         Skip ARM Compiler builds.
     --no-force         Refuse to overwrite modified files (default).
     --no-keep-going    Stop at the first error (default).
     --no-memory        No additional memory tests (default).
     --no-yotta         Ignored for compatibility with other Mbed TLS versions.
     --out-of-source-dir=<path>  Directory used for CMake out-of-source build tests.
     --random-seed      Use a random seed value for randomized tests (default).
  -r|--release-test     Run this script in release mode. This fixes the seed value to 1.
  -s|--seed             Integer seed value to use for this test run.

Tool path options:
     --armc5-bin-dir=<ARMC5_bin_dir_path>       ARM Compiler 5 bin directory.
     --armc6-bin-dir=<ARMC6_bin_dir_path>       Ignored for compatibility with other Mbed TLS versions.
     --gnutls-cli=<GnuTLS_cli_path>             GnuTLS client executable to use for most tests.
     --gnutls-serv=<GnuTLS_serv_path>           GnuTLS server executable to use for most tests.
     --gnutls-legacy-cli=<GnuTLS_cli_path>      GnuTLS client executable to use for legacy tests.
     --gnutls-legacy-serv=<GnuTLS_serv_path>    GnuTLS server executable to use for legacy tests.
     --openssl=<OpenSSL_path>                   OpenSSL executable to use for most tests.
     --openssl-legacy=<OpenSSL_path>            OpenSSL executable to use for legacy tests e.g. SSLv3.
EOF
}

# remove built files as well as the cmake cache/config
cleanup()
{
    if [ -n "${MBEDTLS_ROOT_DIR+set}" ]; then
        cd "$MBEDTLS_ROOT_DIR"
    fi

    command make clean

    # Remove CMake artefacts
    find . -name .git -prune -o -name yotta -prune -o \
           -iname CMakeFiles -exec rm -rf {} \+ -o \
           \( -iname cmake_install.cmake -o \
              -iname CTestTestfile.cmake -o \
              -iname CMakeCache.txt \) -exec rm {} \+
    # Recover files overwritten by in-tree CMake builds
    rm -f include/Makefile include/mbedtls/Makefile programs/*/Makefile
    git update-index --no-skip-worktree Makefile library/Makefile programs/Makefile tests/Makefile
    git checkout -- Makefile library/Makefile programs/Makefile tests/Makefile

    if [ -f "$CONFIG_BAK" ]; then
        mv "$CONFIG_BAK" "$CONFIG_H"
    fi
}

# Executed on exit. May be redefined depending on command line options.
final_report () {
    :
}

fatal_signal () {
    cleanup
    final_report $1
    trap - $1
    kill -$1 $$
}

trap 'fatal_signal HUP' HUP
trap 'fatal_signal INT' INT
trap 'fatal_signal TERM' TERM

msg()
{
    echo ""
    echo "******************************************************************"
    echo "* $1 "
    printf "* "; date
    echo "******************************************************************"
    current_section=$1
}

err_msg()
{
    echo "$1" >&2
}

check_tools()
{
    for TOOL in "$@"; do
        if ! `type "$TOOL" >/dev/null 2>&1`; then
            err_msg "$TOOL not found!"
            exit 1
        fi
    done
}

while [ $# -gt 0 ]; do
    case "$1" in
        --armcc) RUN_ARMCC=1;;
        --armc5-bin-dir) shift; ARMC5_BIN_DIR="$1";;
        --armc6-bin-dir) shift;; # Ignore for compatibility with later Mbed TLS versions
        --force|-f) FORCE=1;;
        --gnutls-cli) shift; GNUTLS_CLI="$1";;
        --gnutls-legacy-cli) shift; GNUTLS_LEGACY_CLI="$1";;
        --gnutls-legacy-serv) shift; GNUTLS_LEGACY_SERV="$1";;
        --gnutls-serv) shift; GNUTLS_SERV="$1";;
        --help|-h) usage; exit;;
        --keep-going|-k) KEEP_GOING=1;;
        --memory|-m) MEMORY=1;;
        --no-armcc) RUN_ARMCC=0;;
        --no-force) FORCE=0;;
        --no-keep-going) KEEP_GOING=0;;
        --no-memory) MEMORY=0;;
        --no-yotta) :;; # No Yotta support anyway, so just ignore --no-yotta
        --openssl) shift; OPENSSL="$1";;
        --openssl-legacy) shift; OPENSSL_LEGACY="$1";;
        --out-of-source-dir) shift; OUT_OF_SOURCE_DIR="$1";;
        --random-seed) unset SEED;;
        --release-test|-r) SEED=1;;
        --seed|-s) shift; SEED="$1";;
        *)
            echo >&2 "Unknown option: $1"
            echo >&2 "Run $0 --help for usage."
            exit 120
            ;;
    esac
    shift
done

if [ $FORCE -eq 1 ]; then
    rm -rf yotta/module "$OUT_OF_SOURCE_DIR"
    git checkout-index -f -q $CONFIG_H
    cleanup
else

    if [ -d yotta/module ]; then
        err_msg "Warning - there is an existing yotta module in the directory 'yotta/module'"
        echo "You can either delete your work and retry, or force the test to overwrite the"
        echo "test by rerunning the script as: $0 --force"
        exit 1
    fi

    if [ -d "$OUT_OF_SOURCE_DIR" ]; then
        echo "Warning - there is an existing directory at '$OUT_OF_SOURCE_DIR'" >&2
        echo "You can either delete this directory manually, or force the test by rerunning"
        echo "the script as: $0 --force --out-of-source-dir $OUT_OF_SOURCE_DIR"
        exit 1
    fi

    if ! git diff-files --quiet include/mbedtls/config.h; then
        err_msg "Warning - the configuration file 'include/mbedtls/config.h' has been edited. "
        echo "You can either delete or preserve your work, or force the test by rerunning the"
        echo "script as: $0 --force"
        exit 1
    fi
fi

build_status=0
if [ $KEEP_GOING -eq 1 ]; then
    failure_summary=
    failure_count=0
    start_red=
    end_color=
    if [ -t 1 ]; then
        case "${TERM:-}" in
            *color*|cygwin|linux|rxvt*|screen|[Eex]term*)
                start_red=$(printf '\033[31m')
                end_color=$(printf '\033[0m')
                ;;
        esac
    fi
    record_status () {
        if "$@"; then
            last_status=0
        else
            last_status=$?
            text="$current_section: $* -> $last_status"
            failure_summary="$failure_summary
$text"
            failure_count=$((failure_count + 1))
            echo "${start_red}^^^^$text^^^^${end_color}"
        fi
    }
    make () {
        case "$*" in
            *test|*check)
                if [ $build_status -eq 0 ]; then
                    record_status command make "$@"
                else
                    echo "(skipped because the build failed)"
                fi
                ;;
            *)
                record_status command make "$@"
                build_status=$last_status
                ;;
        esac
    }
    final_report () {
        if [ $failure_count -gt 0 ]; then
            echo
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "${start_red}FAILED: $failure_count${end_color}$failure_summary"
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            exit 1
        elif [ -z "${1-}" ]; then
            echo "SUCCESS :)"
        fi
        if [ -n "${1-}" ]; then
            echo "Killed by SIG$1."
        fi
    }
else
    record_status () {
        "$@"
    }
fi
if_build_succeeded () {
    if [ $build_status -eq 0 ]; then
        record_status "$@"
    fi
}

msg "info: $0 configuration"
echo "MEMORY: $MEMORY"
echo "FORCE: $FORCE"
echo "SEED: ${SEED-"UNSET"}"
echo "OPENSSL: $OPENSSL"
echo "OPENSSL_LEGACY: $OPENSSL_LEGACY"
echo "GNUTLS_CLI: $GNUTLS_CLI"
echo "GNUTLS_SERV: $GNUTLS_SERV"
echo "GNUTLS_LEGACY_CLI: $GNUTLS_LEGACY_CLI"
echo "GNUTLS_LEGACY_SERV: $GNUTLS_LEGACY_SERV"
echo "ARMC5_BIN_DIR: ${ARMC5_BIN_DIR:-UNSET}"

if [ -n "${ARMC5_BIN_DIR-}" ]; then
    ARMC5_CC="$ARMC5_BIN_DIR/armcc"
    ARMC5_AR="$ARMC5_BIN_DIR/armar"
else
    ARMC5_CC=armcc
    ARMC5_AR=armar
fi

# To avoid setting OpenSSL and GnuTLS for each call to compat.sh and ssl-opt.sh
# we just export the variables they require
export OPENSSL_CMD="$OPENSSL"
export GNUTLS_CLI="$GNUTLS_CLI"
export GNUTLS_SERV="$GNUTLS_SERV"

# Avoid passing --seed flag in every call to ssl-opt.sh
if [ -n "${SEED-}" ]; then
  export SEED
fi

# Make sure the tools we need are available.
check_tools "$OPENSSL" "$OPENSSL_LEGACY" "$GNUTLS_CLI" "$GNUTLS_SERV" \
            "$GNUTLS_LEGACY_CLI" "$GNUTLS_LEGACY_SERV" "doxygen" "dot" \
            "arm-none-eabi-gcc"
if [ $RUN_ARMCC -ne 0 ]; then
    check_tools "$ARMC5_CC" "$ARMC5_AR"
fi



################################################################
#### Basic checks
################################################################

#
# Test Suites to be executed
#
# The test ordering tries to optimize for the following criteria:
# 1. Catch possible problems early, by running first tests that run quickly
#    and/or are more likely to fail than others (eg I use Clang most of the
#    time, so start with a GCC build).
# 2. Minimize total running time, by avoiding useless rebuilds
#
# Indicative running times are given for reference.

msg "test: recursion.pl" # < 1s
tests/scripts/recursion.pl library/*.c

msg "test: freshness of generated source files" # < 1s
tests/scripts/check-generated-files.sh

msg "test: doxygen markup outside doxygen blocks" # < 1s
tests/scripts/check-doxy-blocks.pl

msg "test: check-files.py" # < 1s
cleanup
tests/scripts/check-files.py

msg "test/build: declared and exported names" # < 3s
cleanup
tests/scripts/check-names.sh



################################################################
#### Build and test many configurations and targets
################################################################

# Yotta not supported in 2.1 branch
#msg "build: create and build yotta module" # ~ 30s
#cleanup
#record_status tests/scripts/yotta-build.sh

msg "build: cmake, gcc, ASan" # ~ 1 min 50s
cleanup
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
make

msg "test: main suites (inc. selftests) (ASan build)" # ~ 50s
make test
programs/test/selftest

msg "test: ssl-opt.sh (ASan build)" # ~ 1 min
if_build_succeeded tests/ssl-opt.sh

msg "test/build: ref-configs (ASan build)" # ~ 6 min 20s
record_status tests/scripts/test-ref-configs.pl

msg "build: with ASan (rebuild after ref-configs)" # ~ 1 min
make

msg "test: compat.sh (ASan build)" # ~ 6 min
if_build_succeeded tests/compat.sh

msg "build: default config except MFL extension (ASan build)" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
make

msg "test: ssl-opt.sh, MFL-related tests"
tests/ssl-opt.sh -f "Max fragment length"

msg "build: Default + SSLv3 (ASan build)" # ~ 6 min
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl set MBEDTLS_SSL_PROTO_SSL3
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
make

msg "test: SSLv3 - main suites (inc. selftests) (ASan build)" # ~ 50s
make test
programs/test/selftest

msg "build: SSLv3 - compat.sh (ASan build)" # ~ 6 min
if_build_succeeded tests/compat.sh -m 'tls1 tls1_1 tls1_2 dtls1 dtls1_2'
if_build_succeeded env OPENSSL_CMD="$OPENSSL_LEGACY" tests/compat.sh -m 'ssl3'

msg "build: SSLv3 - ssl-opt.sh (ASan build)" # ~ 6 min
if_build_succeeded tests/ssl-opt.sh

msg "build: Default + !MBEDTLS_SSL_RENEGOTIATION (ASan build)" # ~ 6 min
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl unset MBEDTLS_SSL_RENEGOTIATION
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
make

msg "test: !MBEDTLS_SSL_RENEGOTIATION - main suites (inc. selftests) (ASan build)" # ~ 50s
make test

msg "test: !MBEDTLS_SSL_RENEGOTIATION - ssl-opt.sh (ASan build)" # ~ 6 min
if_build_succeeded tests/ssl-opt.sh

msg "build: Default + RSA_NO_CRT (ASan build)" # ~ 6 min
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl set MBEDTLS_RSA_NO_CRT
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
make

msg "test: RSA_NO_CRT - main suites (inc. selftests) (ASan build)" # ~ 50s
make test

msg "test: RSA_NO_CRT - RSA-related part of ssl-opt.sh (ASan build)" # ~ 5s
tests/ssl-opt.sh -f RSA

msg "test: RSA_NO_CRT - RSA-related part of compat.sh (ASan build)" # ~ 3 min
tests/compat.sh -t RSA


msg "build: cmake, full config, clang" # ~ 50s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # too slow for tests
CC=clang cmake -D CMAKE_BUILD_TYPE:String=Check -D ENABLE_TESTING=On .
make

msg "test: main suites (full config)" # ~ 5s
make test

msg "test: ssl-opt.sh default (full config)" # ~ 1s
if_build_succeeded tests/ssl-opt.sh -f Default

msg "test: compat.sh RC4, DES & NULL (full config)" # ~ 2 min
if_build_succeeded env OPENSSL_CMD="$OPENSSL_LEGACY" GNUTLS_CLI="$GNUTLS_LEGACY_CLI" GNUTLS_SERV="$GNUTLS_LEGACY_SERV" tests/compat.sh -e '3DES\|DES-CBC3' -f 'NULL\|DES\|RC4\|ARCFOUR'

msg "build: make, full config + DEPRECATED_WARNING, gcc -O" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl set MBEDTLS_DEPRECATED_WARNING
# Build with -O -Wextra to catch a maximum of issues.
make CC=gcc CFLAGS='-O -Werror -Wall -Wextra' lib programs
make CC=gcc CFLAGS='-O -Werror -Wall -Wextra -Wno-unused-function' tests

msg "build: make, full config + DEPRECATED_REMOVED, clang -O" # ~ 30s
# No cleanup, just tweak the configuration and rebuild
make clean
scripts/config.pl unset MBEDTLS_DEPRECATED_WARNING
scripts/config.pl set MBEDTLS_DEPRECATED_REMOVED
# Build with -O -Wextra to catch a maximum of issues.
make CC=clang CFLAGS='-O -Werror -Wall -Wextra' lib programs
make CC=clang CFLAGS='-O -Werror -Wall -Wextra -Wno-unused-function' tests

msg "test/build: curves.pl (gcc)" # ~ 4 min
cleanup
record_status tests/scripts/curves.pl

msg "test/build: depends-hashes.pl (gcc)" # ~ 2 min
cleanup
record_status tests/scripts/depends-hashes.pl

msg "test/build: depends-pkalgs.pl (gcc)" # ~ 2 min
cleanup
record_status tests/scripts/depends-pkalgs.pl

msg "test/build: key-exchanges (gcc)" # ~ 1 min
cleanup
record_status tests/scripts/key-exchanges.pl

msg "build: Unix make, -Os (gcc)" # ~ 30s
cleanup
make CC=gcc CFLAGS='-Werror -Os'

# this is meant to cath missing #define mbedtls_printf etc
# disable fsio to catch some more missing #include <stdio.h>
msg "build: full config except platform/fsio, make, gcc" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_PLATFORM_C
scripts/config.pl unset MBEDTLS_PLATFORM_MEMORY
scripts/config.pl unset MBEDTLS_PLATFORM_PRINTF_ALT
scripts/config.pl unset MBEDTLS_PLATFORM_FPRINTF_ALT
scripts/config.pl unset MBEDTLS_PLATFORM_SNPRINTF_ALT
scripts/config.pl unset MBEDTLS_PLATFORM_EXIT_ALT
scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
scripts/config.pl unset MBEDTLS_FS_IO
make CC=gcc CFLAGS='-Werror -O0'

# catch compile bugs in _uninit functions
msg "build: full config with NO_STD_FUNCTION, make, gcc" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
make CC=gcc CFLAGS='-Werror -O0'

msg "build: full config except ssl_srv.c, make, gcc" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_SSL_SRV_C
make CC=gcc CFLAGS='-Werror -O0'

msg "build: full config except ssl_cli.c, make, gcc" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_SSL_CLI_C
make CC=gcc CFLAGS='-Werror -O0'

msg "build: full config except net.c, make, gcc -std=c99 -pedantic" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_NET_C # getaddrinfo() undeclared, etc.
scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY # uses syscall() on GNU/Linux
make CC=gcc CFLAGS='-Werror -O0 -std=c99 -pedantic' lib

if uname -a | grep -F Linux >/dev/null; then
    msg "build/test: make shared" # ~ 40s
    cleanup
    make SHARED=1 all check
fi

if uname -a | grep -F x86_64 >/dev/null; then
    # Build once with -O0, to compile out the i386 specific inline assembly
    msg "build: i386, make, gcc -O0 (ASan build)" # ~ 30s
    cleanup
    cp "$CONFIG_H" "$CONFIG_BAK"
    scripts/config.pl full
    make CC=gcc CFLAGS='-O0 -Werror -Wall -Wextra -m32 -fsanitize=address'

    msg "test: i386, make, gcc -O0 (ASan build)"
    make test

    # Build again with -O1, to compile in the i386 specific inline assembly
    msg "build: i386, make, gcc -O1 (ASan build)" # ~ 30s
    cleanup
    cp "$CONFIG_H" "$CONFIG_BAK"
    scripts/config.pl full
    make CC=gcc CFLAGS='-O1 -Werror -Wall -Wextra -m32 -fsanitize=address'

    msg "test: i386, make, gcc -O1 (ASan build)"
    make test

    msg "build: 64-bit ILP32, make, gcc" # ~ 30s
    cleanup
    cp "$CONFIG_H" "$CONFIG_BAK"
    scripts/config.pl full
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -mx32'

    msg "test: 64-bit ILP32, make, gcc"
    make test
fi # x86_64

msg "build: arm-none-eabi-gcc, make" # ~ 10s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_NET_C
scripts/config.pl unset MBEDTLS_TIMING_C
scripts/config.pl unset MBEDTLS_FS_IO
scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY
# following things are not in the default config
scripts/config.pl unset MBEDTLS_HAVEGE_C # depends on timing.c
scripts/config.pl unset MBEDTLS_THREADING_PTHREAD
scripts/config.pl unset MBEDTLS_THREADING_C
scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # execinfo.h
scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C # calls exit
make CC=arm-none-eabi-gcc AR=arm-none-eabi-ar LD=arm-none-eabi-ld CFLAGS=-Werror lib

if [ $RUN_ARMCC -ne 0 ]; then
    msg "build: armcc, make"
    cleanup
    cp "$CONFIG_H" "$CONFIG_BAK"
    scripts/config.pl full
    scripts/config.pl unset MBEDTLS_NET_C
    scripts/config.pl unset MBEDTLS_TIMING_C
    scripts/config.pl unset MBEDTLS_FS_IO
    scripts/config.pl unset MBEDTLS_HAVE_TIME
    scripts/config.pl unset MBEDTLS_HAVE_TIME_DATE
    scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY
    # following things are not in the default config
    scripts/config.pl unset MBEDTLS_DEPRECATED_WARNING
    scripts/config.pl unset MBEDTLS_HAVEGE_C # depends on timing.c
    scripts/config.pl unset MBEDTLS_THREADING_PTHREAD
    scripts/config.pl unset MBEDTLS_THREADING_C
    scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # execinfo.h
    scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C # calls exit
    make CC="$ARMC5_CC" AR="$ARMC5_AR" WARNING_CFLAGS= lib
fi

msg "build: allow SHA1 in certificates by default"
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl set MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES
make CFLAGS='-Werror -Wall -Wextra'
msg "test: allow SHA1 in certificates by default"
make test
if_build_succeeded tests/ssl-opt.sh -f SHA-1

if which i686-w64-mingw32-gcc >/dev/null; then
    msg "build: cross-mingw64, make" # ~ 30s
    cleanup
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS=-Werror WINDOWS_BUILD=1
    make WINDOWS_BUILD=1 clean
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS=-Werror WINDOWS_BUILD=1 SHARED=1
    make WINDOWS_BUILD=1 clean
fi

# MemSan currently only available on Linux 64 bits
if uname -a | grep 'Linux.*x86_64' >/dev/null; then

    msg "build: MSan (clang)" # ~ 1 min 20s
    cleanup
    cp "$CONFIG_H" "$CONFIG_BAK"
    scripts/config.pl unset MBEDTLS_AESNI_C # memsan doesn't grok asm
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
    make

    msg "test: main suites (MSan)" # ~ 10s
    make test

    msg "test: ssl-opt.sh (MSan)" # ~ 1 min
    if_build_succeeded tests/ssl-opt.sh

    # Optional part(s)

    if [ "$MEMORY" -gt 0 ]; then
        msg "test: compat.sh (MSan)" # ~ 6 min 20s
        if_build_succeeded tests/compat.sh
    fi

else # no MemSan

    msg "build: Release (clang)"
    cleanup
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: main suites valgrind (Release)"
    make memcheck

    # Optional part(s)
    # Currently broken, programs don't seem to receive signals
    # under valgrind on OS X

    if [ "$MEMORY" -gt 0 ]; then
        msg "test: ssl-opt.sh --memcheck (Release)"
        if_build_succeeded tests/ssl-opt.sh --memcheck
    fi

    if [ "$MEMORY" -gt 1 ]; then
        msg "test: compat.sh --memcheck (Release)"
        if_build_succeeded tests/compat.sh --memcheck
    fi

fi # MemSan

msg "build: cmake 'out-of-source' build"
cleanup
MBEDTLS_ROOT_DIR="$PWD"
mkdir "$OUT_OF_SOURCE_DIR"
cd "$OUT_OF_SOURCE_DIR"
cmake "$MBEDTLS_ROOT_DIR"
make

msg "test: cmake 'out-of-source' build"
make test
# Test an SSL option that requires an auxiliary script in test/scripts/.
# Also ensure that there are no error messages such as
# "No such file or directory", which would indicate that some required
# file is missing (ssl-opt.sh tolerates the absence of some files so
# may exit with status 0 but emit errors).
if_build_succeeded ./tests/ssl-opt.sh -f 'Fallback SCSV: beginning of list' 2>ssl-opt.err
if [ -s ssl-opt.err ]; then
  cat ssl-opt.err >&2
  record_status [ ! -s ssl-opt.err ]
  rm ssl-opt.err
fi
cd "$MBEDTLS_ROOT_DIR"
rm -rf "$OUT_OF_SOURCE_DIR"
unset MBEDTLS_ROOT_DIR



################################################################
#### Termination
################################################################

msg "Done, cleaning up"
cleanup

final_report