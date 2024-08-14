README for mbed TLS
===================

Configuration
-------------

mbed TLS should build out of the box on most systems. Some platform specific options are available in the fully-documented configuration file `include/mbedtls/config.h`, which is also the place where features can be selected. This file can be edited manually, or in a more programmatic way using the Perl script `scripts/config.pl` (use `--help` for usage instructions).

Compiler options can be set using standard variables such as `CC` and `CFLAGS` when using the Make and CMake build system (see below).

Compiling
---------

There are currently four active build systems within the mbed TLS releases:

-   yotta
-   Make
-   CMake
-   Microsoft Visual Studio (Visual Studio 6 and Visual Studio 2010)

The main systems used for development are CMake and yotta. Those systems are always complete and up-to-date. The others should reflect all changes present in the CMake and yotta build system, but some features are not ported there by default.

Please note that the yotta option is slightly different from the other build systems:

-   a more minimalistic configuration file is used by default
-   depending on the yotta target, features of mbed OS will be used in examples and tests

The Make and CMake build systems create three libraries: libmbedcrypto, libmbedx509, and libmbedtls. Note that libmbedtls depends on libmbedx509 and libmbedcrypto, and libmbedx509 depends on libmbedcrypto. As a result, some linkers will expect flags to be in a specific order, for example the GNU linker wants `-lmbedtls -lmbedx509 -lmbedcrypto`. Also, when loading shared libraries using dlopen(), you'll need to load libmbedcrypto first, then libmbedx509, before you can load libmbedtls.

### Yotta

[yotta](http://yottabuild.org) is a package manager and build system developed by mbed; it is the build system of mbed OS. To install it on your platform, please follow the yotta [installation instructions](http://docs.yottabuild.org/#installing).

Once yotta is installed, you can use it to download the latest version of mbed TLS form the yotta registry with:

    yotta install mbedtls

and build it with:

    yotta build

If, on the other hand, you already have a copy of mbed TLS from a source other than the yotta registry, for example from cloning our github repository, or from downloading a tarball of the standalone edition, then you'll need first need to generate the yotta module by running:

    yotta/create-module.sh

from the mbed TLS root directory. This will create the yotta module in the `yotta/module` directory. You can then change to that directory and build as usual:

    cd yotta/module
    yotta build

In any case, you'll probably want to set the yotta target before building unless it's already set globally; for more information on using yotta, please consult the [yotta documentation](http://docs.yottabuild.org/).

The yotta edition of mbed TLS includes a few example programs, some of which demonstrate integration with mbed OS; for more details, please consult the [Readme at the root of the yotta module](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/README.md).

### Make

We intentionally only use the absolute minimum of `Make` functionality, as a lot of `Make` features are not supported on all different implementations of Make on different platforms. As such, the Makefiles sometimes require some handwork or export statements in order to work for your platform.

In order to build the source using Make, just enter at the command line:

    make

In order to run the tests, enter:

    make check

The tests need Perl to be built and run. If you don't have Perl installed, you can skip building the tests with:

    make no_test

You'll still be able to run a much smaller set of tests with:

    programs/test/selftest

In order to build for a Windows platform, you should use `WINDOWS_BUILD=1` if the target is Windows but the build environment is Unix-like (for instance when cross-compiling, or compiling from an MSYS shell), and `WINDOWS=1` if the build environment is a Windows shell (for instance using mingw32-make) (in that case some targets will not be available).

Setting the variable `SHARED` in your environment will build shared libraries in addition to the static libraries. Setting `DEBUG` gives you a debug build. You can override `CFLAGS` and `LDFLAGS` by setting them in your environment or on the make command line; compiler warning options may be overridden separately using `WARNING_CFLAGS`. Some directory-specific options (for example, `-I` directives) are still preserved.

Please note that setting `CFLAGS` overrides its default value of `-O2` and setting `WARNING_CFLAGS` overrides its default value (starting with `-Wall -W`), so it you just want to add some warning options to the default ones, you can do so by setting `CFLAGS=-O2 -Werror` for example. Setting `WARNING_CFLAGS` is useful when you want to get rid of its default content (for example because your compiler doesn't accept `-Wall` as an option). Directory-specific options cannot be overriden from the command line.

Depending on your platform, you might run into some issues. Please check the Makefiles in `library/`, `programs/` and `tests/` for options to manually add or remove for specific platforms. You can also check [the mbed TLS Knowledge Base](https://tls.mbed.org/kb) for articles on your platform or issue.

In case you find that you need to do something else as well, please let us know what, so we can add it to the KB.

### CMake

In order to build the source using CMake in a separate directory (recommended), just enter at the command line:

    mkdir /path/to/build_dir && cd /path/to/build_dir
    cmake /path/to/mbedtls_source
    make

In order to run the tests, enter:

    make test

The test suites need Perl to be built. If you don't have Perl installed, you'll want to disable the test suites with:

    cmake -DENABLE_TESTING=Off /path/to/mbedtls_source

If you disabled the test suites, but kept the programs enabled, you can still run a much smaller set of tests with:

    programs/test/selftest

To configure CMake for building shared libraries, use:

    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On /path/to/mbedtls_source

There are many different build modes available within the CMake buildsystem. Most of them are available for gcc and clang, though some are compiler-specific:

-   `Release`. This generates the default code without any unnecessary information in the binary files.
-   `Debug`. This generates debug information and disables optimization of the code.
-   `Coverage`. This generates code coverage information in addition to debug information.
-   `ASan`. This instruments the code with AddressSanitizer to check for memory errors. (This includes LeakSanitizer, with recent version of gcc and clang.) (With recent version of clang, this mode also instruments the code with UndefinedSanitizer to check for undefined behaviour.)
-   `ASanDbg`. Same as ASan but slower, with debug information and better stack traces.
-   `MemSan`. This instruments the code with MemorySanitizer to check for uninitialised memory reads. Experimental, needs recent clang on Linux/x86\_64.
-   `MemSanDbg`. Same as MemSan but slower, with debug information, better stack traces and origin tracking.
-   `Check`. This activates the compiler warnings that depend on optimization and treats all warnings as errors.

Switching build modes in CMake is simple. For debug mode, enter at the command line:

    cmake -D CMAKE_BUILD_TYPE=Debug /path/to/mbedtls_source

To list other available CMake options, use:

    cmake -LH

Note that, with CMake, you can't adjust the compiler or its flags after the
initial invocation of cmake. This means that `CC=your_cc make` and `make
CC=your_cc` will *not* work (similarly with `CFLAGS` and other variables).
These variables need to be adjusted when invoking cmake for the first time,
for example:

    CC=your_cc cmake /path/to/mbedtls_source

If you already invoked cmake and want to change those settings, you need to
remove the build directory and create it again.

Note that it is possible to build in-place; this will however overwrite the
provided Makefiles (see `scripts/tmp_ignore_makefiles.sh` if you want to
prevent `git status` from showing them as modified). In order to do so, from
the Mbed TLS source directory, use:

    cmake .
    make

If you want to change `CC` or `CFLAGS` afterwards, you will need to remove the
CMake cache. This can be done with the following command using GNU find:

    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +

You can now make the desired change:

    CC=your_cc cmake .
    make

Regarding variables, also note that if you set CFLAGS when invoking cmake,
your value of CFLAGS doesn't override the content provided by cmake (depending
on the build mode as seen above), it's merely prepended to it.

### Microsoft Visual Studio

The build files for Microsoft Visual Studio are generated for Visual Studio 2010.

The solution file `mbedTLS.sln` contains all the basic projects needed to build the library and all the programs. The files in tests are not generated and compiled, as these need a perl environment as well. However, the selftest program in `programs/test/` is still available.

Example programs
----------------

We've included example programs for a lot of different features and uses in `programs/`. Most programs only focus on a single feature or usage scenario, so keep that in mind when copying parts of the code.

Tests
-----

mbed TLS includes an elaborate test suite in `tests/` that initially requires Perl to generate the tests files (e.g. `test\_suite\_mpi.c`). These files are generated from a `function file` (e.g. `suites/test\_suite\_mpi.function`) and a `data file` (e.g. `suites/test\_suite\_mpi.data`). The `function file` contains the test functions. The `data file` contains the test cases, specified as parameters that will be passed to the test function.

For machines with a Unix shell and OpenSSL (and optionally GnuTLS) installed, additional test scripts are available:

-   `tests/ssl-opt.sh` runs integration tests for various TLS options (renegotiation, resumption, etc.) and tests interoperability of these options with other implementations.
-   `tests/compat.sh` tests interoperability of every ciphersuite with other implementations.
-   `tests/scripts/test-ref-configs.pl` test builds in various reduced configurations.
-   `tests/scripts/key-exchanges.pl` test builds in configurations with a single key exchange enabled
-   `tests/scripts/all.sh` runs a combination of the above tests, plus some more, with various build options (such as ASan, full `config.h`, etc).

Configurations
--------------

We provide some non-standard configurations focused on specific use cases in the `configs/` directory. You can read more about those in `configs/README.txt`

Contributing
------------

We gratefully accept bug reports and contributions from the community. There are some requirements we need to fulfill in order to be able to integrate contributions:

-   Simple bug fixes to existing code do not contain copyright themselves and we can integrate without issue. The same is true of trivial contributions.
-   For larger contributions, such as a new feature, the code can possibly fall under copyright law. We then need your consent to share in the ownership of the copyright. We have a form for this, which we will send to you in case you submit a contribution or pull request that we deem this necessary for.

### Process

1.  [Check for open issues](https://github.com/ARMmbed/mbedtls/issues) or [start a discussion](https://forums.mbed.com/c/mbed-tls) around a feature idea or a bug.
2.  Fork the [Mbed TLS repository on GitHub](https://github.com/ARMmbed/mbedtls) to start making your changes. As a general rule, you should use the "development" branch as a basis.
3.  Write a test which shows that the bug was fixed or that the feature works as expected.
4.  Send a pull request and bug us until it gets merged and published. We will include your name in the ChangeLog :)
