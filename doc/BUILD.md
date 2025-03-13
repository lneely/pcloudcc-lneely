# Dependencies
- zlib (-lz)
- boost (-lboost_system, -lboost_program_options)
- pthread (lpthread)
- udev (-ludev)
- fuse (-lfuse)
- sqlite (-lsqlite3)
- mbedtls (-lmbedtls -lmbedcrypto -lmbedx509)
- readline (-lreadline)

# Building
```
make
```

(norly! 🦉)

# Installing
```
sudo make install
```

Specify `DESTDIR` to install to a prefix other than `/usr/local`  (see [[#Build Options]]).

# Build Options

Use the following options to influence the build process.

```
make BUILD=debug            # include debug symbols, ASan instrumentation. (default: release)
make STATIC=0               # dynamically link libpcloudcc_lib.so. (default: 1)
make SCAN=1                 # run code analysis; recommend CC=clang and CXX=clang++. (default: 0)
make CC=clang CXX=clang++   # use clang instead of gcc (default: gcc,g++)
make DESTDIR=/prefix        # installation prefix (default: /usr/local/bin)
make SSLDBGLVL=0            # mbedtls debug level (range: 0-5, default: 0)
```
