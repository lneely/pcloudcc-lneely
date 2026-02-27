## mbedtls 3.x Migration Notice

`pcloudcc` now uses `mbedtls` version 3.x. This may already be included in your distribution, and if it is, you can ignore this section. If you're unlucky enough that your distribution still ships with `mbedtls` 2.x *(looking at you, Debian...)*, then try the following instructions. This has been tested on debian bookworm, **but you may have to adjust for your own distribution -- the command sequence below uses `apt` to install known build dependencies.**

Without further ado, the first step is to build and install the `mbedtls` 3.x library on your host machine, hopefully without breaking the distribution version. Review the following commands, then copy and paste them into a terminal to run them.

```
sudo apt install python3 python3-pip python3-venv
mkdir -p $HOME/src; cd $HOME/src
git clone https://github.com/Mbed-TLS/mbedtls/
cd mbedtls
git checkout tags/v3.6.2
git submodule update --init
python3 -m venv ./venv
source ./venv/bin/activate
python3 -m pip install -r scripts/basic.requirements.txt
make
sudo make install
sudo ln -s /usr/local/include/mbedtls/ /usr/local/include/mbedtls3
```

The symbolic link at the end resolves the ambiguity between `/usr/include/mbedtls` and `/usr/local/include/mbedtls`. Now, we need to make some edits to the Makefile and the source files to ensure that the build uses the correct `mbedtls` headers and libraries. We'll do this with `sed`, then run `make` as usual.

```
# run from the source root directory (e.g., pcloudcc-lneely)

sed -i 's/-lmbedtls/-l:libmbedtls.a/;s/-lmbedcrypto/-l:libmbedcrypto.a/;s/-lmbedx509/-l:libmbedx509.a/' Makefile
sed -i 's/LIBLDFLAGS\t= \$(COMMONFLAGS)/LIBLDFLAGS\t= $(COMMONFLAGS) -L\/usr\/local\/lib\//' Makefile
sed -i '5s/$/ -I\/usr\/local\/include/' Makefile
find . -type f -name "*.[ch]" -exec sed -i 's/#include <mbedtls/#include <mbedtls3/' {} +
make clean all
```

You should now have a working `pcloudcc` on your system!