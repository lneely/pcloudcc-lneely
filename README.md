# pCloud Console Client (undead)

`pcloudcc` is simple **linux** console client for pCloud cloud storage derived from the console-client developed by pCloud. This version is independently maintained by me, whose only affiliation with pCloud is as a user of their services. Due credit goes to Anton Titov, Ivan Stoev, and pCloud.

## mbedtls 3.x Migration Notice

`pcloudcc` now uses `mbedtls` version 3.x. This may already be included in your distribution, and if it is, you can ignore this section. If you're unlucky enough that your distribution still ships with `mbedtls` 2.x *(looking at you, Debian...)*, then try the following instructions. This has been tested on debian bookworm, **but you may have to adjust for your own distribution -- the command sequence below uses `apt` to install known build dependencies.**

Without further ado, the first step is to build and install the `mbedtls` 3.x library on your host machine without breaking the distribution. Review the following commands, then copy and paste them into a terminal to run them.

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

The symbolic link at the end resolves the ambiguity between `/usr/include/mbedtls` and `/usr/local/include/mbedtls`. Now, we need to make some edits to the Makefile and the source files to ensure that the build using the correct `mbedtls` headers and libraries. We'll do this with `sed`, then run `make` as usual.

```
# run from the source root directory (e.g., pcloudcc-lneely)

sed -i 's/-lmbedtls/-l:libmbedtls.a/;s/-lmbedcrypto/-l:libmbedcrypto.a/;s/-lmbedx509/-l:libmbedx509.a/' Makefile
sed -i '5s/$/ -I\/usr\/local\/include/' Makefile
sed -i '10s/$/ -L\/usr\/local\/lib\//' Makefile
find . -type f -name "*.[ch]" -exec sed -i 's/#include <mbedtls/#include <mbedtls3/' {} +
make clean all
```

You should now have a working `pcloudcc` on your system!

## Security Notice

While security enhancements are currently being planned, you should be aware that this program currently stores your password and crypto password as an unencrypted string in memory (see: [pclsync_lib.cpp](https://github.com/lneely/pcloudcc-lneely/blob/main/pclsync_lib.cpp). Advise running this program only on a host that you trust and do not share with anyone else.

## Validating Your Device

pCloud requires "first time" validation for all devices. In the standard use case, where the user is running `pcloudcc` on the same host s/he normally works on, this can be completed by simply logging into pcloud.com using the web browser (and often, it already has been). Non-standard use cases (e.g., running `pcloudcc` on a remote server) require a different approach. 

### Tested Workarounds

Props to [@tieum](https://github.com/tieum), [@ebouda333](https://github.com/ebouda33), [@CorvusCorax](https://github.com/CorvusCorax), and [@tomash](https://github.com/tomash) for suggesting the following workarounds:
 
**Dockerized Carbonyl**. *Requires Docker or Podman on the host.*. Run [carbonyl](https://github.com/fathyb/carbonyl) in a container on the target host to complete the validation.

```
docker run --network host --rm -ti fathyb/carbonyl https://my.pcloud.com
```
**SOCKS proxy over SSH** *Requires TCP port forwarding over SSH*. Log in to the remote host using the command `ssh -D <port>` to enable a SOCKS proxy on `localhost:<port>`. Configure your local web browser to use `localhost:<port>` as its proxy, then log in to pcloud.com and validate the device. *Do not forget to remove the proxy from your browser configuration when done.*

## Supported Distributions & Packages

I aim to support as many distributions as possible, and maintain an [AUR](https://aur.archlinux.org/packages/pcloudcc-lneely) package. I do not plan on providing or maintaining any other packages, but encourage anyone interested in doing so for their own distributions.

## Dependencies
- zlib (-lz)
- boost (-lboost_system, -lboost_program_options)
- pthread (lpthread)
- udev (-ludev)
- libfuse (-lfuse)
- libsqlite (-lsqlite3)
- libmbedtls (3.x)

## Building

```
make
```

### Build Options

```
make BUILD=debug            # include debug symbols, ASan instrumentation. (default: release)
make STATIC=0               # dynamically link libpcloudcc_lib.so. (default: 1)
make SCAN=1                 # run code analysis; recommend CC=clang and CXX=clang++. (default: 0)
make CC=clang CXX=clang++   # use clang instead of gcc (default: gcc,g++)
make DESTDIR=/prefix        # installation prefix (default: /usr/local/bin)
```

## Usage

### Getting Help

Terminal command is pcloudcc and -h option prints short options description.

> pcloudcc -h

### First Use

Start the service in the foreground using the -p switch to enter your
password, and the -s switch to save the password to the
database. Verify that file system starts and mounts normally after the

> pcloudcc -u example@myemail.com -p -s

Optionally specify your own mount point.

> pcloudcc -u example@myemail.com -p -s -m /path/to/mountpoint

### Registration (UNTESTED)

If you don't have existing user use -n switch to register new user:

> pcloudcc -u example@myemail.com -p -s -n

Notice that a new user may take a while to mount. Please, be patient.

### Run as Daemon

If you have saved your password, then you can run pcloudcc as a
background daemon. Verify the filesystem is mounted when the daemon
starts.

> pcloudcc -u example@myemail.com -d

### Command Prompt

Use the command prompt to interact with a running daemon. 

> pcloudcc -k

Command Reference:

```
  help(?): Show this help message
  crypto(c):
    start <crypto pass>: Unlock crypto folder
    stop: Lock crypto folder
  sync(s):
    list(ls): List sync folders
    add <localpath> <remotepath>: Add sync folder
    remove(rm) <folderid>: Remove sync folder
  finalize(f): Kill daemon and quit
  quit(q): Exit this program
```

**Note**. Command line arguments that include special characters (e.g., the
  `crypto start` password or paths with spaces) must be quoted or
  escaped. In other words, instead of:

  `startcrypto Str0ng p4$$word 4 great jUSTicE!`

  One must now type, for example:

  `c start 'Str0ng p4$$word 4 great jUSTicE!'`

  If the password includes quotes for some reason, then those characters must
  be escaped properly.

## Warning

**Stopping daemon will break pending background transfers!**
`pcloudcc` does not currently provide a command to check for pending
transfers. You can currently check this by ensuring there is only one
file named `cached` in `~/.pcloud/Cache`. Usually this is a large
file.

