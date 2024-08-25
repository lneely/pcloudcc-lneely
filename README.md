# pCloud Console Client (undead)

This is a simple **linux** console client for pCloud cloud storage, derived from the console-client developed by pCloud.

## Braaaaaains (Fork, please)

This version of pcloudcc is independently maintained by me, whose only affiliation with pCloud is as a user of their services. As of June 2024, the console-client repo (https://github.com/pcloudcom/console-client) seems to have been inactive for several years. This was an attractive alternative for myself and other like-minded weirdos who don't enjoy unneeded GUIs, and it is a shame to see it abandoned.

## Supported Distributions & Packages

pcloudcc-lneely seeks to support as many Linux distributions as possible and has been tested on recent versions of Fedora, Debian, Ubuntu, Arch, and Artix. 

I use Artix and maintain an [AUR](https://aur.archlinux.org/packages/pcloudcc-lneely) package. I do not plan on providing or maintaining any other packages, but encourage anyone interested in doing so for their own distributions.

## Due Credit
- Anton Titov
- Ivan Stoev
- pCloud

## Dependencies  
- zlib (-lz)
- boost (-lboost_system, -lboost_program_options)
- pthread (lpthread)
- udev (-ludev)
- libfuse (-lfuse)
- libsqlite (-lsqlite3)
- libmbedtls (-l:libmbedtls.so.14, -l:libmbedx509.so.1, -l:libmbedcrypto.so.7)

## Building

```
make
```

It's really that easy. Use `make install` to install, and `make uninstall` to uninstall. Specify `DESTDIR` if desired (see **Make Options**). 

## Make Options

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


### Registration

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
startcrypto <crypto pass>: Unlock crypto folder
stopcrypto: Lock crypto folder
finalize: Kill daemon and quit
syncls: List sync folders
syncadd <localpath> <remotepath>: Add sync folder (full sync)
syncrm <folderid>: Remove sync folder
quit(q): Exit this program
```

## Warning

**Stopping daemon will break pending background transfers!**
`pcloudcc` does not currently provide a command to check for pending
transfers. You can currently check this by ensuring there is only one
file named `cached` in `~/.pcloud/Cache`. Usually this is a large
file.

