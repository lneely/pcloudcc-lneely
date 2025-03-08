# pCloud Console Client (undead)

This is a simple **linux** console client for pCloud cloud storage, derived from the console-client developed by pCloud.

## Braaaaaains (Fork, please)

This version of pcloudcc is independently maintained by me, whose only affiliation with pCloud is as a user of their services. As of June 2024, the console-client repo (https://github.com/pcloudcom/console-client) seems to have been inactive for several years. This was an attractive alternative for myself and other like-minded weirdos who don't enjoy unneeded GUIs, and it is a shame to see it abandoned.

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

### Untested Workarounds

Fundamentally, the workaround is to log in to pcloud.com using a web browser from the target device. Therefore the following (untested) workarounds may also work.

**SSH/X11 forwarding**. *Requires web browser, X11 forwarding over SSH on host. Requires X11 client on local machine.*. If a sufficiently capable web browser and X11 forwarding are available on the host, login to SSH with X11 forwarding enabled (`ssh -X <targethost>`) and run the web browser from the SSH session to log in and validate the device. 

**Remote Desktop / VNC**. *Requires a sufficiently capable web browser and RDP/VNC capabilities on host*. Run the web browser in a remote desktop session to log in and validate the device. 

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
  `crypto start` password or paths with spaces) must now be quoted or
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

