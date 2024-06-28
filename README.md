# pCloud Console Client (undead)

This is a simple **linux** console client for pCloud cloud storage, originally developed by pCloud.

## Braaaaaains (Fork, please)

This version of pcloudcc is independently maintained by me, whose only affiliation with pCloud is as a user of their services. As of June 2024, the console-client repo (https://github.com/pcloudcom/console-client) seems to have been inactive for several years. This was an attractive alternative for myself and other like-minded weirdos who don't enjoy unneeded GUIs, and it is a shame to see it abandoned.

## Due Credit
- Anton Titov
- Ivan Stoev
- pCloud

## Dependencies
[CMake](https://cmake.org/) build system.  
[Zlib](http://zlib.net/)  A Massively Spiffy Yet Delicately Unobtrusive Compression Library.  
[Boost](http://www.boost.org/) Boost system and boost program options libraries used.  
[Pthread](http://www.gnu.org/)   
[Fuse](https://github.com/libfuse/libfuse) Filesystem in Userspace.


## Build steps

> make

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

> pcloudcc -u example@myemail.com -k

Command Reference:

> startcrypto <crypto pass> - use your password to unlock the crypto folder

> stopcrypto – lock the crypto folder

> finalize – stops the running daemon.

> quit, q  - exits the command prompt, daemon continues running in background

## Warning

**Stopping daemon will break pending background transfers!**
`pcloudcc` does not currently provide a command to check for pending
transfers. You can currently check this by ensuring there is only one
file named `cached` in `~/.pcloud/Cache`. Usually this is a large
file.

