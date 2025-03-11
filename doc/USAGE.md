# pcloudcc usage

## Getting Help

Terminal command is pcloudcc and -h option prints short options description.

> pcloudcc -h

## First Use

Start the service in the foreground using the -p switch to enter your
password, and the -s switch to save the password to the
database. Verify that file system starts and mounts normally after the

> pcloudcc -u example@myemail.com -p -s

Optionally specify your own mount point.

> pcloudcc -u example@myemail.com -p -s -m /path/to/mountpoint

## Registration (UNTESTED)

If you don't have existing user use -n switch to register new user:

> pcloudcc -u example@myemail.com -p -s -n

Notice that a new user may take a while to mount. Please, be patient.

## Run as Daemon

If you have saved your password, then you can run pcloudcc as a
background daemon. Verify the filesystem is mounted when the daemon
starts.

> pcloudcc -u example@myemail.com -d

## Command Prompt

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
