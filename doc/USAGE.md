# pcloudcc usage

## Getting Help

Terminal command is pcloudcc and -h option prints short options description.

```bash
pcloudcc -h
```

## New Options

### Cache Size Management

By default, the cache is limited to 5GB. You can adjust this with `--cache-size` (value in GB):

```bash
# Set cache to 10GB
pcloudcc -u example@myemail.com -d --cache-size 10

# Set to 1GB for limited storage systems
pcloudcc -u example@myemail.com -d --cache-size 1
```

### Custom Log Path

By default, logs are written to `~/.pcloud/debug.log`. You can specify a custom path:

```bash
# System-wide log (requires permissions)
pcloudcc -u example@myemail.com -d --log-path /var/log/pcloudcc.log

# Custom user log
pcloudcc -u example@myemail.com -d --log-path ~/my-pcloud.log
```

See [LOG-MANAGEMENT.md](../LOG-MANAGEMENT.md) for log rotation configuration.

### Log Level Control

By default, the logging level is set to INFO. You can adjust verbosity with `--log-level`:

```bash
# Minimal logging (errors only)
pcloudcc -u example@myemail.com -d --log-level ERROR

# Quiet mode (no logging)
pcloudcc -u example@myemail.com -d --log-level NONE

# Detailed logging for troubleshooting
pcloudcc -u example@myemail.com -d --log-level DEBUG
```

Available levels (from least to most verbose):
- `NONE` - Disable all logging
- `ERROR` - Only critical errors
- `WARNING` - Errors and warnings
- `INFO` - Normal operation info (default)
- `NOTICE` - Informational notices
- `DEBUG` - Detailed debug information

### Filesystem Events Log

Enable a separate log containing only filesystem events (no debug messages):

```bash
pcloudcc -u example@myemail.com -d --fs-event-log ~/.pcloud/fs-events.log
```

**Event format:** `<timestamp> <event_type> <path>`

**Event types:**
- `file created`, `file modified`, `file deleted`, `file downloaded`
- `file moved <oldpath> -> <newpath>`
- `folder created`, `folder deleted`
- `folder moved <oldpath> -> <newpath>`

**Example log entries:**
```
Wed, 12 Nov 2025 05:24:23.032 +0000 file deleted /tmp/xxx
Wed, 12 Nov 2025 05:24:47.861 +0000 folder moved /tmp/test2 -> /tmp/test3
Wed, 12 Nov 2025 05:25:10.445 +0000 file created /tmp/newfile.txt
```

See [LOG-MANAGEMENT.md](../LOG-MANAGEMENT.md) for monitoring scripts and log rotation setup.

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

**Daemon mode (`-d`) is the recommended way to run pcloudcc in production.** Running in foreground mode can cause FUSE filesystem errors and crashes if interrupted.

If you have saved your password, then you can run pcloudcc as a background daemon:

```bash
pcloudcc -u example@myemail.com -d
```

With custom mount point, cache size, and log path:

```bash
pcloudcc -u example@myemail.com -d -m /mnt/pcloud --cache-size 10 --log-path /var/log/pcloudcc.log
```

Verify the filesystem is mounted when the daemon starts:

```bash
mount | grep pCloud
ps aux | grep pcloudcc
```

### Stopping the Daemon

To stop the daemon gracefully, use one of these methods:

```bash
# Graceful shutdown (recommended)
pkill -TERM pcloudcc

# Or use the command prompt
pcloudcc -k
# Then type: finalize
```

**Important**: Do NOT use `kill -9` or interrupt with Ctrl+C, as this can cause filesystem corruption.

### Available Signals

- **SIGTERM / SIGINT**: Gracefully shut down the daemon
- **SIGHUP**: Terminate the daemon (exits the process)
- **SIGUSR1**: Dump internal debugging information (debug builds only)
- **SIGUSR2**: Reopen log files for rotation

#### Log Rotation with SIGUSR2

The daemon responds to SIGUSR2 by reopening both the debug log and fs-events log (if enabled). This allows safe log rotation:

```bash
# Manual log rotation
mv ~/.pcloud/debug.log ~/.pcloud/debug.log.old
pkill -SIGUSR2 pcloudcc

# With fs-events log
mv ~/.pcloud/fs-events.log ~/.pcloud/fs-events.log.old
pkill -SIGUSR2 pcloudcc
```

For automatic log rotation with logrotate, see [LOG-MANAGEMENT.md](../LOG-MANAGEMENT.md).

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
