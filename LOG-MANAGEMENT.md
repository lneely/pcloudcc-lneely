# Log Management Guide

This guide covers log configuration and rotation for `pcloudcc`.

## Log Files

`pcloudcc` supports two types of logs:

1. **Debug Log** - Operational information, errors, and debug messages
   - Default location: `~/.pcloud/debug.log`
   - Configure with: `--log-path` and `--log-level`

2. **Filesystem Events Log** - Clean log of file/folder operations only
   - Disabled by default
   - Enable with: `--fs-event-log`

## Log Configuration

### Log Level

Control verbosity with `--log-level`:

```bash
# Errors only
pcloudcc -u user@example.com -d --log-level ERROR

# Normal operation (default)
pcloudcc -u user@example.com -d --log-level INFO

# Detailed debugging
pcloudcc -u user@example.com -d --log-level DEBUG

# Disable logging
pcloudcc -u user@example.com -d --log-level NONE
```

Available levels: `NONE`, `ERROR`, `WARNING`, `INFO`, `NOTICE`, `DEBUG`

### Custom Log Path

```bash
# System-wide log
pcloudcc -u user@example.com -d --log-path /var/log/pcloudcc.log

# Custom user location
pcloudcc -u user@example.com -d --log-path ~/logs/pcloud.log
```

### Filesystem Events Log

Enable a separate log containing only filesystem events:

```bash
pcloudcc -u user@example.com -d --fs-event-log ~/.pcloud/fs-events.log
```

Event format: `<timestamp> <event_type> <path>`

Example events:
```
Wed, 12 Nov 2025 05:24:23.032 +0000 file deleted /tmp/xxx
Wed, 12 Nov 2025 05:24:47.861 +0000 folder moved /tmp/test2 -> /tmp/test3
Wed, 12 Nov 2025 05:25:10.445 +0000 file created /tmp/newfile.txt
```

## Log Rotation

### System-Wide (with logrotate)

Install the provided configuration:

```bash
sudo cp pcloudcc.logrotate /etc/logrotate.d/pcloudcc
```

This rotates logs daily, keeps 7 days of history, and compresses old logs.

### User-Specific Rotation

Create `~/.logrotate.conf`:

```
/home/username/.pcloud/debug.log /home/username/.pcloud/fs-events.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 0600 username username
    maxsize 50M
    postrotate
        pkill -USR2 -u username pcloudcc 2>/dev/null || true
    endscript
}
```

Add to crontab:

```bash
crontab -e
# Add this line:
0 2 * * * /usr/sbin/logrotate -s ~/.logrotate.state ~/.logrotate.conf
```

### Manual Rotation

```bash
# Move current logs
mv ~/.pcloud/debug.log ~/.pcloud/debug.log.old
mv ~/.pcloud/fs-events.log ~/.pcloud/fs-events.log.old

# Signal pcloudcc to reopen logs
pkill -SIGUSR2 pcloudcc
```

## Cache Management

Configure cache size (default 5GB):

```bash
# Set to 10GB
pcloudcc -u user@example.com -d --cache-size 10

# Set to 1GB for limited storage
pcloudcc -u user@example.com -d --cache-size 1
```

Check cache usage:

```bash
du -sh ~/.pcloud/Cache
```

Cache is stored in `~/.pcloud/Cache/` and managed automatically by `pcloudcc`.
