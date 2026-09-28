# Disk full: No space left on device

Use when logs show `No space left on device` (ENOSPC) or writes fail.

## Check usage

```bash
df -h
df -i
du -xh /var --max-depth=2 | sort -h | tail -20
```

`df -i` at 100% means inodes are exhausted even if bytes are free, often from millions of small
cache or session files.

## Safe cleanup

Rotate and compress logs with `logrotate -f /etc/logrotate.conf`. Remove old journal entries with
`journalctl --vacuum-time=7d`. Never delete files that a running process still holds open;
find them with `lsof +L1` and restart that process instead.
