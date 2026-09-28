# Process killed by the OOM killer

Use when a service restarts unexpectedly and the kernel log shows `Out of memory: Killed process`
or systemd reports `Failed with result 'oom-kill'`.

## Confirm the kill

Kernel messages name the victim process and its memory at the time:

```bash
journalctl -k --since "1 hour ago" | grep -iE "out of memory|oom-kill|killed process"
systemctl status app.service
```

`Memory cgroup out of memory` means the service hit its own cgroup limit (`MemoryMax`), not
that the whole host ran out. Compare `anon-rss` in the kill message with the unit's limit:

```bash
systemctl show app.service -p MemoryMax -p MemoryCurrent -p MemoryPeak
```

## Find what grew

A limit that worked before a deploy usually means the new version uses more memory. Look for
steadily rising heap or cache metrics in the application log between restarts, and check the
release notes for new caches or larger batch sizes.

## Fix

Prefer fixing the growth: bound the cache, lower batch sizes, or roll back the release.
Raising `MemoryMax` with `systemctl edit app.service` buys time but hides a leak.
Record the old value first so the change can be reverted with `systemctl revert app.service`.

Restarting the service drops in-flight requests; schedule it when traffic is low.
