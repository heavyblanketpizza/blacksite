# nginx returns 502 Bad Gateway

A 502 means nginx could not get a valid response from the upstream (the application server).

## Read the error log

| Error text | Meaning |
| --- | --- |
| `connect() failed (111: Connection refused)` | Nothing is listening on the upstream port: the app is down or restarting. |
| `upstream prematurely closed connection` | The app accepted the request and then died or closed the socket. |
| `upstream timed out (110: Connection timed out)` | The app is alive but too slow; see proxy_read_timeout. |
| `no live upstreams` | Every server in the upstream block is marked failed. |

## Next steps

For connection refused, check whether the application process is running and why it stopped:
`systemctl status`, the service journal, and the kernel log for OOM kills. Bursts of 502s
that stop after a few seconds usually match application restarts.

Do not raise nginx timeouts for connection refused errors: the upstream is not slow, it is absent.
