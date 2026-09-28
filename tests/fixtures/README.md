# Test fixtures

Everything here is synthetic and is published with the repository. Never add real logs,
configs, or command output. Real incidents belong in `var/` or on a USB drive, and both
are kept out of Git.

`tests/test_fixtures.py` enforces this: addresses must be private, loopback, or reserved
for documentation (RFC 1918, RFC 5737), hosts must use reserved names (RFC 2606), and any
line that the redaction rules would mask must be marked `EXAMPLE` or use a known fake password.
