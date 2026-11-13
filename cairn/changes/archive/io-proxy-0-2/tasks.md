---
cairn: tasks
change: io-proxy-0-2
---

# Tasks

- [x] Raise the io-proxy requirement to 0.2 and resolve the lockfile, one version in the graph.
- [x] Hand the proxy password to `Socks5Credentials::new` and `HttpCredentials::new` as a `SecretString`.
- [x] Take an IPv6 target with or without its brackets in `Proxy::connect`.
- [x] Test, through `Proxy::connect` against a local listener: a bracketed IPv6 target sent to SOCKS5 as an address, a refused HTTP target with nothing written, an end of stream during each handshake.
- [x] Fold the target host requirement into cairn/spec/proxy.md.
- [ ] Bound the proxy handshake in time (left open, see the log entry).
- [ ] Decide what the `https` proxy scheme means (left open, see the log entry).
- [ ] Strip the IPv6 brackets before the TLS server name too, in the stream module (left open, see the log entry).
