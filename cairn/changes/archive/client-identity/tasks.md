---
cairn: tasks
change: client-identity
---

# Tasks

- [x] Add `TlsClient { cert, key }` and `Tls::client`.
- [x] Move `Tls::cert` to `Tls::server`, a `TlsServer { cert }`, so each certificate says whose it is.
- [x] Present the client certificate under rustls on both verifier paths, and under native-tls.
- [x] Test it over a real handshake against an in-process rustls server that requires a client certificate, with and without one.
- [x] Check it against a real server: Dovecot with a private-CA client certificate, under both rustls and native-tls.
- [x] Record the user-facing half in CHANGELOG.md.
- [x] Fold the delta into cairn/spec/tls.md, write the log entry and archive this change.
- [ ] Follow-up, outside this repository: move each consumer's `cert` to `server` when it is bumped, and expose the client certificate in himalaya's `TlsConfig`.
