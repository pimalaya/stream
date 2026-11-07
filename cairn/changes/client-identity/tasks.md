---
cairn: tasks
change: client-identity
---

# Tasks

- [x] Add `Identity { cert, key }` and `Tls::identity`.
- [x] Present it under rustls on both verifier paths, and under native-tls.
- [x] Test it over a real handshake against an in-process rustls server that requires a client certificate, with and without one.
- [x] Check it against a real server: Dovecot with a private-CA client certificate, under both rustls and native-tls.
- [x] Record the user-facing half in CHANGELOG.md.
- [ ] Fold the delta into cairn/spec/tls.md, write the log entry and archive this change once it lands.
- [ ] Follow-up, outside this repository: expose it in himalaya's `TlsConfig`.
