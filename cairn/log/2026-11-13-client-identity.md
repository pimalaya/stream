---
cairn: log
change: client-identity
landed: 2026-11-13
---

# A client certificate for mutual TLS

A server that asks for a client certificate during the handshake refused every Pimalaya client: each connect ended in `with_no_client_auth()` under rustls and in a connector with no identity under native-tls, whatever the protocol crate above wanted. `Tls::client` now names one, a `TlsClient` holding the certificate (optionally followed by its intermediates) and its private key as PEM paths. Both backends present it, rustls through `with_client_auth_cert` on the pinned and the platform-verifier paths alike, native-tls through `Identity::from_pkcs8`, which is why a native-tls key must be PKCS#8 while rustls also reads PKCS#1 and SEC1.

Beside a client certificate, the bare `Tls::cert` no longer said whose certificate it was, so it moved to `Tls::server`, a `TlsServer` holding the `cert`. What it does is unchanged: pinned to the leaf and offered as an extra anchor under rustls, a root under native-tls. Splitting by role is what makes this a breaking change rather than an added field; it was asked for in review so the two certificates can never be confused.

It was tested over a real handshake against an in-process rustls server requiring a client certificate, with and without one, and by hand against Dovecot with a private-CA client certificate under both backends.

Every consumer naming `Tls::cert` moves to `Tls::server` when it is bumped. himalaya exposes the client certificate in its `TlsConfig` first.

Capabilities moved: tls.
