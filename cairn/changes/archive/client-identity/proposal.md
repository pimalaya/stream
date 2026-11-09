---
cairn: change
id: client-identity
status: landed
created: 2026-11-06
---

# A client certificate for mutual TLS

## Why

Some mail servers ask the client for a certificate during the handshake and refuse a login without one, a private CA's client certificate standing in for, or beside, the password. Every connect here ends in `with_no_client_auth()` under rustls and in a connector with no identity under native-tls, so no Pimalaya client can reach such a server at all, whatever the protocol crate above does.

## What

- `Tls` gains `client: Option<TlsClient>`, `None` by default. `TlsClient { cert, key }` holds two PEM paths: the client certificate, optionally followed by its intermediates, and its private key.
- Beside it, a bare `Tls::cert` no longer says whose certificate it is, so it moves to `server: Option<TlsServer>`, `TlsServer { cert }`. The certificate does what it did.
- Paths rather than bytes on both sides, so a config layer passes through what the user wrote.
- Under rustls the chain and key go to `with_client_auth_cert`, on both the pinned-certificate and the platform-verifier paths; the platform branch moves from `ClientConfig::with_platform_verifier()` to `ClientConfig::builder().with_platform_verifier()` so the client-auth step can follow it.
- Under native-tls they become `native_tls::Identity::from_pkcs8`, which reads a PKCS#8 key only; rustls also reads PKCS#1 and SEC1.

The backend types still never escape the crate: both structs are plain paths.

## Cost

Breaking, so a minor bump. Every consumer naming `Tls::cert` moves to `Tls::server`, a one-line change; one using `..Default::default()` and no certificate is untouched. Within the org, every io- crate and himalaya pass `Tls` through from their own config, so each moves its `cert` mapping when it is bumped, and each one wanting the client certificate adds a config field: himalaya's `TlsConfig` first.
