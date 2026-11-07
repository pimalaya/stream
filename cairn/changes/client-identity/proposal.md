---
cairn: change
id: client-identity
status: active
created: 2026-11-06
---

# A client certificate for mutual TLS

## Why

Some mail servers ask the client for a certificate during the handshake and refuse a login without one, a private CA's client certificate standing in for, or beside, the password. Every connect here ends in `with_no_client_auth()` under rustls and in a connector with no identity under native-tls, so no Pimalaya client can reach such a server at all, whatever the protocol crate above does.

## What

- `Tls` gains `identity: Option<Identity>`, `None` by default, so every existing consumer is unchanged.
- `Identity { cert, key }` holds two PEM paths: the client certificate, optionally followed by its intermediates, and its private key. Paths rather than bytes, like `Tls::cert`, so a config layer passes through what the user wrote.
- Under rustls the chain and key go to `with_client_auth_cert`, on both the pinned-certificate and the platform-verifier paths; the platform branch moves from `ClientConfig::with_platform_verifier()` to `ClientConfig::builder().with_platform_verifier()` so the client-auth step can follow it.
- Under native-tls they become `native_tls::Identity::from_pkcs8`, which reads a PKCS#8 key only; rustls also reads PKCS#1 and SEC1.

The backend types still never escape the crate: `Identity` is plain paths.

## Cost

Additive. `Tls` is a struct of public fields, so a consumer building it with a struct literal and no `..Default::default()` stops compiling until it names the new field. Within the org, every io- crate and himalaya pass `Tls` through from their own config, so each one wanting to expose the option adds a config field: himalaya's `TlsConfig` first, as `client-cert` and `client-key`.
