# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the protocol-agnostic `Sasl` enum and `SaslMechanism` tag.

  Variants `Anonymous`, `Login`, `Plain`, `OAuthBearer`, `XOAuth2`, `ScramSha256` wrap per-mechanism structs (`SaslAnonymous`, `SaslLogin`, `SaslPlain`, `SaslOauthbearer`, `SaslXoauth2`, `SaslScramSha256`) carrying only the bits each mechanism actually transmits. Consumer crates translate them into the appropriate protocol framing.

- Added the `Tls` configuration struct.

  Carries a `provider: Option<TlsProvider>` selector (`Rustls` / `NativeTls`, falling back to the first enabled feature in the order `rustls-ring`, `rustls-aws`, `native-tls`), a `Rustls` sub-struct (crypto provider + ALPN list) and an optional PEM trust anchor path.

- Added the `StreamStd` blocking transport behind the `std` feature.

  Single `Read + Write` handle wrapping a TCP socket, a Unix-domain socket, a `rustls` TLS session or a `native-tls` TLS session. Constructors: `connect_tcp`, `connect_unix`, `connect_tls` (implicit TLS), `upgrade_tls` (STARTTLS).

- Added the `rustls-ring` cargo feature (default).

  Enables the rustls TLS backend with the ring crypto provider; pulls in `rustls`, `rustls-platform-verifier` and gates the `Rustls(...)` `StreamStd` variant.

- Added the `rustls-aws` cargo feature.

  Same rustls backend but with the aws-lc-rs crypto provider.

- Added the `native-tls` cargo feature.

  Enables the platform-backed `native-tls` TLS backend and gates the `NativeTls(...)` `StreamStd` variant.

- Added the `vendored` cargo feature.

  Forwarded to `native-tls/vendored` so consumers can compile the underlying TLS dependencies in vendored mode.

[unreleased]: https://github.com/pimalaya/stream/compare/root..HEAD
