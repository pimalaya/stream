# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `tls::TlsClient` and `Tls::client`, a client certificate and its private key as PEM paths, presented when the server asks for one (mutual TLS). Both backends present it; native-tls reads a PKCS#8 key only, rustls PKCS#1 and SEC1 too. Unset by default, so nothing is presented unless a consumer names one.

### Changed

- `Tls::cert` moved to `Tls::server`, a `tls::TlsServer` holding the `cert`. **Breaking.**

  Beside a client certificate, a bare `cert` no longer said whose it was. `cert: Some(path)` becomes `server: Some(TlsServer { cert: path })`; what the certificate does is unchanged.

## [0.3.1] - 2026-11-03

### Changed

- Changed the minimum Rust version to 1.89.

- Changed the io-proxy requirement to 0.1.1, which replaced the base64 crate with base64-codec.

### Security

- Raised the rustls requirement to 0.23.46, fixing RUSTSEC-2026-0346 to RUSTSEC-2026-0349.

## [0.3.0] - 2026-08-15

### Added

- Added `retry::Retry`, what a stream does when a read or a write reports it is not ready: `Never` hands the failure back untouched, `Until(Duration)` retries until that long passes without progress and then fails with `TimedOut`. Streams open with `Retry::default()`, which is `Until` the new `retry::DEFAULT_TIMEOUT` of one minute.

  A blocking socket is not supposed to report `EAGAIN`, yet callers do see one surface mid-exchange, macOS especially and the more readily the longer the exchange runs. Every protocol crate above was ending its exchange there, on a stream that was merely not ready yet: himalaya#731 and himalaya#732 are the same bare `Resource temporarily unavailable (os error 35)` reported from an IMAP `SORT` fallback and from a slow `AUTHENTICATE`, and every client arming a read deadline of its own was building the same failure in on purpose. The strategy is the only thing a caller chooses, `Read` and `Write` honoring it without a method of their own to call.

- Added `stream::TcpConnectOptions`, `stream::TlsConnectOptions` and `stream::UnixConnectOptions`, one per transport, each holding what that transport has and nothing more: a proxy where there is one to route through, TLS settings where there is a session to secure, and the retry strategy everywhere. All public fields with a `Default`, the shape the io- protocol crates already use for their own options.

### Changed

- `Read` and `Write` on `Stream` now honor the stream's retry strategy. **Behaviour change.**

  Reads, writes and flushes retry `EAGAIN`, `EINTR` and the Windows spelling of an expired deadline, pausing from one millisecond up to 250 between attempts and logging the raw errno of each at debug level. Each call carries its own budget, so a slow but progressing transfer never runs out, and the `write_all` std builds on `write` inherits the whole thing. Exhausting the budget yields `TimedOut` with a message saying so, in place of the raw errno callers used to surface. A caller that wants the not-ready failures for itself, a watcher polling a shutdown flag between IDLE keep-alives being the usual case, selects `Retry::Never`.

- Opening a stream now arms a socket read deadline matching its retry strategy, one minute by default. **Behaviour change.**

  Without it the budget would not be enforceable: a server that goes silent on an otherwise healthy connection blocks the caller in `read` forever, which is where the deadline turns the silence into a retry the budget can count. A caller arming a shorter one of its own keeps it, and only gets more wakeups.

- `Stream::connect_tcp`, `Stream::connect_tls` and `Stream::connect_unix` take their transport's options struct. **Breaking.**

  `connect_tls(&host, port, &tls)` becomes `connect_tls(&host, port, TlsConnectOptions { tls, ..Default::default() })`, and the proxy that only the builder could set is now a field beside it. A caller with nothing to say passes the default options and gets the ambient proxy and the default strategy.

- `Stream::retry` is a public field, replacing a setter. **Breaking.**

  Assigning `Retry::Never` is how a caller takes the not-ready failures back mid-connection, which is the only such switch the org makes. Assigning a different `Retry::Until` changes the budget alone: the deadline was armed at connect time, so a caller wanting a matching one calls `set_read_timeout` beside it rather than having a setter re-arm the socket behind its back.

- `Stream::set_nonblocking` no longer touches the retry strategy, and takes `&self` again. A caller reaching for non-blocking mode assigns `Retry::Never` beside it, the two settings being contradictory: it wants the `WouldBlock` failures a strategy would spend its whole budget hiding.

- Renamed `StreamStd` to `stream::Stream`, and dropped the `Stream` prefix from the rest of the public types: `StreamRetry` is `retry::Retry`, `DEFAULT_RETRY_TIMEOUT` is `retry::DEFAULT_TIMEOUT`, and the options structs are `stream::TcpConnectOptions`, `stream::TlsConnectOptions` and `stream::UnixConnectOptions`. **Breaking.**

  The crate name and the module path already namespace what these hold, which is why `Proxy` and `Tls` never carried a prefix either. Consumers import `pimalaya_stream::stream::Stream`, aliasing it where a `Stream` of their own is already in scope.

- Moved `Retry` and `DEFAULT_TIMEOUT` to a `retry` module of their own, with the loop honoring them. **Breaking.**

  The stream module carried two subjects: the transport it exists for, and the policy its reads and writes run under. The loop stays a method on `Stream`, running an operation being the job of the thing holding the socket, but it is written next to the strategy it honors.

- Replaced `proxy::dial` with `Proxy::connect`. **Breaking.**

  `dial(host, port, &proxy)` becomes `proxy.connect(host, port)`. A stream connects and a proxy dialled, which was one act under two verbs depending on the layer being read. The module's other free functions became private associated ones with it, so nothing floats at module level and the two public methods are visibly the surface.

- Moved `std::stream` and `std::proxy` to the crate root as `stream` and `proxy`. **Breaking.**

  The runtime module existed so an async twin could sit beside it as `tokio`, and there is none coming: this crate stays blocking. Imports lose the middle segment, `pimalaya_stream::std::stream::Stream` becoming `pimalaya_stream::stream::Stream`. The `std` cargo feature keeps its name and its job, gating the transport and the proxy selector so a consumer wanting only the TLS configuration vocabulary still gets it without sockets.

### Removed

- Removed `stream::StreamBuilder` and `Stream::builder`. **Breaking.**

  Four entry points said the same thing: three constructors, a builder with a setter per field, and two private layers behind both. Chained setters were also a second vocabulary for a job the rest of Pimalaya does with an options struct. Everything the builder could say, the connect options say.

## [0.2.0] - 2026-08-15

### Added

- Added examples for the three shapes a consumer opens a connection in: implicit TLS, a STARTTLS upgrade, and a connect through an explicitly configured proxy.

### Changed

- Rescoped the crate as public, dropping the internal-usage disclaimer from the README and the crate documentation.

  The blocking stream, the TLS options and the proxy selector are documented for any consumer of the io- protocol crates, not only for Pimalaya's own products. The crate stays on 0.x: breaking changes land in minor bumps and never in patch bumps.

### Removed

- Removed the `sasl` module. **Breaking.**

  `Sasl`, `SaslMechanism` and the six credential structs moved to io-sasl, which is no_std, opens nothing and pairs each credential type with the coroutine that computes its payloads. Callers import them from there, where the structs carry a `Creds` suffix (`SaslPlainCreds`, `SaslLoginCreds`, ...) and SCRAM gained the client nonce and the channel binding the mechanism needs.

  This is what the extraction was for: a transport crate wrapping sockets and TLS sessions had become the home of a vocabulary that a no_std protocol core needed, so io-imap and io-smtp had to depend on it just to name a mechanism. Both now depend on it only for their std clients, and their coroutine cores are free of it.

## [0.1.2] - 2026-07-26

### Added

- Added the `Proxy` selector and blocking `dial` under the `std::proxy` module (`std` feature), letting every `StreamStd` connect tunnel through a proxy.

  Variants: `None` (direct), `Socks5` and `Http` (`CONNECT`) with optional username/password auth, and the default `System`, which resolves `all_proxy`/`https_proxy` from the environment at dial time, honouring `no_proxy` and always bypassing loopback. `Proxy::from_url` parses `socks5://`, `socks5h://`, `socks://`, `http://` and `https://` URLs. The handshakes run on the I/O-free `io-proxy` coroutines.

## [0.1.1] - 2026-07-25

### Fixed

- Fixed the `tls.cert` option being unusable for self-signed servers (Proton Bridge, self-hosted).

  Under rustls a configured certificate is now pinned to the server's leaf, instead of being registered as a CA trust anchor that rejected the self-signed leaf with `CaUsedAsEndEntity`. A server presenting a different leaf still falls back to using the certificate as an extra trust anchor.

## [0.1.0] - 2026-07-15

### Changed

- Aligned logging with the Pimalaya guidelines: connect and upgrade lifecycle points now log a short debug phrase followed by trace lines carrying the data (host, port, path), instead of single data-inlined traces.

### Removed

- Removed the unused serde dependency, along with the serde feature of secrecy, lightening the dependency tree.

## [0.0.1] - 2026-06-03

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

[unreleased]: https://github.com/pimalaya/stream/compare/v0.3.1..HEAD
[0.3.1]: https://github.com/pimalaya/stream/compare/v0.3.0..v0.3.1
[0.3.0]: https://github.com/pimalaya/stream/compare/v0.2.0..v0.3.0
[0.2.0]: https://github.com/pimalaya/stream/compare/v0.1.2..v0.2.0
[0.1.2]: https://github.com/pimalaya/stream/compare/v0.1.1..v0.1.2
[0.1.1]: https://github.com/pimalaya/stream/compare/v0.1.0..v0.1.1
[0.1.0]: https://github.com/pimalaya/stream/compare/v0.0.1..v0.1.0
[0.0.1]: https://github.com/pimalaya/stream/compare/root...v0.0.1
