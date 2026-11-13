//! User-facing TLS configuration.
//!
//! Consumers construct a [`Tls`] and pass it to a runtime-specific connector
//! (e.g. [`Stream::connect_tls`] / [`Stream::upgrade_tls`]); the
//! underlying TLS backend types (`rustls`, `native-tls`) never escape this
//! crate.
//!
//! ALPN lives on [`Rustls`] rather than [`Tls`] because `native-tls` does
//! not expose an ALPN option. Protocol crates (`io-imap`, `io-smtp`, ...)
//! ship `default_alpn()` helpers so config layers can populate
//! `rustls.alpn` before calling `connect_tls`.
//!
//! [`Stream::connect_tls`]: crate::stream::Stream::connect_tls
//! [`Stream::upgrade_tls`]: crate::stream::Stream::upgrade_tls

use std::path::PathBuf;

/// TLS settings shared by both backends.
#[derive(Clone, Debug, Default)]
pub struct Tls {
    /// TLS backend selector. `None` falls back to the first enabled feature
    /// in this order: `rustls-ring`, `rustls-aws`, `native-tls`.
    pub provider: Option<TlsProvider>,
    /// Rustls-specific options. Ignored when the resolved provider is
    /// [`TlsProvider::NativeTls`].
    pub rustls: Rustls,
    /// Certificate to trust in the server, beside the platform store.
    pub server: Option<TlsServer>,
    /// Certificate presented when the server asks for one (mutual TLS).
    pub client: Option<TlsClient>,
}

/// What the client trusts in the server, beyond the platform store.
#[derive(Clone, Debug)]
pub struct TlsServer {
    /// Path to the PEM certificate.
    ///
    /// Under rustls it is pinned to the server's leaf, else used as an
    /// extra trust anchor; under native-tls, a root certificate.
    pub cert: PathBuf,
}

/// The certificate the client presents, with its private key.
#[derive(Clone, Debug)]
pub struct TlsClient {
    /// Path to the PEM certificate, optionally followed by intermediates.
    pub cert: PathBuf,
    /// Path to the PEM private key.
    ///
    /// PKCS#8 under native-tls, rustls also reads PKCS#1 and SEC1.
    pub key: PathBuf,
}

/// TLS backend selector.
#[derive(Clone, Debug)]
pub enum TlsProvider {
    /// The rustls backend.
    Rustls,
    /// The platform-backed native-tls backend.
    NativeTls,
}

/// Rustls-specific TLS options.
#[derive(Clone, Debug, Default)]
pub struct Rustls {
    /// Crypto provider. `None` falls back to `ring` if enabled, otherwise
    /// `aws-lc-rs`.
    pub crypto: Option<RustlsCrypto>,
    /// ALPN protocol identifiers offered during the handshake (e.g.
    /// `vec!["imap".into()]`). An empty vec skips ALPN negotiation. Ignored
    /// by `native-tls`.
    pub alpn: Vec<String>,
}

/// Rustls crypto provider selector.
#[derive(Clone, Debug)]
pub enum RustlsCrypto {
    /// The aws-lc-rs crypto provider.
    Aws,
    /// The ring crypto provider.
    Ring,
}
