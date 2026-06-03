//! User-facing TLS configuration.
//!
//! Consumers construct a [`Tls`] and pass it to a runtime-specific connector
//! (e.g. [`StreamStd::connect_tls`] / [`StreamStd::upgrade_tls`]); the
//! underlying TLS backend types (`rustls`, `native-tls`) never escape this
//! crate.
//!
//! ALPN lives on [`Rustls`] rather than [`Tls`] because `native-tls` does
//! not expose an ALPN option. Protocol crates (`io-imap`, `io-smtp`, ...)
//! ship `default_alpn()` helpers so config layers can populate
//! `rustls.alpn` before calling `connect_tls`.
//!
//! [`StreamStd::connect_tls`]: crate::std::stream::StreamStd::connect_tls
//! [`StreamStd::upgrade_tls`]: crate::std::stream::StreamStd::upgrade_tls

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

    /// Optional extra trust anchor, as a path to a PEM file.
    pub cert: Option<PathBuf>,
}

/// TLS backend selector.
#[derive(Clone, Debug)]
pub enum TlsProvider {
    Rustls,
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
    Aws,
    Ring,
}
