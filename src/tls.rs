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
    /// Optional certificate to trust in the server. `None` relies on
    /// the platform trust store alone.
    pub server: Option<TlsServer>,
    /// Optional certificate the client presents when the server asks for
    /// one (mutual TLS). `None` presents nothing.
    pub client: Option<TlsClient>,
}

/// What the client trusts in the server, beyond the platform store.
#[derive(Clone, Debug)]
pub struct TlsServer {
    /// A certificate as a path to a PEM file.
    ///
    /// Under rustls it is pinned to the server's leaf (e.g. Proton Bridge),
    /// else used as an extra trust anchor; under native-tls, a root
    /// certificate.
    pub cert: PathBuf,
}

/// The client's own certificate and private key, as paths to PEM files.
#[derive(Clone, Debug)]
pub struct TlsClient {
    /// The certificate, optionally followed by the intermediates the
    /// server needs to build the chain.
    pub cert: PathBuf,
    /// The private key. PKCS#8 (`BEGIN PRIVATE KEY`) is the form both
    /// backends read; rustls also reads PKCS#1 and SEC1.
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
