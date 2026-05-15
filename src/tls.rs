//! # TLS configuration
//!
//! User-facing TLS knobs. Consumers construct a [`Tls`] and pass it
//! to a runtime-specific connector (e.g. [`std::stream::Stream`]'s
//! `connect_tls` / `upgrade_tls`); the actual TLS backend types
//! (`rustls`, `native-tls`) never escape this crate.
//!
//! [`std::stream::Stream`]: crate::std::stream::Stream

use std::path::PathBuf;

/// TLS settings shared by both backends.
#[derive(Clone, Debug, Default)]
pub struct Tls {
    /// TLS backend selector. `None` falls back to the first enabled
    /// feature in this order: `rustls-ring`, `rustls-aws`,
    /// `native-tls`.
    pub provider: Option<TlsProvider>,
    /// Rustls-specific knobs. Ignored when the resolved provider is
    /// [`TlsProvider::NativeTls`].
    pub rustls: Rustls,
    /// Optional extra trust anchor, as a path to a PEM file.
    pub cert: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub enum TlsProvider {
    Rustls,
    NativeTls,
}

#[derive(Clone, Debug, Default)]
pub struct Rustls {
    /// Crypto provider. `None` falls back to `ring` if enabled,
    /// otherwise `aws-lc-rs`.
    pub crypto: Option<RustlsCrypto>,
    /// ALPN protocol identifiers offered during the handshake (e.g.
    /// `vec!["imap".into()]`, `vec!["http/1.1".into()]`). `None` or
    /// empty skips ALPN negotiation.
    pub alpn: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum RustlsCrypto {
    Aws,
    Ring,
}
