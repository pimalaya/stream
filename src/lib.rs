#![cfg_attr(docsrs, feature(doc_cfg))]

//! # pimalaya-stream
//!
//! Opens and upgrades blocking streams for the Pimalaya io-* protocol
//! crates: TCP connections, TLS connections, Unix-domain sockets,
//! proxy resolution and the plain-to-TLS upgrade STARTTLS flows need.
//! It also carries the TLS configuration vocabulary those crates share.
//!
//! The crate is public. Every io-* protocol client needs a stream
//! handed to it, and this is the one Pimalaya's own clients are built
//! on, so a third party wiring its own client against io-imap,
//! io-smtp, io-http or a sibling is a first-class consumer rather than
//! a tolerated one. Reusing it is the supported path, reimplementing
//! TCP, TLS, proxy resolution and the STARTTLS upgrade is not.
//!
//! ## Stability
//!
//! The crate stays on 0.x. Breaking changes land in minor bumps and
//! never in patch bumps, which is what Cargo already assumes for a 0.x
//! version, so pinning a minor keeps a consumer building. Every break
//! is spelled out in the
//! [CHANGELOG](https://github.com/pimalaya/stream/blob/master/CHANGELOG.md).
//!
//! ## Layout
//!
//! The crate is deliberately std and blocking: it wraps TLS providers
//! and sockets and exposes no I/O-free coroutines, so the no_std
//! conventions of the io-* family do not apply here. There is no async
//! twin planned, which is why the three modules sit flat at the root
//! rather than under a runtime one.
//!
//! [`tls`] holds the provider-agnostic TLS options consumed by connect
//! and upgrade: the provider choice (Rustls with ring or aws crypto,
//! Native TLS), ALPN identifiers, an optional extra trust anchor and an
//! optional client certificate.
//! [`stream`] (`std` feature) is the transport itself, one `Read +
//! Write` handle over TCP, Unix sockets or a TLS session, with the
//! upgrade from plain to TLS. [`proxy`] (same feature) is the selector
//! every connect funnels through (SOCKS5, HTTP CONNECT, or
//! environment-resolved), defaulting to the ambient proxy variables,
//! and [`retry`] (same again) is what a stream does when a socket
//! reports it is not ready yet, which is not the same as broken.
//!
//! SASL is not here. The credential vocabulary and the mechanisms that
//! compute payloads from it live in io-sasl, which is no_std and knows
//! nothing about sockets; a protocol crate reaching for authentication
//! reaches there, and this crate stays what its name says.
//!
//! ## Where to read further
//!
//! Runnable programs for the three shapes a connection takes live in
//! the examples folder: implicit TLS, a STARTTLS upgrade, and a connect
//! through an explicitly configured proxy. What the crate does today,
//! capability by capability, is written down under cairn/spec, with the
//! dated history of how it got there under cairn/log.
//!
//! ## Conventions
//!
//! The conventions every Pimalaya repository shares are described in
//! the org
//! [ARCHITECTURE](https://github.com/pimalaya/.github/blob/master/ARCHITECTURE.md)
//! and
//! [GUIDELINES](https://github.com/pimalaya/.github/blob/master/GUIDELINES.md).
//! Logging follows the library rules: debug marks the lifecycle points
//! (connect, upgrade), trace carries the data.

#[cfg(feature = "std")]
pub mod proxy;
#[cfg(feature = "std")]
pub mod retry;
#[cfg(feature = "std")]
pub mod stream;
pub mod tls;
