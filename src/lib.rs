//! Stream, TLS and SASL utils shared by the Pimalaya `io-*` protocol crates.
//!
//! Published for internal Pimalaya usage; API may change without notice.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod sasl;
#[cfg(feature = "std")]
pub mod std;
pub mod tls;
