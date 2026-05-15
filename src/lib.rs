#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod sasl;
#[cfg(feature = "std")]
pub mod std;
