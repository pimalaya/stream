//! # Stream pool
//!
//! Lazily-opened, URL-keyed cache of [`Stream`] streams for
//! sans-I/O coroutine runtimes that talk to multiple endpoints in a
//! single discovery cycle (PACC, autoconfig, …).
//!
//! On a [`get`] miss, the pool dispatches to a factory closure
//! registered for the URL scheme. A default `tcp` factory is
//! pre-registered by [`new`]; callers plug additional schemes
//! (typically `http`/`https` via `io-http`) through [`with_factory`].
//!
//! [`new`]: StreamPool::new
//! [`get`]: StreamPool::get
//! [`with_factory`]: StreamPool::with_factory

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::{bail, Error, Result};
use log::trace;
use url::Url;

/// Open marker for everything the pool can store. Auto-implemented
/// for any blocking `Read + Write`.
pub trait Stream: Read + Write {}
impl<T: Read + Write + ?Sized> Stream for T {}

type StreamFactory = Box<dyn FnMut(&Url) -> Result<Box<dyn Stream>>>;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StreamPoolKey {
    scheme: String,
    host: String,
    port: u16,
}

impl TryFrom<&Url> for StreamPoolKey {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self> {
        let scheme = url.scheme().to_ascii_lowercase();

        let Some(host) = url.host_str() else {
            bail!("stream pool URL `{url}` has no host");
        };

        let Some(port) = url.port_or_known_default() else {
            bail!("stream pool URL `{url}` has no known port")
        };

        Ok(StreamPoolKey {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// URL-keyed pool of lazily-opened blocking streams.
pub struct StreamPool {
    streams: HashMap<StreamPoolKey, Box<dyn Stream>>,
    factories: HashMap<&'static str, StreamFactory>,
}

impl Default for StreamPool {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamPool {
    /// Builds a pool with the default `tcp` factory pre-registered.
    /// Callers plug additional schemes (e.g. `http`/`https` through
    /// `io-http`) via [`with_factory`].
    ///
    /// [`with_factory`]: StreamPool::with_factory
    pub fn new() -> Self {
        let pool = Self {
            streams: HashMap::new(),
            factories: HashMap::new(),
        };

        pool.with_factory("tcp", |url: &Url| -> Result<TcpStream> {
            let Some(host) = url.host_str() else {
                bail!("tcp URL `{url}` has no host");
            };

            let Some(port) = url.port_or_known_default() else {
                bail!("tcp URL `{url}` has no port");
            };

            Ok(TcpStream::connect((host, port))?)
        })
    }

    /// Registers (or replaces) the factory for `scheme`. Pass a
    /// lowercase literal (`"https"`, `"tcp"`, …) — URL lookups are
    /// lowercased before matching.
    pub fn with_factory<F, S>(mut self, scheme: &'static str, mut factory: F) -> Self
    where
        F: FnMut(&Url) -> Result<S> + 'static,
        S: Stream + 'static,
    {
        let boxed: StreamFactory =
            Box::new(move |url| factory(url).map(|s| Box::new(s) as Box<dyn Stream>));
        self.factories.insert(scheme, boxed);
        self
    }

    /// Pre-feeds a stream for one specific URL. Bypasses the
    /// scheme factory for that URL.
    pub fn insert(&mut self, url: &Url, stream: impl Stream + 'static) {
        if let Ok(key) = url.try_into() {
            self.streams.insert(key, Box::new(stream));
        }
    }

    /// Returns a mutable reference to the stream open on `url`,
    /// opening one via the factory registered for `url.scheme()`
    /// if the cache misses.
    pub fn get(&mut self, url: &Url) -> Result<&mut dyn Stream> {
        let key = url.try_into()?;

        if !self.streams.contains_key(&key) {
            trace!("opening pool stream for {url}");

            let stream = {
                let Some(factory) = self.factories.get_mut(key.scheme.as_str()) else {
                    bail!("no stream factory registered for scheme `{}`", key.scheme)
                };

                factory(url)?
            };

            self.streams.insert(key.clone(), stream);
        }

        Ok(self.streams.get_mut(&key).unwrap().as_mut())
    }
}
