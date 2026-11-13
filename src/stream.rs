//! Blocking std transport handle.
//!
//! [`Stream`] is a single `Read + Write` type wrapping a TCP socket, a
//! Unix-domain socket or a TLS session (`rustls` or `native-tls`). TLS
//! options (provider, crypto, ALPN, a pinned certificate, a client
//! certificate) come from [`Tls`].
//!
//! A stream is opened by one of the `connect_*` methods, each taking the
//! options its transport has and nothing more: a proxy where there is
//! one to route through, TLS settings where there is a session to
//! secure, and the [`Retry`] strategy everywhere.
//!
//! That strategy is what reads and writes do when a socket reports it is
//! not ready yet, and connecting arms the socket read deadline it
//! implies, which is what makes it enforceable. The loop honoring it
//! lives in [`crate::retry`], next to the strategy itself.
//!
//! [`Tls`]: crate::tls::Tls

#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    path::Path,
    time::Duration,
};

use anyhow::{Result, bail};
use log::{debug, trace};
#[cfg(windows)]
use uds_windows::UnixStream;

use crate::{proxy::Proxy, retry::Retry, tls::Tls};

#[derive(Debug)]
enum StreamKind {
    Tcp(TcpStream),
    Unix(UnixStream),
    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
    Rustls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
    #[cfg(feature = "native-tls")]
    NativeTls(native_tls::TlsStream<TcpStream>),
}

/// The raw I/O, one attempt per call, under whichever variant is open.
impl StreamKind {
    fn read_once(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            StreamKind::Tcp(s) => s.read(buf),
            StreamKind::Unix(s) => s.read(buf),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.read(buf),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.read(buf),
        }
    }

    fn write_once(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            StreamKind::Tcp(s) => s.write(buf),
            StreamKind::Unix(s) => s.write(buf),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.write(buf),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.write(buf),
        }
    }

    fn flush_once(&mut self) -> io::Result<()> {
        match self {
            StreamKind::Tcp(s) => s.flush(),
            StreamKind::Unix(s) => s.flush(),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.flush(),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.flush(),
        }
    }
}

/// Blocking transport handle: TCP, Unix-domain or TLS, behind one
/// `Read + Write`.
#[derive(Debug)]
pub struct Stream {
    kind: StreamKind,
    host: String,
    /// What the stream does when a read or a write reports it is not
    /// ready, taken from the options it was opened with.
    ///
    /// Assigning [`Retry::Never`] is how a caller takes the
    /// not-ready failures back mid-connection, which is what a watcher
    /// entering IDLE does. Assigning a different [`Retry::Until`]
    /// changes the budget alone: the socket read deadline was armed at
    /// connect time, so a caller wanting a matching one calls
    /// [`set_read_timeout`](Self::set_read_timeout) beside it.
    pub retry: Retry,
}

impl Stream {
    /// Wraps `kind` in the handle and arms the socket read deadline
    /// `retry` implies, the one way a stream comes into existence.
    ///
    /// The arming is why this is not a struct literal at each connect: a
    /// budget cannot be spent against a socket that never returns, so
    /// [`Retry::Until`] is only enforceable with a deadline behind
    /// it, and a connect that forgot one would promise a budget it could
    /// not keep. [`Retry::Never`] arms nothing, a caller wanting
    /// the not-ready failures being one that arms its own.
    fn new(kind: StreamKind, host: String, retry: Retry) -> Result<Self> {
        let stream = Self { kind, host, retry };

        if let Retry::Until(timeout) = retry {
            stream.set_read_timeout(Some(timeout))?;
        }

        Ok(stream)
    }

    /// Opens a Unix-domain socket at `path`.
    pub fn connect_unix(path: impl AsRef<Path>, opts: UnixConnectOptions) -> Result<Self> {
        debug!("connect unix stream");
        trace!("path: {}", path.as_ref().display());

        let kind = StreamKind::Unix(UnixStream::connect(path)?);
        let host = String::from("127.0.0.1");

        debug!("unix stream connected");
        Self::new(kind, host, opts.retry)
    }

    /// Opens a plain TCP connection to `host:port`.
    pub fn connect_tcp(host: impl ToString, port: u16, opts: TcpConnectOptions) -> Result<Self> {
        let host = host.to_string();

        debug!("connect tcp stream");
        trace!("host: {host}");
        trace!("port: {port}");

        let tcp = opts.proxy.connect(&host, port)?;

        debug!("tcp stream connected");
        Self::new(StreamKind::Tcp(tcp), host, opts.retry)
    }

    /// Opens a TCP connection and runs the TLS handshake (implicit TLS).
    pub fn connect_tls(host: impl ToString, port: u16, opts: TlsConnectOptions) -> Result<Self> {
        let host = host.to_string();

        debug!("connect tls stream");
        trace!("host: {host}");
        trace!("port: {port}");

        let tcp = opts.proxy.connect(&host, port)?;
        let kind = Self::_upgrade_tls(&host, tcp, &opts.tls)?;

        Self::new(kind, host, opts.retry)
    }

    /// Wraps a plain TCP stream in a TLS session (STARTTLS upgrade).
    ///
    /// Fails on Unix-domain or already-TLS variants.
    pub fn upgrade_tls(self, tls: &Tls) -> Result<Self> {
        match self.kind {
            StreamKind::Tcp(tcp) => {
                debug!("upgrade tcp stream to tls");
                trace!("host: {}", self.host);

                let kind = Self::_upgrade_tls(&self.host, tcp, tls)?;

                Self::new(kind, self.host, self.retry)
            }
            StreamKind::Unix(_) => bail!("cannot upgrade Unix-domain stream to TLS"),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(_) => bail!("stream is already wrapped in rustls"),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(_) => bail!("stream is already wrapped in native-tls"),
        }
    }

    #[cfg(not(feature = "rustls-aws"))]
    #[cfg(not(feature = "rustls-ring"))]
    #[cfg(not(feature = "native-tls"))]
    fn _upgrade_tls(_: &str, _: TcpStream, _: &Tls) -> Result<StreamKind> {
        bail!("missing cargo feature: `rustls-aws`, `rustls-ring` or `native-tls`")
    }

    #[cfg(any(
        feature = "rustls-aws",
        feature = "rustls-ring",
        feature = "native-tls"
    ))]
    fn _upgrade_tls(host: &str, tcp: TcpStream, tls: &Tls) -> Result<StreamKind> {
        use crate::tls::TlsProvider;

        let provider = match &tls.provider {
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Some(TlsProvider::Rustls) => TlsProvider::Rustls,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            Some(TlsProvider::Rustls) => {
                bail!("missing cargo feature: `rustls-aws` or `rustls-ring`")
            }
            #[cfg(feature = "native-tls")]
            Some(TlsProvider::NativeTls) => TlsProvider::NativeTls,
            #[cfg(not(feature = "native-tls"))]
            Some(TlsProvider::NativeTls) => bail!("missing cargo feature: `native-tls`"),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            None => TlsProvider::Rustls,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            #[cfg(feature = "native-tls")]
            None => TlsProvider::NativeTls,
        };

        match provider {
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            TlsProvider::Rustls => {
                use std::{fs, sync::Arc};

                use rustls::{
                    ClientConfig, ClientConnection, StreamOwned,
                    crypto::{self, CryptoProvider},
                    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
                };
                use rustls_platform_verifier::{BuilderVerifierExt, Verifier};

                use crate::tls::RustlsCrypto;

                let crypto_provider = match &tls.rustls.crypto {
                    #[cfg(feature = "rustls-aws")]
                    Some(RustlsCrypto::Aws) => crypto::aws_lc_rs::default_provider(),
                    #[cfg(not(feature = "rustls-aws"))]
                    Some(RustlsCrypto::Aws) => bail!("missing cargo feature: `rustls-aws`"),
                    #[cfg(feature = "rustls-ring")]
                    Some(RustlsCrypto::Ring) => crypto::ring::default_provider(),
                    #[cfg(not(feature = "rustls-ring"))]
                    Some(RustlsCrypto::Ring) => bail!("missing cargo feature: `rustls-ring`"),
                    #[cfg(feature = "rustls-ring")]
                    None => crypto::ring::default_provider(),
                    #[cfg(not(feature = "rustls-ring"))]
                    #[cfg(feature = "rustls-aws")]
                    None => crypto::aws_lc_rs::default_provider(),
                    #[cfg(not(feature = "rustls-ring"))]
                    #[cfg(not(feature = "rustls-aws"))]
                    None => bail!("missing cargo feature: `rustls-aws` or `rustls-ring`"),
                };

                let crypto_provider = match crypto_provider.install_default() {
                    Ok(()) => CryptoProvider::get_default().unwrap().clone(),
                    Err(crypto_provider) => crypto_provider,
                };

                let builder = if let Some(server) = &tls.server {
                    trace!("using TLS server cert at {}", server.cert.display());
                    let pem = fs::read(&server.cert)?;

                    let Some(cert) = CertificateDer::pem_slice_iter(&pem).next() else {
                        bail!("empty TLS server cert at {}", server.cert.display())
                    };
                    let cert = cert?;

                    // NOTE: pin the leaf; a self-signed CA-marked leaf
                    // (Proton Bridge) fails a normal chain build with
                    // CaUsedAsEndEntity.
                    let fallback = Verifier::new_with_extra_roots(
                        vec![cert.clone()],
                        crypto_provider.clone(),
                    )?;

                    let verifier = pinned::PinnedServerCertVerifier::new(
                        cert,
                        Arc::new(fallback),
                        crypto_provider,
                    );

                    ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(verifier))
                } else {
                    trace!("using platform TLS certs");
                    ClientConfig::builder().with_platform_verifier()?
                };

                let mut config = if let Some(client) = &tls.client {
                    trace!(
                        "using TLS client cert at {} with key at {}",
                        client.cert.display(),
                        client.key.display()
                    );

                    let pem = fs::read(&client.cert)?;
                    let chain =
                        CertificateDer::pem_slice_iter(&pem).collect::<Result<Vec<_>, _>>()?;
                    if chain.is_empty() {
                        bail!("empty TLS client cert at {}", client.cert.display())
                    }

                    let pem = fs::read(&client.key)?;
                    let key = PrivateKeyDer::from_pem_slice(&pem)?;

                    builder.with_client_auth_cert(chain, key)?
                } else {
                    builder.with_no_client_auth()
                };

                config.alpn_protocols = tls
                    .rustls
                    .alpn
                    .iter()
                    .map(|p| p.as_bytes().to_vec())
                    .collect();

                let server_name = host.to_string().try_into()?;
                let conn = ClientConnection::new(Arc::new(config), server_name)?;

                debug!("tls stream connected");
                Ok(StreamKind::Rustls(StreamOwned::new(conn, tcp)))
            }

            #[cfg(feature = "native-tls")]
            TlsProvider::NativeTls => {
                use std::fs;

                use native_tls::{Certificate, Identity, TlsConnector};

                let mut builder = TlsConnector::builder();

                if let Some(server) = &tls.server {
                    trace!("using TLS server cert at {}", server.cert.display());
                    let pem = fs::read(&server.cert)?;
                    let cert = Certificate::from_pem(&pem)?;
                    builder.add_root_certificate(cert);
                } else {
                    trace!("using platform TLS certs");
                }

                if let Some(client) = &tls.client {
                    trace!(
                        "using TLS client cert at {} with key at {}",
                        client.cert.display(),
                        client.key.display()
                    );
                    let cert = fs::read(&client.cert)?;
                    let key = fs::read(&client.key)?;
                    builder.identity(Identity::from_pkcs8(&cert, &key)?);
                }

                let connector = builder.build()?;
                let session = connector.connect(host, tcp)?;

                debug!("tls stream connected");
                Ok(StreamKind::NativeTls(session))
            }

            // NOTE: reachable only on a partial feature set, every
            // provider being matched above
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    /// Sets the read timeout on the underlying socket; `None` blocks
    /// forever.
    ///
    /// Under [`Retry::Until`] this is the pace at which a stalled
    /// read wakes up to check the budget, not the deadline the caller
    /// sees: a shorter timeout than the budget only means more wakeups.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match &self.kind {
            StreamKind::Tcp(s) => s.set_read_timeout(timeout),
            StreamKind::Unix(s) => s.set_read_timeout(timeout),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.sock.set_read_timeout(timeout),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.get_ref().set_read_timeout(timeout),
        }
    }

    /// Toggles non-blocking mode on the underlying socket. Under a TLS
    /// variant it applies to the socket beneath the session, so reads and
    /// writes surface `WouldBlock` reliably (unlike a read timeout, which
    /// the TLS layer does not always propagate).
    ///
    /// Non-blocking mode wants [`Retry::Never`] beside it: the two
    /// settings are contradictory, a caller reaching for non-blocking
    /// mode wanting those `WouldBlock` failures that a retry strategy
    /// would spend its whole budget hiding.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match &self.kind {
            StreamKind::Tcp(s) => s.set_nonblocking(nonblocking),
            StreamKind::Unix(s) => s.set_nonblocking(nonblocking),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.sock.set_nonblocking(nonblocking),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.get_ref().set_nonblocking(nonblocking),
        }
    }
}

impl Read for Stream {
    /// Reads under the stream's [`Retry`] strategy: a socket
    /// reporting it is not ready costs an attempt, not the exchange.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.retry(|stream| stream.kind.read_once(buf))
    }
}

impl Write for Stream {
    /// Writes under the stream's [`Retry`] strategy, which is what
    /// makes the `write_all` built on top of it survive a socket that is
    /// momentarily full.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.retry(|stream| stream.kind.write_once(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.retry(|stream| stream.kind.flush_once())
    }
}

/// Options for [`Stream::connect_unix`].
#[derive(Clone, Debug, Default)]
pub struct UnixConnectOptions {
    /// What the stream does when a read or a write reports it is not
    /// ready. Defaults to [`Retry::default`].
    ///
    /// A local socket has neither a proxy nor a TLS session to
    /// configure, which is why this is the whole of it.
    pub retry: Retry,
}

/// Options for [`Stream::connect_tcp`].
#[derive(Clone, Debug, Default)]
pub struct TcpConnectOptions {
    /// How the connection reaches its target. Defaults to
    /// [`Proxy::System`], resolved from the environment at connect time.
    pub proxy: Proxy,
    /// What the stream does when a read or a write reports it is not
    /// ready. Defaults to [`Retry::default`].
    pub retry: Retry,
}

/// Options for [`Stream::connect_tls`].
#[derive(Clone, Debug, Default)]
pub struct TlsConnectOptions {
    /// How the session is secured: provider, crypto, ALPN, an extra
    /// certificate to trust.
    pub tls: Tls,
    /// How the connection reaches its target. Defaults to
    /// [`Proxy::System`], resolved from the environment at connect time.
    pub proxy: Proxy,
    /// What the stream does when a read or a write reports it is not
    /// ready. Defaults to [`Retry::default`].
    pub retry: Retry,
}

/// Certificate pinning for the rustls TLS branch.
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
mod pinned {
    use std::sync::Arc;

    use rustls::{
        DigitallySignedStruct, Error, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };
    use rustls_platform_verifier::Verifier;

    /// A rustls verifier that pins one server certificate.
    ///
    /// The pin is trusted when the server presents it verbatim as its leaf,
    /// the model self-signed servers need (e.g. Proton Bridge): such a
    /// certificate is often a CA, which a normal chain build rejects in the
    /// leaf position (`CaUsedAsEndEntity`).
    ///
    /// A different leaf falls back to the pin as an extra trust anchor;
    /// handshake signatures are always verified through the active crypto
    /// provider.
    #[derive(Debug)]
    pub struct PinnedServerCertVerifier {
        pinned: CertificateDer<'static>,
        fallback: Arc<Verifier>,
        provider: Arc<CryptoProvider>,
    }

    impl PinnedServerCertVerifier {
        /// Builds a pinning verifier for `pinned`.
        ///
        /// Handshake signatures are verified through `provider`; `fallback`
        /// handles a server presenting a different leaf.
        pub fn new(
            pinned: CertificateDer<'static>,
            fallback: Arc<Verifier>,
            provider: Arc<CryptoProvider>,
        ) -> Self {
            Self {
                pinned,
                fallback,
                provider,
            }
        }
    }

    impl ServerCertVerifier for PinnedServerCertVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            if end_entity.as_ref() == self.pinned.as_ref() {
                return Ok(ServerCertVerified::assertion());
            }

            self.fallback.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
