//! # Blocking std stream
//!
//! [`Stream`] is the single transport handle used by every Pimalaya
//! `io-*` protocol crate: a plain TCP socket, a Unix-domain socket,
//! a `rustls`-wrapped TLS session, or a `native-tls`-wrapped TLS
//! session — all behind one `Read + Write` enum.
//!
//! Constructors live as inherent methods:
//!
//! - [`connect_tcp`] / [`connect_unix`] — plain transports.
//! - [`connect_tls`] — opens TCP and runs the TLS handshake (implicit
//!   TLS, the `imaps`/`smtps`/`https` style).
//! - [`upgrade_tls`] — consumes a plain [`Stream::Tcp`] and returns a
//!   TLS-wrapped variant (STARTTLS style).
//!
//! ALPN, crypto provider and the extra trust anchor are user-facing
//! knobs on [`Tls`] / [`Rustls`] — stream just reads them. ALPN
//! lookup applies only to rustls; native-tls ignores it.
//!
//! [`connect_tcp`]: Stream::connect_tcp
//! [`connect_unix`]: Stream::connect_unix
//! [`connect_tls`]: Stream::connect_tls
//! [`upgrade_tls`]: Stream::upgrade_tls
//! [`Tls`]: crate::tls::Tls
//! [`Rustls`]: crate::tls::Rustls

#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    path::Path,
    time::Duration,
};

use anyhow::{bail, Result};
use log::trace;
#[cfg(windows)]
use uds_windows::UnixStream;

use crate::tls::{Tls, TlsProvider};

#[derive(Debug)]
enum StreamKind {
    Tcp(TcpStream),
    Unix(UnixStream),
    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
    Rustls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
    #[cfg(feature = "native-tls")]
    NativeTls(native_tls::TlsStream<TcpStream>),
}

#[derive(Debug)]
pub struct Stream {
    inner: StreamKind,
    host: String,
}

impl Stream {
    /// Opens a Unix-domain socket at `path`.
    pub fn connect_unix<P: AsRef<Path>>(path: P) -> io::Result<Stream> {
        trace!("connecting Unix stream to {}", path.as_ref().display());
        let inner = StreamKind::Unix(UnixStream::connect(path)?);
        let host = String::from("127.0.0.1");
        Ok(Self { inner, host })
    }

    /// Opens a plain TCP connection to `host:port`.
    pub fn connect_tcp(host: impl ToString, port: u16) -> io::Result<Stream> {
        let host = host.to_string();
        trace!("connecting TCP stream to {host}:{port}");
        let inner = StreamKind::Tcp(TcpStream::connect((host.as_str(), port))?);
        Ok(Self { inner, host })
    }

    /// Opens a TCP connection to `host:port` and runs the TLS
    /// handshake using `tls`. ALPN, crypto provider and the extra
    /// trust anchor are read from `tls`.
    pub fn connect_tls(host: impl ToString, port: u16, tls: &Tls) -> Result<Stream> {
        let host = host.to_string();
        trace!("connecting TLS stream to {host}:{port}");
        let tcp = TcpStream::connect((host.as_str(), port))?;
        Self::_upgrade_tls(host, tcp, tls)
    }

    /// Consumes a plain [`Stream::Tcp`] and wraps it in a TLS
    /// session — the STARTTLS upgrade path. Fails if `self` is a
    /// Unix-domain socket or already a TLS variant.
    pub fn upgrade_tls(self, tls: &Tls) -> Result<Stream> {
        match self.inner {
            StreamKind::Tcp(tcp) => {
                trace!("upgrading TCP stream to TLS for {}", self.host);
                Self::_upgrade_tls(self.host, tcp, tls)
            }
            StreamKind::Unix(_) => bail!("cannot upgrade Unix-domain stream to TLS"),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(_) => bail!("stream is already wrapped in rustls"),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(_) => bail!("stream is already wrapped in native-tls"),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match &self.inner {
            StreamKind::Tcp(s) => s.set_read_timeout(timeout),
            StreamKind::Unix(s) => s.set_read_timeout(timeout),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.sock.set_read_timeout(timeout),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.get_ref().set_read_timeout(timeout),
        }
    }

    fn _upgrade_tls(host: String, tcp: TcpStream, tls: &Tls) -> Result<Stream> {
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
            #[cfg(not(feature = "rustls-aws",))]
            #[cfg(not(feature = "rustls-ring",))]
            #[cfg(not(feature = "native-tls"))]
            None => bail!("missing cargo feature: `rustls-aws`, `rustls-ring` or `native-tls`"),
        };

        match provider {
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            TlsProvider::Rustls => {
                use std::{fs, sync::Arc};

                use rustls::{
                    crypto::{self, CryptoProvider},
                    pki_types::{pem::PemObject, CertificateDer},
                    ClientConfig, ClientConnection, StreamOwned,
                };
                use rustls_platform_verifier::{ConfigVerifierExt, Verifier};

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

                let mut config = if let Some(pem_path) = &tls.cert {
                    trace!("using TLS cert at {}", pem_path.display());
                    let pem = fs::read(pem_path)?;

                    let Some(cert) = CertificateDer::pem_slice_iter(&pem).next() else {
                        bail!("empty TLS cert at {}", pem_path.display())
                    };

                    let verifier = Verifier::new_with_extra_roots(vec![cert?], crypto_provider)?;

                    ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(verifier))
                        .with_no_client_auth()
                } else {
                    trace!("using platform TLS certs");
                    ClientConfig::with_platform_verifier()?
                };

                config.alpn_protocols = tls
                    .rustls
                    .alpn
                    .iter()
                    .map(|p| p.as_bytes().to_vec())
                    .collect();

                let server_name = host.to_string().try_into()?;
                let conn = ClientConnection::new(Arc::new(config), server_name)?;
                let inner = StreamKind::Rustls(StreamOwned::new(conn, tcp));
                Ok(Stream { inner, host })
            }

            #[cfg(feature = "native-tls")]
            TlsProvider::NativeTls => {
                use std::fs;

                use native_tls::{Certificate, TlsConnector};

                let mut builder = TlsConnector::builder();

                if let Some(pem_path) = &tls.cert {
                    trace!("using TLS cert at {}", pem_path.display());
                    let pem = fs::read(pem_path)?;
                    let cert = Certificate::from_pem(&pem)?;
                    builder.add_root_certificate(cert);
                } else {
                    trace!("using platform TLS certs");
                }

                let connector = builder.build()?;
                let inner = Stream::NativeTls(connector.connect(host, tcp)?);
                Ok(Stream { inner, host })
            }

            // SAFETY: case already handled
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            StreamKind::Tcp(s) => s.read(buf),
            StreamKind::Unix(s) => s.read(buf),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.read(buf),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            StreamKind::Tcp(s) => s.write(buf),
            StreamKind::Unix(s) => s.write(buf),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.write(buf),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            StreamKind::Tcp(s) => s.flush(),
            StreamKind::Unix(s) => s.flush(),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            StreamKind::Rustls(s) => s.flush(),
            #[cfg(feature = "native-tls")]
            StreamKind::NativeTls(s) => s.flush(),
        }
    }
}
