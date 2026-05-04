use std::{net::TcpStream, sync::Arc};

use anyhow::{bail, Result};
use log::info;
#[cfg(feature = "native-tls")]
use native_tls::TlsConnector;
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls::{ClientConnection, StreamOwned};
use url::Url;

use crate::{
    std::stream::Stream,
    tls::{Tls, TlsProvider},
};

#[derive(Debug)]
pub struct HttpSession {
    pub stream: Stream,
}

impl HttpSession {
    pub fn new(url: &Url, tls: Tls) -> Result<Self> {
        info!("connecting to HTTP server using {url}");

        let host = url.host_str().unwrap_or("127.0.0.1");

        let stream = match url.scheme() {
            scheme if scheme.eq_ignore_ascii_case("http") => {
                let port = url.port().unwrap_or(80);
                let stream = TcpStream::connect((host, port))?;
                Stream::Tcp(stream)
            }
            scheme if scheme.eq_ignore_ascii_case("https") => {
                let port = url.port().unwrap_or(443);
                let stream = TcpStream::connect((host, port))?;
                match tls.provider()? {
                    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
                    TlsProvider::Rustls => {
                        let config = tls.build_rustls_client_config()?;
                        let server_name = host.to_string().try_into()?;
                        let conn = ClientConnection::new(Arc::new(config), server_name)?;
                        Stream::Rustls(StreamOwned::new(conn, stream))
                    }
                    #[cfg(feature = "native-tls")]
                    TlsProvider::NativeTls => {
                        let mut builder = TlsConnector::builder();

                        if let Some(pem_path) = &tls.cert {
                            log::debug!("using TLS cert at {}", pem_path.display());
                            let pem = std::fs::read(pem_path)?;
                            let cert = native_tls::Certificate::from_pem(&pem)?;
                            builder.add_root_certificate(cert);
                        }

                        let connector = builder.build()?;
                        Stream::NativeTls(connector.connect(host, stream)?)
                    }
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                }
            }
            scheme => {
                bail!("Unknown scheme {scheme}, expected imap, imaps or unix");
            }
        };

        Ok(Self { stream })
    }
}
