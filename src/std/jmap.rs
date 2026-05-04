use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use anyhow::{bail, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use io_jmap::rfc8620::{
    session::JmapSession as IoJmapSession,
    session_get::{JmapSessionGet, JmapSessionGetResult},
};
use log::info;
#[cfg(feature = "native-tls")]
use native_tls::TlsConnector;
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls::{ClientConnection, StreamOwned};
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::{
    std::stream::Stream,
    tls::{Tls, TlsProvider},
};

const READ_BUFFER_SIZE: usize = 16 * 1024;

/// Authentication for a JMAP session.
// https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml#authschemes
#[derive(Clone, Debug)]
pub enum JmapAuth {
    Header(SecretString),
    /// Bearer token (OAuth 2.0).
    Bearer(SecretString),
    /// HTTP Basic authentication.
    Basic {
        username: String,
        password: SecretString,
    },
}

impl From<JmapAuth> for SecretString {
    fn from(auth: JmapAuth) -> SecretString {
        match auth {
            JmapAuth::Header(auth) => auth,
            JmapAuth::Bearer(token) => {
                let token = token.expose_secret();
                format!("Bearer {token}").into()
            }
            JmapAuth::Basic { username, password } => {
                let creds = format!("{}:{}", username, password.expose_secret());
                let creds = BASE64_STANDARD.encode(creds.into_bytes());
                format!("Basic {creds}").into()
            }
        }
    }
}

/// A live JMAP session over a TLS connection.
///
/// Created by [`JmapSession::new`]. Holds the discovered session
/// and the open TLS stream to the JMAP server.
///
/// JMAP always requires TLS — plain HTTP connections are not
/// supported by this session type.
#[derive(Debug)]
pub struct JmapSession {
    pub session: IoJmapSession,
    pub stream: Stream,
    pub http_auth: SecretString,
}

fn new_tls_stream(host: &str, tcp: TcpStream, tls: &Tls) -> Result<Stream> {
    let stream = match tls.provider()? {
        #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
        TlsProvider::Rustls => {
            let config = tls.build_rustls_client_config()?;
            let server_name = host.to_string().try_into()?;
            let conn = ClientConnection::new(Arc::new(config), server_name)?;
            Stream::Rustls(StreamOwned::new(conn, tcp))
        }
        #[cfg(feature = "native-tls")]
        TlsProvider::NativeTls => {
            let mut builder = TlsConnector::builder();

            if let Some(pem_path) = &tls.cert {
                let pem = std::fs::read(pem_path)?;
                let cert = native_tls::Certificate::from_pem(&pem)?;
                builder.add_root_certificate(cert);
            }

            let connector = builder.build()?;
            Stream::NativeTls(connector.connect(host, tcp)?)
        }
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    };

    Ok(stream)
}

fn use_tls(scheme: &str) -> bool {
    scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("jmaps")
}

fn default_port(scheme: &str) -> u16 {
    if use_tls(scheme) {
        443
    } else {
        80
    }
}

fn connect(url: &Url, tls: &Tls) -> Result<Stream> {
    let host = url.host_str().unwrap_or("localhost");
    let port = url.port().unwrap_or_else(|| default_port(url.scheme()));
    let tcp = TcpStream::connect((host, port))?;

    if use_tls(url.scheme()) {
        new_tls_stream(host, tcp, tls)
    } else {
        Ok(Stream::Tcp(tcp))
    }
}

impl JmapSession {
    /// Returns a new TLS stream to `url` if its authority differs from the
    /// current JMAP API URL, or `None` if the existing stream can be reused.
    pub fn connect_if_different(&self, url: &Url, tls: &Tls) -> Result<Option<Stream>> {
        let api_url = &self.session.api_url;

        let same_host = api_url.host() == url.host();
        let same_port = api_url.port_or_known_default() == url.port_or_known_default();

        if same_host && same_port {
            return Ok(None);
        }

        let host = url.host_str().unwrap_or("localhost");
        let port = url.port_or_known_default().unwrap_or(443);
        let tcp = TcpStream::connect((host, port))?;
        Ok(Some(new_tls_stream(host, tcp, tls)?))
    }

    /// Establishes a JMAP session.
    ///
    /// `server` accepts either a bare authority (`fastmail.com`,
    /// `mail.example.com:8080`) or a full URL (`https://api.fastmail.com/jmap/api/`).
    /// A bare authority triggers `/.well-known/jmap` discovery; a full URL is
    /// used as the direct session endpoint.
    ///
    /// Supported schemes: `https`, `jmaps` (TLS); `http`, `jmap` (plain).
    pub fn new(server: String, tls: Tls, auth: JmapAuth) -> Result<Self> {
        let url = match Url::parse(&server) {
            Ok(url) => url,
            Err(url::ParseError::RelativeUrlWithoutBase) => {
                Url::parse(&format!("https://{server}"))?
            }
            Err(e) => return Err(e.into()),
        };

        info!("connecting to JMAP server {url}");

        match url.scheme() {
            s if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("jmaps") => {}
            s if s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("jmap") => {}
            scheme => bail!("unsupported JMAP scheme `{scheme}`, expected http/https/jmap/jmaps"),
        }

        let mut stream = connect(&url, &tls)?;

        let http_auth: SecretString = auth.into();
        let mut coroutine = JmapSessionGet::new(&http_auth, &url);
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        let session = loop {
            match coroutine.resume(arg.take()) {
                JmapSessionGetResult::Ok { session, .. } => break session,
                JmapSessionGetResult::WantsRead => {
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                JmapSessionGetResult::WantsWrite(bytes) => {
                    stream.write_all(&bytes)?;
                    arg = None;
                }
                JmapSessionGetResult::WantsRedirect { url: new_url, .. } => {
                    stream = connect(&new_url, &tls)?;
                    coroutine = JmapSessionGet::new(&http_auth, &new_url);
                    arg = None;
                }
                JmapSessionGetResult::Err(err) => return Err(err.into()),
            }
        };

        Ok(Self {
            session,
            stream,
            http_auth,
        })
    }
}
