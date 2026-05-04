#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream},
    sync::Arc,
};

use anyhow::{bail, Result};
use io_smtp::{
    login::{SmtpLogin, SmtpLoginResult},
    rfc3207::starttls::{SmtpStartTls, SmtpStartTlsResult},
    rfc4616::plain::{SmtpPlain, SmtpPlainResult},
    rfc5321::{
        ehlo::{SmtpEhlo, SmtpEhloResult},
        greeting::{GetSmtpGreeting, GetSmtpGreetingResult},
        types::ehlo_domain::EhloDomain,
    },
};
use log::info;
#[cfg(feature = "native-tls")]
use native_tls::TlsConnector;
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls::{ClientConnection, StreamOwned};
#[cfg(windows)]
use uds_windows::UnixStream;
use url::Url;

use crate::{
    sasl::{Sasl, SaslMechanism},
    std::stream::Stream,
    tls::{Tls, TlsProvider},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

#[derive(Debug)]
pub struct SmtpSession {
    pub stream: Stream,
}

fn upgrade_tls(host: &str, tcp: TcpStream, tls: &Tls) -> Result<Stream> {
    match tls.provider()? {
        #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
        TlsProvider::Rustls => {
            let mut config = tls.build_rustls_client_config()?;
            config.alpn_protocols = vec![b"smtp".to_vec()];
            let server_name = host.to_string().try_into()?;
            let conn = ClientConnection::new(Arc::new(config), server_name)?;
            Ok(Stream::Rustls(StreamOwned::new(conn, tcp)))
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
            Ok(Stream::NativeTls(connector.connect(host, tcp)?))
        }
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    }
}

fn drive_greeting<S: Read + Write>(stream: &mut S) -> Result<()> {
    let mut buf = [0u8; READ_BUFFER_SIZE];
    let mut coroutine = GetSmtpGreeting::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Ok { .. } => return Ok(()),
            GetSmtpGreetingResult::WantsRead => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            GetSmtpGreetingResult::Err(err) => bail!(err),
        }
    }
}

fn drive_ehlo<S: Read + Write>(stream: &mut S, domain: EhloDomain<'_>) -> Result<()> {
    let mut buf = [0u8; READ_BUFFER_SIZE];
    let mut coroutine = SmtpEhlo::new(domain);
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpEhloResult::Ok { .. } => return Ok(()),
            SmtpEhloResult::WantsRead => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            SmtpEhloResult::WantsWrite(bytes) => {
                stream.write_all(&bytes)?;
                arg = None;
            }
            SmtpEhloResult::Err(err) => bail!(err),
        }
    }
}

fn drive_starttls<S: Read + Write>(stream: &mut S) -> Result<()> {
    let mut buf = [0u8; READ_BUFFER_SIZE];
    let mut coroutine = SmtpStartTls::new();
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            SmtpStartTlsResult::WantsStartTls(_) => return Ok(()),
            SmtpStartTlsResult::WantsRead => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            SmtpStartTlsResult::WantsWrite(bytes) => {
                stream.write_all(&bytes)?;
                arg = None;
            }
            SmtpStartTlsResult::Err(err) => bail!(err),
        }
    }
}

impl SmtpSession {
    pub fn new(url: Url, tls: Tls, starttls: bool, mut sasl: Sasl) -> Result<Self> {
        info!("connecting to SMTP server using {url}");

        let host = url.host_str().unwrap_or("127.0.0.1");
        let domain: EhloDomain<'static> = Ipv4Addr::new(127, 0, 0, 1).into();

        let mut stream = match url.scheme() {
            scheme if scheme.eq_ignore_ascii_case("smtp") => {
                let port = url.port().unwrap_or(25);
                let mut tcp = TcpStream::connect((host, port))?;

                drive_greeting(&mut tcp)?;
                drive_ehlo(&mut tcp, domain.clone())?;

                Stream::Tcp(tcp)
            }
            scheme if scheme.eq_ignore_ascii_case("smtps") => {
                let default_port = if starttls { 587 } else { 465 };
                let port = url.port().unwrap_or(default_port);
                let mut tcp = TcpStream::connect((host, port))?;

                if starttls {
                    drive_greeting(&mut tcp)?;
                    drive_ehlo(&mut tcp, domain.clone())?;
                    drive_starttls(&mut tcp)?;
                }

                let mut stream = upgrade_tls(host, tcp, &tls)?;

                if !starttls {
                    drive_greeting(&mut stream)?;
                }

                drive_ehlo(&mut stream, domain.clone())?;

                stream
            }
            scheme if scheme.eq_ignore_ascii_case("unix") => {
                let sock_path = url.path();
                let mut unix = UnixStream::connect(sock_path)?;

                drive_greeting(&mut unix)?;
                drive_ehlo(&mut unix, domain.clone())?;

                Stream::Unix(unix)
            }
            scheme => {
                bail!("Unknown scheme {scheme}, expected smtp, smtps or unix");
            }
        };

        let mechanism = sasl
            .mechanism
            .or(Some(SaslMechanism::Plain).filter(|_| sasl.plain.is_some()))
            .or(Some(SaslMechanism::Login).filter(|_| sasl.login.is_some()));

        match mechanism {
            None => bail!("no SASL mechanism configured"),
            Some(SaslMechanism::Login) => {
                let Some(auth) = sasl.login.take() else {
                    bail!("missing SASL LOGIN configuration");
                };

                let mut buf = [0u8; READ_BUFFER_SIZE];
                let mut coroutine = SmtpLogin::new(&auth.username, &auth.password, domain.clone());
                let mut arg: Option<&[u8]> = None;

                loop {
                    match coroutine.resume(arg.take()) {
                        SmtpLoginResult::Ok => break,
                        SmtpLoginResult::WantsRead => {
                            let n = stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        SmtpLoginResult::WantsWrite(bytes) => {
                            stream.write_all(&bytes)?;
                            arg = None;
                        }
                        SmtpLoginResult::Err(err) => bail!(err),
                    }
                }
            }
            Some(SaslMechanism::Plain) => {
                let Some(auth) = sasl.plain.take() else {
                    bail!("missing SASL PLAIN configuration");
                };

                let mut buf = [0u8; READ_BUFFER_SIZE];
                let mut coroutine = SmtpPlain::new(&auth.authcid, &auth.passwd, domain.clone());
                let mut arg: Option<&[u8]> = None;

                loop {
                    match coroutine.resume(arg.take()) {
                        SmtpPlainResult::Ok => break,
                        SmtpPlainResult::WantsRead => {
                            let n = stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        SmtpPlainResult::WantsWrite(bytes) => {
                            stream.write_all(&bytes)?;
                            arg = None;
                        }
                        SmtpPlainResult::Err(err) => bail!(err),
                    }
                }
            }
            Some(SaslMechanism::Anonymous) => {
                unimplemented!("ANONYMOUS SASL mechanism not yet implemented")
            }
        }

        Ok(Self { stream })
    }
}
