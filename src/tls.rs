use std::{fs, net::TcpStream, path::PathBuf, sync::Arc};

use anyhow::{bail, Result};
use log::debug;
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls::{
    crypto::{self, CryptoProvider},
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig, ClientConnection, StreamOwned,
};
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls_platform_verifier::{ConfigVerifierExt, Verifier};

#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
use crate::std::stream::Stream;

#[derive(Clone, Debug, Default)]
pub struct Tls {
    pub provider: Option<TlsProvider>,
    pub rustls: Rustls,
    pub cert: Option<PathBuf>,
}

impl Tls {
    pub fn provider(&self) -> Result<TlsProvider> {
        let provider = match &self.provider {
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Some(TlsProvider::Rustls) => TlsProvider::Rustls,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            Some(TlsProvider::Rustls) => {
                bail!("Missing cargo feature: `rustls-aws` or `rustls-ring`")
            }
            #[cfg(feature = "native-tls")]
            Some(TlsProvider::NativeTls) => TlsProvider::NativeTls,
            #[cfg(not(feature = "native-tls"))]
            Some(TlsProvider::NativeTls) => {
                bail!("Missing cargo feature: `native-tls`")
            }
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            None => TlsProvider::Rustls,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            #[cfg(feature = "native-tls")]
            None => TlsProvider::NativeTls,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            #[cfg(not(feature = "native-tls"))]
            None => {
                bail!("Missing cargo feature: `rustls-aws`, `rustls-ring` or `native-tls`")
            }
        };

        debug!("using TLS provider: {provider:?}");
        Ok(provider)
    }

    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
    pub fn build_rustls_client_config(&self) -> Result<ClientConfig> {
        let crypto_provider = match &self.rustls.crypto {
            #[cfg(feature = "rustls-aws")]
            Some(RustlsCrypto::Aws) => RustlsCrypto::Aws,
            #[cfg(not(feature = "rustls-aws"))]
            Some(RustlsCrypto::Aws) => {
                bail!("Missing cargo feature: `rustls-aws`")
            }
            #[cfg(feature = "rustls-ring")]
            Some(RustlsCrypto::Ring) => RustlsCrypto::Ring,
            #[cfg(not(feature = "rustls-ring"))]
            Some(RustlsCrypto::Ring) => {
                bail!("Missing cargo feature: `rustls-ring`");
            }
            #[cfg(feature = "rustls-ring")]
            None => RustlsCrypto::Ring,
            #[cfg(not(feature = "rustls-ring"))]
            #[cfg(feature = "rustls-aws")]
            None => RustlsCrypto::Aws,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            None => {
                bail!("Missing cargo feature: `rustls-aws` or `rustls-ring`");
            }
        };

        debug!("using rustls crypto provider: {crypto_provider:?}");

        let crypto_provider = match crypto_provider {
            #[cfg(feature = "rustls-aws")]
            RustlsCrypto::Aws => crypto::aws_lc_rs::default_provider(),
            #[cfg(feature = "rustls-ring")]
            RustlsCrypto::Ring => crypto::ring::default_provider(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        };

        let crypto_provider = match crypto_provider.install_default() {
            Ok(()) => CryptoProvider::get_default().unwrap().clone(),
            Err(crypto_provider) => crypto_provider,
        };

        let config = if let Some(pem_path) = &self.cert {
            debug!("using TLS cert at {}", pem_path.display());
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
            debug!("using OS TLS certs");
            ClientConfig::with_platform_verifier()?
        };

        Ok(config)
    }
}

#[derive(Clone, Debug)]
pub enum TlsProvider {
    Rustls,
    NativeTls,
}

#[derive(Clone, Debug, Default)]
pub struct Rustls {
    pub crypto: Option<RustlsCrypto>,
}

#[derive(Clone, Debug)]
pub enum RustlsCrypto {
    Aws,
    Ring,
}

/// Wraps a connected [`TcpStream`] in a TLS session, picking the
/// provider declared by `tls`. `host` is used as SNI / hostname
/// verification target, and `alpn` is the ALPN protocol list (e.g.
/// `&[b"imap"]`, `&[b"smtp"]`, or `&[b"http/1.1"]`); pass an empty
/// slice to skip ALPN negotiation.
#[cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]
pub fn upgrade_tls(host: &str, tcp: TcpStream, tls: &Tls, alpn: &[&[u8]]) -> Result<Stream> {
    match tls.provider()? {
        #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
        TlsProvider::Rustls => {
            let mut config = tls.build_rustls_client_config()?;
            config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            let server_name = host.to_string().try_into()?;
            let conn = ClientConnection::new(Arc::new(config), server_name)?;
            Ok(Stream::Rustls(StreamOwned::new(conn, tcp)))
        }
        #[cfg(feature = "native-tls")]
        TlsProvider::NativeTls => {
            let mut builder = native_tls::TlsConnector::builder();

            if let Some(pem_path) = &tls.cert {
                let pem = fs::read(pem_path)?;
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
