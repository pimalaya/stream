//! The client certificate over a real handshake, against an in-process
//! rustls server that requires one, the way a mutual-TLS IMAP server
//! does.
//!
//! Every certificate is generated per run: a throwaway CA, a server
//! leaf for `localhost` and a client leaf, both signed by it. The CA is
//! handed to the client as its extra trust anchor, which is also how a
//! private deployment is reached in practice.
#![cfg(feature = "rustls-ring")]

use std::{
    env, fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::Arc,
    thread,
};

use pimalaya_stream::{
    proxy::Proxy,
    stream::{Stream, TlsConnectOptions},
    tls::{Identity, Tls, TlsProvider},
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};

/// PEM files for one run, written under a directory of their own.
struct Pki {
    ca: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
    server_cert: String,
    server_key: String,
}

fn pki(name: &str) -> Pki {
    let dir = env::temp_dir().join(format!("pimalaya-stream-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&server_key, &issuer)
        .unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

    let pki = Pki {
        ca: dir.join("ca.pem"),
        client_cert: dir.join("client.pem"),
        client_key: dir.join("client.key.pem"),
        server_cert: server_cert.pem(),
        server_key: server_key.serialize_pem(),
    };
    fs::write(&pki.ca, ca_cert.pem()).unwrap();
    fs::write(&pki.client_cert, client_cert.pem()).unwrap();
    fs::write(&pki.client_key, client_key.serialize_pem()).unwrap();
    pki
}

/// Serves one connection that must present a client certificate the CA
/// signed, answering `ok` once the handshake completes.
fn serve(pki: &Pki) -> (u16, thread::JoinHandle<Result<(), String>>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&pki.ca).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let chain = CertificateDer::pem_slice_iter(pki.server_cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(pki.server_key.as_bytes()).unwrap();
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().map_err(|e| e.to_string())?;
        let conn = ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;
        let mut tls = StreamOwned::new(conn, tcp);
        tls.write_all(b"ok\n").map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())
    });

    (port, handle)
}

fn tls(pki: &Pki, identity: bool) -> TlsConnectOptions {
    TlsConnectOptions {
        tls: Tls {
            provider: Some(TlsProvider::Rustls),
            cert: Some(pki.ca.clone()),
            identity: identity.then(|| Identity {
                cert: pki.client_cert.clone(),
                key: pki.client_key.clone(),
            }),
            ..Default::default()
        },
        proxy: Proxy::None,
        ..Default::default()
    }
}

#[test]
fn presents_the_client_certificate() {
    let pki = pki("identity");
    let (port, server) = serve(&pki);

    let mut stream = Stream::connect_tls("localhost", port, tls(&pki, true)).unwrap();
    let mut buf = [0u8; 3];
    stream.read_exact(&mut buf).unwrap();

    assert_eq!(&buf, b"ok\n");
    server.join().unwrap().unwrap();
}

#[test]
fn without_one_the_server_refuses() {
    let pki = pki("no-identity");
    let (port, server) = serve(&pki);

    // NOTE: under TLS 1.3 the client finishes first, so the refusal
    // arrives as an alert on the first read rather than at connect
    let refused = Stream::connect_tls("localhost", port, tls(&pki, false))
        .and_then(|mut stream| Ok(stream.read(&mut [0u8; 3])?));

    assert!(refused.is_err(), "expected a refusal, got {refused:?}");
    assert!(server.join().unwrap().is_err());
}
