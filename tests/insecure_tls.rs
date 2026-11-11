use inode_cli::protocol::{self, Session};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

/// One-shot TLS gateway with a self-signed certificate that no root store
/// trusts, so only an explicit trust decision can reach HTTP.
async fn gateway() -> (String, String, tokio::task::JoinHandle<()>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pin = format!("{:x}", Sha256::digest(cert.cert.der()));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let accept = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let Ok(mut tls) = accept.accept(tcp).await else {
            return; // Rejected by the client's default verification.
        };
        let mut received = Vec::new();
        let mut byte = [0u8; 1];
        while !received.ends_with(b"\r\n\r\n") {
            match tls.read(&mut byte).await {
                // A client that rejects the certificate may abort instead of
                // sending a TLS close_notify; Windows surfaces that as an error.
                Ok(0) | Err(_) => return,
                Ok(_) => received.push(byte[0]),
            }
        }
        assert!(String::from_utf8_lossy(&received).starts_with("GET /svpn/index.cgi"));
        let body = "<data><gatewayinfo><auth><supportPassword>true</supportPassword></auth><url><login>/login</login><logout>/logout</logout></url></gatewayinfo></data>";
        tls.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let _ = tls.shutdown().await;
    });
    (url, pin, task)
}

#[tokio::test]
async fn default_verification_rejects_a_self_signed_gateway() {
    let (url, _, task) = gateway().await;
    let session = Session::new(
        protocol::gateway(&url).unwrap(),
        None,
        None,
        false,
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(session.discover(None).await.is_err());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn insecure_reaches_the_gateway_without_any_pin() {
    let (url, _, task) = gateway().await;
    let session = Session::new(
        protocol::gateway(&url).unwrap(),
        None,
        None,
        true,
        Duration::from_secs(5),
    )
    .unwrap();
    let info = session.discover(None).await.unwrap();
    assert!(info.captcha.is_none());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn insecure_conflicts_with_explicit_trust() {
    let url = protocol::gateway("https://localhost:8443").unwrap();
    let pin = "00".repeat(32);
    let error = Session::new(url.clone(), None, Some(&pin), true, Duration::from_secs(5))
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("cannot be combined"), "{error}");
    let error = Session::new(
        url,
        Some(b"-----BEGIN CERTIFICATE-----\n"),
        None,
        true,
        Duration::from_secs(5),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("cannot be combined"), "{error}");
}
