use inode_cli::proxy::{Config, Proxy};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    address
}

fn start() -> Proxy {
    Proxy::start(
        "127.0.0.1:0".parse().unwrap(),
        Config {
            auth: Some(("u".into(), "p".into())),
            timeout: Duration::from_secs(5),
        },
    )
    .unwrap()
}

async fn client(proxy: &Proxy) -> TcpStream {
    TcpStream::connect(proxy.local_addr()).await.unwrap()
}

async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test]
async fn http_requires_basic_credentials() {
    let target = echo().await;
    let proxy = start();

    let mut stream = client(&proxy).await;
    stream
        .write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", target.port()).as_bytes())
        .await
        .unwrap();
    assert!(read_head(&mut stream).await.starts_with("HTTP/1.1 407"));

    let mut stream = client(&proxy).await;
    stream
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nProxy-Authorization: Basic d3Jvbmc=\r\n\r\n",
                target.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(read_head(&mut stream).await.starts_with("HTTP/1.1 407"));

    let mut stream = client(&proxy).await;
    stream
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
                target.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(read_head(&mut stream).await.starts_with("HTTP/1.1 200"));
    stream.write_all(b"ping").await.unwrap();
    let mut payload = [0u8; 4];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"ping");
}

#[tokio::test]
async fn socks5_requires_userpass_negotiation() {
    let target = echo().await;
    let proxy = start();

    // Only no-auth is offered; it must be refused.
    let mut stream = client(&proxy).await;
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 0xff]);

    // Wrong password: the sub-negotiation fails and the tunnel never opens.
    let mut stream = client(&proxy).await;
    let mut request = vec![5, 1, 2];
    request.extend_from_slice(&[1, 1, b'u', 1, b'x']);
    stream.write_all(&request).await.unwrap();
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 2]);
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 1]);

    // Correct password: CONNECT succeeds.
    let mut stream = client(&proxy).await;
    let mut request = vec![5, 1, 2];
    request.extend_from_slice(&[1, 1, b'u', 1, b'p']);
    stream.write_all(&request).await.unwrap();
    stream.read_exact(&mut selection).await.unwrap();
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0]);
    let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
    connect.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&connect).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    stream.write_all(b"ping").await.unwrap();
    let mut payload = [0u8; 4];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"ping");
}

#[tokio::test]
async fn socks4_is_rejected_when_auth_is_enabled() {
    let target = echo().await;
    let proxy = start();
    let mut stream = client(&proxy).await;
    let mut request = vec![4, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(&[127, 0, 0, 1, 0]);
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x5b);
}
