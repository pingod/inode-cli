use inode_cli::proxy::{Config, Proxy};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

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
            auth: None,
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

async fn socks5_connect(stream: &mut TcpStream, port: u16) {
    // No authentication, IPv4 CONNECT.
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&[127, 0, 0, 1]);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT rejected");
}

async fn roundtrip(stream: &mut TcpStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut payload = [0u8; 4];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"ping");
}

#[tokio::test]
async fn socks5_tunnels_to_target() {
    let target = echo().await;
    let proxy = start();
    let mut stream = client(&proxy).await;
    socks5_connect(&mut stream, target.port()).await;
    roundtrip(&mut stream).await;
}

#[tokio::test]
async fn socks4_and_socks4a_tunnel_to_target() {
    let target = echo().await;
    let proxy = start();

    let mut stream = client(&proxy).await;
    let mut request = vec![4, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(&[127, 0, 0, 1, 0]);
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x5a);
    roundtrip(&mut stream).await;

    let mut stream = client(&proxy).await;
    let mut request = vec![4, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(&[0, 0, 0, 1, 0]);
    request.extend_from_slice(b"localhost\0");
    stream.write_all(&request).await.unwrap();
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x5a);
    roundtrip(&mut stream).await;
}

#[tokio::test]
async fn http_connect_tunnels_to_target() {
    let target = echo().await;
    let proxy = start();
    let mut stream = client(&proxy).await;
    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: x\r\n\r\n",
        target.port()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    assert!(read_head(&mut stream).await.starts_with("HTTP/1.1 200"));
    roundtrip(&mut stream).await;
}

#[tokio::test]
async fn http_absolute_form_rewrites_to_origin_form() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    let (seen, seen_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];
        while !buffer.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).await.unwrap();
            buffer.push(byte[0]);
        }
        let request = String::from_utf8(buffer).unwrap();
        seen.send(request.lines().next().unwrap().to_owned())
            .unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    let proxy = start();
    let mut stream = client(&proxy).await;
    let request = format!("GET http://{origin}/a?b=1 HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.ends_with("ok"), "{response}");
    assert_eq!(seen_rx.await.unwrap(), "GET /a?b=1 HTTP/1.1");
}
