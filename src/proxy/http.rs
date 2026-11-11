use super::{Config, connect, relay};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use url::Url;

pub(super) async fn request(stream: &mut TcpStream, config: &Config) -> Result<()> {
    let (head, rest) = read_head(stream).await?;
    let text = std::str::from_utf8(&head).context("HTTP proxy request is not UTF-8")?;
    let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(method), Some(target), Some(version))
            if !method.is_empty() && version.starts_with("HTTP/1.") =>
        {
            (method, target, version)
        }
        _ => return bad_request(stream, "Malformed request line").await,
    };
    let headers: Vec<&str> = lines.filter(|line| !line.is_empty()).collect();

    if let Err(response) = authorize(&headers, config) {
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    if method == "CONNECT" {
        let (host, port) = authority(target, 443)?;
        let mut remote = connect(&host, port, config.timeout).await?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !rest.is_empty() {
            remote.write_all(&rest).await?;
        }
        return relay(stream, remote).await;
    }

    let url = Url::parse(target).context("Proxy target must be an absolute http:// URL")?;
    ensure!(
        url.scheme() == "http" && url.username().is_empty(),
        "Only absolute-form http:// targets are supported"
    );
    let host = url.host_str().context("Proxy target has no host")?;
    let port = url.port_or_known_default().context("Unsupported scheme")?;
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    ensure!(
        !path.chars().any(char::is_control),
        "Invalid request target"
    );

    let mut remote = connect(host, port, config.timeout).await?;
    // Rewrite absolute-form into origin-form and force one request per
    // connection; the proxy never parses message bodies or responses.
    remote
        .write_all(format!("{method} {path} {version}\r\n").as_bytes())
        .await?;
    for header in headers {
        let name = header.split(':').next().unwrap_or_default().trim();
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        ensure!(
            !header.contains('\r') && !header.contains('\n'),
            "Invalid header"
        );
        remote.write_all(header.as_bytes()).await?;
        remote.write_all(b"\r\n").await?;
    }
    remote.write_all(b"Connection: close\r\n\r\n").await?;
    if !rest.is_empty() {
        remote.write_all(&rest).await?;
    }
    relay(stream, remote).await
}

/// Read the request head plus any body bytes that arrived in the same read.
async fn read_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        ensure!(read > 0, "HTTP proxy client closed before its request head");
        buffer.extend_from_slice(&chunk[..read]);
        ensure!(
            buffer.len() <= super::MAX_HEAD,
            "HTTP proxy request head too large"
        );
        for (index, window) in buffer.windows(2).enumerate() {
            let end = if window == b"\r\n" {
                if buffer.get(index + 2..index + 4) == Some(b"\r\n") {
                    index + 4
                } else {
                    continue;
                }
            } else if window == b"\n\n" {
                index + 2
            } else {
                continue;
            };
            let rest = buffer.split_off(end);
            return Ok((buffer, rest));
        }
    }
}

fn authorize(headers: &[&str], config: &Config) -> Result<(), String> {
    let Some((user, pass)) = &config.auth else {
        return Ok(());
    };
    let encoded = headers.iter().find_map(|header| {
        let (name, value) = header.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("proxy-authorization")
            .then(|| value.trim())
    });
    let decoded = encoded
        .and_then(|value| value.get(..6).map(|prefix| (prefix, &value[6..])))
        .filter(|(prefix, _)| prefix.eq_ignore_ascii_case("Basic "))
        .and_then(|(_, value)| base64::engine::general_purpose::STANDARD.decode(value).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());
    match decoded.as_deref().and_then(|text| text.split_once(':')) {
        Some((given_user, given_pass)) if given_user == user && given_pass == pass => Ok(()),
        _ => Err(challenge()),
    }
}

fn challenge() -> String {
    "HTTP/1.1 407 Proxy Authentication Required\r\n\
     Proxy-Authenticate: Basic realm=\"inode\"\r\n\
     Content-Length: 0\r\n\
     Connection: close\r\n\r\n"
        .to_owned()
}

async fn bad_request(stream: &mut TcpStream, reason: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}",
        reason.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

/// `host:port`, `host` or a bracketed IPv6 literal.
fn authority(value: &str, default_port: u16) -> Result<(String, u16)> {
    ensure!(
        !value.is_empty() && !value.chars().any(char::is_control),
        "Invalid CONNECT target"
    );
    let (host, port) = if value.starts_with('[') {
        let end = value.find(']').context("Unterminated IPv6 literal")?;
        let port = match value[end + 1..].strip_prefix(':') {
            Some(port) => port
                .parse()
                .with_context(|| format!("Invalid port in CONNECT target {value}"))?,
            None if value[end + 1..].is_empty() => default_port,
            None => bail!("Invalid CONNECT target {value}"),
        };
        (&value[1..end], port)
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse()
                    .with_context(|| format!("Invalid port in CONNECT target {value}"))?,
            ),
            None => (value, default_port),
        }
    };
    ensure!(!host.is_empty(), "CONNECT target has no host");
    Ok((host.to_owned(), port))
}
