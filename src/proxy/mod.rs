//! One listening port that speaks HTTP (CONNECT and absolute-form), SOCKS5
//! and SOCKS4/4a; the client's first bytes select the protocol.
//!
//! The proxy only forwards TCP. Destinations are reached through the kernel
//! routes that `connect` installed, so no packet handling lives here.

use anyhow::{Context, Result, ensure};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};

mod http;
mod socks;

/// Upper bound for one proxy request head; the longest legitimate head is a
/// few hundred bytes, and nothing is trusted before authentication.
const MAX_HEAD: usize = 16 * 1024;

pub struct Config {
    /// Username and password required by HTTP Basic and SOCKS5. `None` keeps
    /// the listener open, which is only safe on a loopback bind.
    pub auth: Option<(String, String)>,
    /// Applies to the protocol handshake and to reaching the destination.
    pub timeout: Duration,
}

impl Config {
    fn authorized(&self, user: &str, pass: &str) -> bool {
        match &self.auth {
            Some((expected_user, expected_pass)) => expected_user == user && expected_pass == pass,
            None => true,
        }
    }

    fn requires_auth(&self) -> bool {
        self.auth.is_some()
    }
}

/// Owning handle: dropping it closes the listener and every in-flight relay.
pub struct Proxy {
    local: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Proxy {
    pub fn start(listen: SocketAddr, config: Config) -> Result<Self> {
        let listener = std::net::TcpListener::bind(listen)
            .with_context(|| format!("Cannot bind proxy listener {listen}"))?;
        listener.set_nonblocking(true)?;
        let local = listener.local_addr()?;
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let Ok(listener) = TcpListener::from_std(listener) else {
                return;
            };
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    continue;
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(error) = serve(stream, &config).await {
                        eprintln!("Proxy {peer}: {error:#}");
                    }
                });
            }
        });
        Ok(Self { local, task })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(mut stream: TcpStream, config: &Config) -> Result<()> {
    // Peek instead of read: a SOCKS client's greeting must stay intact for the
    // handler, while an HTTP request starts with its method name.
    let mut first = [0u8; 1];
    let read = tokio::time::timeout(config.timeout, stream.peek(&mut first)).await??;
    ensure!(read == 1, "Proxy client closed before sending a request");
    stream.set_nodelay(true)?;
    match first[0] {
        5 => socks::socks5(&mut stream, config).await,
        4 => socks::socks4(&mut stream, config).await,
        _ => http::request(&mut stream, config).await,
    }
}

/// Resolve (inside this container: the VPN protocol carries no DNS) and connect.
pub(super) async fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    ensure!(
        !host.is_empty()
            && port != 0
            && !host.contains('/')
            && !host.contains('\\')
            && !host.chars().any(char::is_control),
        "Invalid proxy destination"
    );
    let targets = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .context("Proxy destination resolution timed out")??;
    let mut last: Option<anyhow::Error> = None;
    for target in targets {
        match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Ok(Err(error)) => last = Some(error.into()),
            Err(error) => last = Some(error.into()),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("Proxy destination has no address")))
}

pub(super) async fn relay(client: &mut TcpStream, mut remote: TcpStream) -> Result<()> {
    tokio::io::copy_bidirectional(client, &mut remote).await?;
    Ok(())
}
