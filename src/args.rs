//! Command-line surface. Kept out of `main.rs` so each owned file stays small.
use clap::{Args, Parser, Subcommand};
use ipnet::Ipv4Net;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "inode",
    version,
    about = "Experimental H3C SSL VPN CLI for Windows, Linux and macOS"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Inspect local prerequisites, without changing network configuration.
    Doctor,
    /// Discover gateway protocol without submitting credentials.
    Probe(GatewayArgs),
    /// Authenticate once and log out, without creating a TUN interface.
    Authenticate(LoginArgs),
    /// Connect in foreground; Ctrl+C removes this connection's interface/routes.
    Connect(ConnectArgs),
    /// [test] Recognize a CAPTCHA image file with the embedded CNN.
    CaptchaTest { file: PathBuf },
}
#[derive(Args)]
pub(crate) struct GatewayArgs {
    /// HTTPS VPN gateway (no path), e.g. https://vpn.example.com:443.
    pub(crate) gateway: String,
    /// Trusted organization CA certificate in PEM format.
    #[arg(long)]
    pub(crate) ca: Option<PathBuf>,
    /// Exact trusted server certificate SHA-256 fingerprint (64 hex characters).
    #[arg(long)]
    pub(crate) servercert: Option<String>,
    /// Accept any server certificate: no chain, hostname or fingerprint check.
    /// Credentials and traffic can be intercepted; use only as a last resort.
    #[arg(long, conflicts_with_all = ["ca", "servercert"])]
    pub(crate) insecure: bool,
    #[arg(long)]
    pub(crate) domain: Option<String>,
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=120))]
    pub(crate) timeout: u64,
    /// HTTP proxy for reaching the gateway, e.g. http://127.0.0.1:1080.
    /// Also read from INODE_PROXY. The CONNECT tunnel carries all traffic.
    #[arg(long)]
    pub(crate) proxy: Option<String>,
}
#[derive(Args)]
pub(crate) struct LoginArgs {
    #[command(flatten)]
    pub(crate) gateway: GatewayArgs,
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Read one password line from stdin instead of the terminal (automation).
    #[arg(long)]
    pub(crate) password_stdin: bool,
    /// Optionally save CAPTCHA; interactive terminals display it directly.
    #[arg(long)]
    pub(crate) captcha_file: Option<PathBuf>,
    /// Width of the inline color CAPTCHA in terminal columns.
    #[arg(long, default_value_t = 96, value_parser = clap::value_parser!(u32).range(40..=160))]
    pub(crate) captcha_columns: u32,
    /// Solve the CAPTCHA manually (default: automatic on-device recognition).
    #[arg(long)]
    pub(crate) manual_captcha: bool,
    /// Minimum confidence to submit an auto-recognized CAPTCHA (0-1).
    #[arg(long, default_value_t = 0.90)]
    pub(crate) captcha_confidence: f32,
}
#[derive(Args)]
pub(crate) struct ConnectArgs {
    #[command(flatten)]
    pub(crate) login: LoginArgs,
    /// Internal IPv4 network; repeat for more networks. DNS/default route are unchanged.
    #[arg(long)]
    pub(crate) route: Vec<Ipv4Net>,
    /// Consecutive tunnel reconnects before giving up; 0 exits on the first drop.
    #[arg(long, default_value_t = 5)]
    pub(crate) reconnect_attempts: u32,
    /// TCP keepalive interval in seconds for idle tunnels; 0 disables it.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(0..=3600))]
    pub(crate) keepalive: u64,
    /// Also install the routes the gateway advertises in its NET_EXTEND response.
    #[arg(long)]
    pub(crate) gateway_routes: bool,
    /// Tunnel interface MTU. The protocol carries no MTU, so this is a local choice.
    #[arg(long, default_value_t = 1400, value_parser = clap::value_parser!(u16).range(576..=1500))]
    pub(crate) mtu: u16,
    /// Serve HTTP, SOCKS5 and SOCKS4/4a proxies on this address; one port,
    /// protocol auto-detected per connection.
    #[arg(long, value_name = "ADDR")]
    pub(crate) proxy_listen: Option<SocketAddr>,
    /// Require this username for HTTP Basic and SOCKS5 password authentication.
    #[arg(long, requires = "proxy_listen")]
    pub(crate) proxy_user: Option<String>,
    /// Password for --proxy-user. SOCKS4/4a is rejected while auth is enabled.
    #[arg(long, requires = "proxy_user")]
    pub(crate) proxy_password: Option<String>,
}
