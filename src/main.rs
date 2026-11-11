use anyhow::{Context, Result, ensure};
use clap::Parser;
use inode_cli::{
    platform::{self, Platform},
    protocol::{self, Session},
};
use serde::Serialize;
use std::{
    io::{self, BufRead, Write},
    time::Duration,
};
use url::Url;
mod args;
mod captcha;
mod connection;
mod readiness;
pub(crate) use args::*;
use connection::connected;
use inode_cli::captcha_cnn;
use zeroize::Zeroizing;

fn session_with_keepalive(args: &GatewayArgs, keepalive: Option<Duration>) -> Result<Session> {
    Ok(session(args)?.with_keepalive(keepalive))
}

fn session(args: &GatewayArgs) -> Result<Session> {
    let ca = args
        .ca
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("Unable to read CA file")?;
    let proxy = args
        .proxy
        .clone()
        .or_else(|| std::env::var("INODE_PROXY").ok())
        .map(|p| Url::parse(&p))
        .transpose()
        .context("Invalid proxy URL")?;
    if args.insecure {
        eprintln!(
            "WARNING: --insecure skips certificate verification; credentials and traffic can be intercepted."
        );
    }
    Ok(Session::new(
        protocol::gateway(&args.gateway)?,
        ca.as_deref(),
        args.servercert.as_deref(),
        args.insecure,
        Duration::from_secs(args.timeout),
    )?
    .with_proxy(proxy))
}

fn credentials(args: &LoginArgs) -> Result<(String, Zeroizing<String>)> {
    let username = if let Some(user) = &args.user {
        user.clone()
    } else {
        ensure!(!args.password_stdin, "--password-stdin requires --user");
        print!("Username: ");
        io::stdout().flush()?;
        let mut user = String::new();
        io::stdin().read_line(&mut user)?;
        user.trim().to_owned()
    };
    ensure!(
        !username.is_empty() && !username.chars().any(char::is_control),
        "Invalid username"
    );
    let password = if args.password_stdin {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        ensure!(line.len() <= 4096, "Password input too long");
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        line
    } else {
        rpassword::prompt_password("Password: ")?
    };
    ensure!(!password.is_empty(), "Password is required");
    Ok((username, Zeroizing::new(password)))
}

async fn login(args: &LoginArgs, connect: Option<&ConnectArgs>) -> Result<()> {
    let keepalive = connect.map(|c| Duration::from_secs(c.keepalive));
    let s = session_with_keepalive(&args.gateway, keepalive)?;
    let info = s.discover(args.gateway.domain.as_deref()).await?;
    ensure!(
        !info.extra_auth || info.captcha.is_some(),
        "Gateway requires unsupported SMS/SSO authentication"
    );
    if let Some(connect) = connect {
        let ips: Vec<_> = tokio::net::lookup_host((
            s.gateway.host_str().unwrap(),
            s.gateway.port_or_known_default().unwrap(),
        ))
        .await?
        .map(|s| s.ip())
        .collect();
        platform::validate_routes(&connect.route, &ips)?;
    }
    let (user, password) = credentials(args)?;
    if info.captcha.is_some() && !args.manual_captcha {
        // 全自动：内嵌 CNN 识别 + 置信门控 + 免费换图（抓图不限次，提交上限 3 防锁定）
        s.login_auto(&info, &user, &password, args.captcha_confidence, 60, 3)
            .await?;
    } else {
        let captcha = if let Some(url) = &info.captcha {
            let bytes = s.request_bytes(url.clone(), None, false).await?;
            ensure!(
                bytes.starts_with(b"\x89PNG")
                    || bytes.starts_with(b"GIF8")
                    || bytes.starts_with(b"\xff\xd8")
                    || bytes.starts_with(b"BM"),
                "Gateway did not return a supported CAPTCHA image"
            );
            captcha::display(&bytes, args.captcha_file.as_deref(), args.captcha_columns)?;
            print!("CAPTCHA: ");
            io::stdout().flush()?;
            let mut code = String::new();
            io::stdin().read_line(&mut code)?;
            ensure!(!code.trim().is_empty(), "CAPTCHA is required");
            Some(code.trim().to_owned())
        } else {
            None
        };
        s.login_with_captcha(&info, &user, &password, captcha.as_deref())
            .await?;
    }
    drop(password);
    let result = if let Some(args) = connect {
        connected(&s, args).await
    } else {
        println!("Authentication succeeded. No interface or routes created.");
        Ok(())
    };
    s.logout(&info).await;
    result
}

#[derive(Serialize)]
struct Health {
    os: &'static str,
    arch: &'static str,
    tun_driver_available: bool,
    note: &'static str,
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Doctor => {
            let platform = platform::current()?;
            let available = match platform {
                Platform::Linux => std::path::Path::new("/dev/net/tun").exists(),
                Platform::Macos => true,
                Platform::Windows => std::env::current_exe()?
                    .parent()
                    .unwrap()
                    .join("wintun.dll")
                    .is_file(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&Health {
                    os: std::env::consts::OS,
                    arch: std::env::consts::ARCH,
                    tun_driver_available: available,
                    note: "Connect needs administrator/root. Doctor does not prove VPN connectivity or driver loadability."
                })?
            );
            ensure!(available, "TUN prerequisites missing");
        }
        Commands::Probe(args) => {
            let s = session(&args)?;
            let info = s.discover(args.domain.as_deref()).await?;
            println!(
                "{}",
                serde_json::json!({"h3c_gatewayinfo": true, "extra_auth_advertised": info.extra_auth,
                "captcha_supported": info.captcha.is_some(), "authenticated": false, "auth_parameters": info.auth_parameters})
            );
        }
        Commands::Authenticate(args) => login(&args, None).await?,
        Commands::Connect(args) => login(&args.login, Some(&args)).await?,
        Commands::CaptchaTest { file } => {
            let bytes = std::fs::read(&file)?;
            match captcha_cnn::Model::load().solve(&bytes) {
                Some((s, c)) => println!("{s}\t{c:.3}"),
                None => println!("<no-4-glyphs>\t0"),
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("Error: {error:#}");
        std::process::exit(2);
    }
}
