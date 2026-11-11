use super::{Config, connect, relay};
use anyhow::{Context, Result, bail, ensure};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const REPLY_SUCCESS: u8 = 0;
const REPLY_FAILURE: u8 = 1;
const REPLY_UNSUPPORTED: u8 = 7;
const REPLY_ADDRESS: u8 = 8;

async fn reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    // BND.ADDR/BND.PORT are placeholders: clients only read REP.
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

pub(super) async fn socks5(stream: &mut TcpStream, config: &Config) -> Result<()> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    ensure!(greeting[0] == 5, "Not a SOCKS5 greeting");
    ensure!(greeting[1] > 0, "Empty SOCKS5 method list");
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;

    let method = if config.requires_auth() { 2 } else { 0 };
    if !methods.contains(&method) {
        stream.write_all(&[5, 0xff]).await?;
        bail!("SOCKS5 client did not offer the required authentication method");
    }
    stream.write_all(&[5, method]).await?;
    if method == 2 {
        userpass(stream, config).await?;
    }

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    ensure!(
        request[0] == 5 && request[2] == 0,
        "Malformed SOCKS5 request"
    );
    if request[1] != 1 {
        reply(stream, REPLY_UNSUPPORTED).await?;
        bail!("Only SOCKS5 CONNECT is supported");
    }
    let (host, port) = match target(stream, request[3]).await {
        Ok(target) => target,
        Err(error) => {
            reply(stream, REPLY_ADDRESS).await?;
            return Err(error);
        }
    };
    let remote = match connect(&host, port, config.timeout).await {
        Ok(remote) => remote,
        Err(error) => {
            reply(stream, REPLY_FAILURE).await?;
            return Err(error);
        }
    };
    reply(stream, REPLY_SUCCESS).await?;
    relay(stream, remote).await
}

/// RFC 1929 username/password sub-negotiation.
async fn userpass(stream: &mut TcpStream, config: &Config) -> Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    ensure!(head[0] == 1 && head[1] > 0, "Malformed SOCKS5 credentials");
    let mut user = vec![0u8; head[1] as usize];
    stream.read_exact(&mut user).await?;
    let mut length = [0u8; 1];
    stream.read_exact(&mut length).await?;
    ensure!(length[0] > 0, "SOCKS5 password is empty");
    let mut pass = vec![0u8; length[0] as usize];
    stream.read_exact(&mut pass).await?;
    let ok = config.authorized(
        &String::from_utf8_lossy(&user),
        &String::from_utf8_lossy(&pass),
    );
    stream.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    ensure!(ok, "SOCKS5 authentication failed");
    Ok(())
}

async fn target(stream: &mut TcpStream, address_type: u8) -> Result<(String, u16)> {
    let host = match address_type {
        1 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            Ipv4Addr::from(address).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            ensure!(length[0] > 0, "SOCKS5 domain name is empty");
            let mut name = vec![0u8; length[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).context("SOCKS5 domain name is not UTF-8")?
        }
        4 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            Ipv6Addr::from(address).to_string()
        }
        other => bail!("Unsupported SOCKS5 address type {other}"),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

async fn socks4_reply(stream: &mut TcpStream, granted: bool) -> Result<()> {
    // VN=0, CD=0x5A granted / 0x5B rejected, then a zeroed address.
    let code = if granted { 0x5a } else { 0x5b };
    stream.write_all(&[0, code, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

pub(super) async fn socks4(stream: &mut TcpStream, config: &Config) -> Result<()> {
    let mut head = [0u8; 8];
    stream.read_exact(&mut head).await?;
    ensure!(head[0] == 4, "Not a SOCKS4 request");
    read_cstring(stream).await?; // USERID: SOCKS4 has no password field.
    if config.requires_auth() {
        socks4_reply(stream, false).await?;
        bail!("SOCKS4 cannot authenticate; use SOCKS5 or HTTP, or disable proxy auth");
    }
    if head[1] != 1 {
        socks4_reply(stream, false).await?;
        bail!("Only SOCKS4 CONNECT is supported");
    }
    let port = u16::from_be_bytes([head[2], head[3]]);
    let address = Ipv4Addr::new(head[4], head[5], head[6], head[7]);
    let host = if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 {
        read_cstring(stream).await? // SOCKS4a: the name follows USERID.
    } else {
        address.to_string()
    };
    let remote = match connect(&host, port, config.timeout).await {
        Ok(remote) => remote,
        Err(error) => {
            socks4_reply(stream, false).await?;
            return Err(error);
        }
    };
    socks4_reply(stream, true).await?;
    relay(stream, remote).await
}

async fn read_cstring(stream: &mut TcpStream) -> Result<String> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        if byte[0] == 0 {
            return String::from_utf8(bytes).context("SOCKS4 string is not UTF-8");
        }
        bytes.push(byte[0]);
        ensure!(bytes.len() <= 255, "SOCKS4 string too long");
    }
}
