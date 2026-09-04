//! Минимальный SOCKS5-приём (RFC 1928, только CONNECT, без аутентификации).
//!
//! Локальные приложения указывают VLYNESS-клиент как SOCKS5-прокси. Здесь мы читаем
//! приветствие и запрос CONNECT, извлекаем целевой адрес и отвечаем успехом; затем тот
//! же сокет пробрасывается в туннель ([`crate::TunnelClient::open`]).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use vlyness_core::address::Addr;

fn proto_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Провести SOCKS5-рукопожатие и разобрать запрос CONNECT.
/// Возвращает целевой `(addr, port)`; сокет остаётся готовым к пробросу.
pub async fn socks5_accept<S>(s: &mut S) -> std::io::Result<(Addr, u16)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- приветствие: [ver][nmethods][methods...] ---
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(proto_err("не SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    // Отвечаем «без аутентификации».
    s.write_all(&[VER, 0x00]).await?;

    // --- запрос: [ver][cmd][rsv][atyp][addr][port] ---
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != VER {
        return Err(proto_err("плохая версия запроса"));
    }
    if req[1] != CMD_CONNECT {
        // 0x07 = command not supported.
        let _ = s.write_all(&reply(0x07)).await;
        return Err(proto_err("поддерживается только CONNECT"));
    }

    let addr = match req[3] {
        ATYP_IPV4 => {
            let mut o = [0u8; 4];
            s.read_exact(&mut o).await?;
            Addr::Ipv4(o.into())
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut d = vec![0u8; len[0] as usize];
            s.read_exact(&mut d).await?;
            let host = String::from_utf8(d).map_err(|_| proto_err("домен не UTF-8"))?;
            Addr::Domain(host)
        }
        ATYP_IPV6 => {
            let mut o = [0u8; 16];
            s.read_exact(&mut o).await?;
            Addr::Ipv6(o.into())
        }
        _ => {
            let _ = s.write_all(&reply(0x08)).await; // address type not supported
            return Err(proto_err("неизвестный тип адреса"));
        }
    };

    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    // Успех (0x00). BND.ADDR/PORT = 0.0.0.0:0 — приложению они не важны.
    s.write_all(&reply(0x00)).await?;
    Ok((addr, port))
}

/// Ответ SOCKS5 с кодом `rep`, BND = 0.0.0.0:0 (atyp IPv4).
fn reply(rep: u8) -> [u8; 10] {
    [VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn connect_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move { socks5_accept(&mut server).await });

        client.write_all(&[VER, 1, 0]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [VER, 0]);

        client
            .write_all(&[VER, CMD_CONNECT, 0, ATYP_IPV4, 1, 2, 3, 4, 0x01, 0xbb])
            .await
            .unwrap();
        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[0..2], [VER, 0x00]);

        let (addr, port) = srv.await.unwrap().unwrap();
        assert_eq!(addr, Addr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn connect_domain() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move { socks5_accept(&mut server).await });

        client.write_all(&[VER, 1, 0]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();

        let host = b"example.com";
        let mut req = vec![VER, CMD_CONNECT, 0, ATYP_DOMAIN, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).await.unwrap();

        let (addr, port) = srv.await.unwrap().unwrap();
        assert_eq!(addr, Addr::Domain("example.com".to_string()));
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn rejects_non_connect() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move { socks5_accept(&mut server).await });
        client.write_all(&[VER, 1, 0]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();
        // cmd=0x02 BIND (не поддерживаем)
        client.write_all(&[VER, 0x02, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut rep = [0u8; 10];
        let _ = client.read_exact(&mut rep).await;
        assert_eq!(rep[1], 0x07);
        assert!(srv.await.unwrap().is_err());
    }
}
