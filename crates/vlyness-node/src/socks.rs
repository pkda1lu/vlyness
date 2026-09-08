//! SOCKS5 (RFC 1928): CONNECT (TCP) и UDP ASSOCIATE. Без аутентификации.
//!
//! Локальные приложения указывают VLYNESS-клиент как SOCKS5-прокси. Здесь — разбор
//! приветствия и запроса, отправка ответа, и кодек заголовка UDP-датаграмм (§7 RFC),
//! которым инкапсулируется каждый UDP-пакет между приложением и прокси.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use vlyness_core::address::Addr;

fn proto_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// Код ответа: успех.
pub const REP_SUCCESS: u8 = 0x00;

/// Разобранный запрос SOCKS5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksRequest {
    /// CONNECT к цели (TCP).
    Connect { addr: Addr, port: u16 },
    /// UDP ASSOCIATE (адрес в запросе — где клиент будет слать; обычно 0.0.0.0:0).
    UdpAssociate,
}

/// Прочитать адрес по типу `atyp` из потока.
async fn read_addr<S: AsyncRead + Unpin>(s: &mut S, atyp: u8) -> std::io::Result<Addr> {
    Ok(match atyp {
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
            Addr::Domain(String::from_utf8(d).map_err(|_| proto_err("домен не UTF-8"))?)
        }
        ATYP_IPV6 => {
            let mut o = [0u8; 16];
            s.read_exact(&mut o).await?;
            Addr::Ipv6(o.into())
        }
        _ => return Err(proto_err("неизвестный тип адреса")),
    })
}

/// Провести приветствие и разобрать запрос. Финальный ответ НЕ шлётся — его отправляет
/// вызывающий через [`reply`] (для UDP нужно знать адрес UDP-релея).
pub async fn accept<S>(s: &mut S) -> std::io::Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Приветствие: [ver][nmethods][methods...] → отвечаем «без аутентификации».
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(proto_err("не SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    s.write_all(&[VER, 0x00]).await?;

    // Запрос: [ver][cmd][rsv][atyp][addr][port].
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != VER {
        return Err(proto_err("плохая версия запроса"));
    }
    let addr = read_addr(s, req[3]).await?;
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    match req[1] {
        CMD_CONNECT => Ok(SocksRequest::Connect { addr, port }),
        CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate),
        _ => {
            // 0x07 = command not supported.
            let _ = reply(s, 0x07, "0.0.0.0:0".parse().unwrap()).await;
            Err(proto_err("команда не поддерживается"))
        }
    }
}

/// Отправить ответ SOCKS5 с кодом `rep` и привязанным адресом `bnd`.
pub async fn reply<S>(s: &mut S, rep: u8, bnd: SocketAddr) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = vec![VER, rep, 0x00];
    match bnd {
        SocketAddr::V4(a) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&bnd.port().to_be_bytes());
    s.write_all(&out).await
}

/// Разобрать заголовок UDP-датаграммы SOCKS5 (§7): `RSV(2) FRAG(1) ATYP ADDR PORT DATA`.
/// Возвращает `(целевой адрес, порт, смещение до DATA)`. Фрагментация (FRAG≠0) не
/// поддерживается — такие датаграммы отбрасываются.
pub fn parse_udp_header(buf: &[u8]) -> Option<(Addr, u16, usize)> {
    if buf.len() < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return None; // RSV должен быть 0, FRAG=0
    }
    let (addr, mut off) = match buf[3] {
        ATYP_IPV4 => {
            if buf.len() < 4 + 4 + 2 {
                return None;
            }
            (Addr::Ipv4([buf[4], buf[5], buf[6], buf[7]].into()), 8)
        }
        ATYP_DOMAIN => {
            let len = *buf.get(4)? as usize;
            let start = 5;
            if buf.len() < start + len + 2 {
                return None;
            }
            let d = String::from_utf8(buf[start..start + len].to_vec()).ok()?;
            (Addr::Domain(d), start + len)
        }
        ATYP_IPV6 => {
            if buf.len() < 4 + 16 + 2 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[4..20]);
            (Addr::Ipv6(o.into()), 20)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
    off += 2;
    Some((addr, port, off))
}

/// Построить заголовок UDP-датаграммы SOCKS5 для `(addr, port)` (FRAG=0).
pub fn build_udp_header(addr: &Addr, port: u16) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00]; // RSV RSV FRAG
    match addr {
        Addr::Ipv4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Addr::Domain(d) => {
            out.push(ATYP_DOMAIN);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
        Addr::Ipv6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn connect_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move { accept(&mut server).await });
        client.write_all(&[VER, 1, 0]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [VER, 0]);
        client
            .write_all(&[VER, CMD_CONNECT, 0, ATYP_IPV4, 1, 2, 3, 4, 0x01, 0xbb])
            .await
            .unwrap();
        let req = srv.await.unwrap().unwrap();
        assert_eq!(req, SocksRequest::Connect { addr: Addr::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), port: 443 });
    }

    #[tokio::test]
    async fn udp_associate_parsed() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move { accept(&mut server).await });
        client.write_all(&[VER, 1, 0]).await.unwrap();
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet).await.unwrap();
        // UDP ASSOCIATE, DST = 0.0.0.0:0
        client
            .write_all(&[VER, CMD_UDP_ASSOCIATE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        assert_eq!(srv.await.unwrap().unwrap(), SocksRequest::UdpAssociate);
    }

    #[test]
    fn udp_header_roundtrip_ipv4() {
        let h = build_udp_header(&Addr::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let mut dg = h.clone();
        dg.extend_from_slice(b"dns-payload");
        let (addr, port, off) = parse_udp_header(&dg).unwrap();
        assert_eq!(addr, Addr::Ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(port, 53);
        assert_eq!(&dg[off..], b"dns-payload");
    }

    #[test]
    fn udp_header_roundtrip_domain() {
        let h = build_udp_header(&Addr::Domain("dns.example".into()), 853);
        let (addr, port, off) = parse_udp_header(&h).unwrap();
        assert_eq!(addr, Addr::Domain("dns.example".into()));
        assert_eq!(port, 853);
        assert_eq!(off, h.len());
    }

    #[test]
    fn udp_header_rejects_fragment() {
        // FRAG != 0 → не поддерживаем.
        let dg = [0x00, 0x00, 0x01, ATYP_IPV4, 1, 2, 3, 4, 0, 53];
        assert!(parse_udp_header(&dg).is_none());
    }
}
