//! Адресный кадр (wire-spec §6) — VLESS-совместимое ядро адресации.
//!
//! Формат намеренно повторяет адресную часть VLESS (док 00 §2), чтобы переиспользовать
//! логику роутинга. Отличия от VLESS-хедера:
//! - нет `ver`/`UUID` — аутентификация ушла в `auth` (§3) и Noise (§4);
//! - добавлен `streamId` — всё мультиплексируется в одном TLS (дизайн §5, признак №5);
//! - нет `flow`/addons — Vision заменён shaping-слоем (дизайн §8).
//!
//! Эта структура сериализуется в payload кадра [`crate::frame::FrameType::Address`].
//!
//! ```text
//! +-----------+--------+--------+-----------+---------+
//! |   2 B     |  1 B   |  2 B   |    1 B     |   N B   |
//! +-----------+--------+--------+-----------+---------+
//! | streamId  |  cmd   |  port  | addrType  |  addr   |
//! +-----------+--------+--------+-----------+---------+
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

/// Команда: тип соединения к цели.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cmd {
    Tcp = 0x01,
    Udp = 0x02,
}

impl Cmd {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Cmd::Tcp),
            0x02 => Some(Cmd::Udp),
            _ => None,
        }
    }
}

/// Адрес назначения. Домен хранится как есть (резолвится на стороне сервера,
/// чтобы наружу не утекал DNS-запрос клиента к цели).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    Ipv4(Ipv4Addr),
    /// Доменное имя, ≤ 255 байт.
    Domain(String),
    Ipv6(Ipv6Addr),
}

const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x02;
const ADDR_IPV6: u8 = 0x03;

/// Максимальная длина доменного имени в байтах (кодируется одним байтом длины).
pub const MAX_DOMAIN_LEN: usize = 255;

/// Ошибки разбора/сборки адресного кадра.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("буфер обрывается: нужно ещё байт для поля {field}")]
    Truncated { field: &'static str },
    #[error("неизвестная команда: {0:#04x}")]
    BadCmd(u8),
    #[error("неизвестный тип адреса: {0:#04x}")]
    BadAddrType(u8),
    #[error("домен длиннее {MAX_DOMAIN_LEN} байт: {0}")]
    DomainTooLong(usize),
    #[error("домен не является валидным UTF-8")]
    DomainNotUtf8,
    #[error("в буфере остались лишние байты после адреса: {0}")]
    TrailingBytes(usize),
}

/// Адресный кадр открытия логического потока.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressFrame {
    pub stream_id: u16,
    pub cmd: Cmd,
    pub port: u16,
    pub addr: Addr,
}

impl AddressFrame {
    pub fn new(stream_id: u16, cmd: Cmd, port: u16, addr: Addr) -> Self {
        AddressFrame { stream_id, cmd, port, addr }
    }

    /// Сериализация в байты (тело кадра `Address`).
    pub fn encode(&self) -> Result<Vec<u8>, AddressError> {
        if let Addr::Domain(d) = &self.addr {
            if d.len() > MAX_DOMAIN_LEN {
                return Err(AddressError::DomainTooLong(d.len()));
            }
        }
        let mut buf = Vec::with_capacity(6 + 16);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.push(self.cmd as u8);
        buf.extend_from_slice(&self.port.to_be_bytes());
        match &self.addr {
            Addr::Ipv4(ip) => {
                buf.push(ADDR_IPV4);
                buf.extend_from_slice(&ip.octets());
            }
            Addr::Domain(d) => {
                buf.push(ADDR_DOMAIN);
                buf.push(d.len() as u8);
                buf.extend_from_slice(d.as_bytes());
            }
            Addr::Ipv6(ip) => {
                buf.push(ADDR_IPV6);
                buf.extend_from_slice(&ip.octets());
            }
        }
        Ok(buf)
    }

    /// Разбор байтов обратно в адресный кадр. Буфер должен быть исчерпан целиком.
    pub fn decode(buf: &[u8]) -> Result<AddressFrame, AddressError> {
        let mut cur = Cursor { buf, pos: 0 };
        let stream_id = cur.u16("stream_id")?;
        let cmd = Cmd::from_u8(cur.u8("cmd")?).ok_or_else(|| AddressError::BadCmd(buf[2]))?;
        let port = cur.u16("port")?;
        let addr_type = cur.u8("addr_type")?;
        let addr = match addr_type {
            ADDR_IPV4 => {
                let o = cur.take(4, "ipv4")?;
                Addr::Ipv4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
            }
            ADDR_DOMAIN => {
                let len = cur.u8("domain_len")? as usize;
                let d = cur.take(len, "domain")?;
                let s = std::str::from_utf8(d).map_err(|_| AddressError::DomainNotUtf8)?;
                Addr::Domain(s.to_owned())
            }
            ADDR_IPV6 => {
                let o = cur.take(16, "ipv6")?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(o);
                Addr::Ipv6(Ipv6Addr::from(octets))
            }
            other => return Err(AddressError::BadAddrType(other)),
        };
        let remaining = buf.len() - cur.pos;
        if remaining != 0 {
            return Err(AddressError::TrailingBytes(remaining));
        }
        Ok(AddressFrame { stream_id, cmd, port, addr })
    }
}

/// Минималистичный курсор по срезу с проверками границ.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], AddressError> {
        if self.pos + n > self.buf.len() {
            return Err(AddressError::Truncated { field });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, AddressError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, AddressError> {
        let s = self.take(2, field)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(f: &AddressFrame) {
        let buf = f.encode().unwrap();
        assert_eq!(&AddressFrame::decode(&buf).unwrap(), f);
    }

    #[test]
    fn roundtrip_ipv4() {
        roundtrip(&AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn roundtrip_ipv6() {
        roundtrip(&AddressFrame::new(
            65535,
            Cmd::Udp,
            53,
            Addr::Ipv6("2001:4860:4860::8888".parse().unwrap()),
        ));
    }

    #[test]
    fn roundtrip_domain() {
        roundtrip(&AddressFrame::new(
            7,
            Cmd::Tcp,
            80,
            Addr::Domain("example.com".to_string()),
        ));
    }

    #[test]
    fn roundtrip_max_length_domain() {
        let d = "a".repeat(MAX_DOMAIN_LEN);
        roundtrip(&AddressFrame::new(2, Cmd::Tcp, 8080, Addr::Domain(d)));
    }

    #[test]
    fn encode_rejects_overlong_domain() {
        let d = "a".repeat(MAX_DOMAIN_LEN + 1);
        let f = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Domain(d));
        assert_eq!(f.encode(), Err(AddressError::DomainTooLong(MAX_DOMAIN_LEN + 1)));
    }

    #[test]
    fn decode_rejects_bad_cmd() {
        // streamId=0x0001, cmd=0x09 (invalid)
        let buf = [0x00, 0x01, 0x09, 0x01, 0xbb, ADDR_IPV4, 1, 2, 3, 4];
        assert_eq!(AddressFrame::decode(&buf), Err(AddressError::BadCmd(0x09)));
    }

    #[test]
    fn decode_rejects_bad_addr_type() {
        let buf = [0x00, 0x01, 0x01, 0x01, 0xbb, 0x099];
        assert_eq!(AddressFrame::decode(&buf), Err(AddressError::BadAddrType(0x99)));
    }

    #[test]
    fn decode_rejects_truncated() {
        // Обрыв внутри IPv4-адреса.
        let buf = [0x00, 0x01, 0x01, 0x01, 0xbb, ADDR_IPV4, 1, 2];
        assert_eq!(AddressFrame::decode(&buf), Err(AddressError::Truncated { field: "ipv4" }));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut buf = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::LOCALHOST))
            .encode()
            .unwrap();
        buf.push(0xff); // лишний байт
        assert_eq!(AddressFrame::decode(&buf), Err(AddressError::TrailingBytes(1)));
    }
}
