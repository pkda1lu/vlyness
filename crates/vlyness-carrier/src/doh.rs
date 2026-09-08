//! Получение ECHConfigList носителя из DNS через DoH (whitelist §5.1, док 05 §2.1).
//!
//! Настоящий ECH требует ECHConfigList того фронта (CDN), чьим арендатором мы являемся.
//! Публикуется он в DNS — в записи **HTTPS RR** (тип 65, RFC 9460), в параметре
//! `ech` (SvcParamKey 5). Забирать его обычным DNS нельзя: резолвер провайдера — ровно
//! тот, кто может подменить или вырезать ответ. Поэтому запрос идёт **DNS-over-HTTPS**
//! (RFC 8484): по TLS к независимому резолверу, неотличимо от обычного HTTPS.
//!
//! Собственный минимальный DNS-кодек вместо тяжёлой библиотеки: нужен ровно один тип
//! записи. Декомпрессия имён не требуется — имена в ответе мы только **пропускаем**
//! (указатель распознаётся по старшим битам), а `TargetName` внутри HTTPS RR по RFC 9460
//! сжиматься не может.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::net::TcpStream;

use crate::http::{read_body, send_body};

/// Тип записи HTTPS (RFC 9460).
const RR_TYPE_HTTPS: u16 = 65;
/// SvcParamKey `ech` (RFC 9460 + draft-ietf-tls-esni).
const SVCPARAM_ECH: u16 = 5;
/// Резолвер по умолчанию.
pub const DEFAULT_DOH_RESOLVER: &str = "https://cloudflare-dns.com/dns-query";

fn bad(msg: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

fn other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Разобрать `https://host/path` на `(host, path)`.
fn split_resolver(url: &str) -> std::io::Result<(String, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| bad("резолвер должен быть https://"))?;
    match rest.split_once('/') {
        Some((host, path)) if !host.is_empty() => Ok((host.to_string(), format!("/{path}"))),
        _ if !rest.is_empty() => Ok((rest.to_string(), "/dns-query".to_string())),
        _ => Err(bad("пустой адрес резолвера")),
    }
}

/// Закодировать доменное имя в метки DNS: `example.com` → `7example3com0`.
fn encode_name(domain: &str, out: &mut Vec<u8>) -> std::io::Result<()> {
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(bad(format!("некорректная метка домена в '{domain}'")));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Собрать DNS-запрос HTTPS RR для домена.
///
/// ID = 0: RFC 8484 рекомендует это для кэшируемости DoH-запросов.
pub fn build_https_query(domain: &str) -> std::io::Result<Vec<u8>> {
    let mut q = Vec::with_capacity(32 + domain.len());
    q.extend_from_slice(&[0x00, 0x00]); // ID
    q.extend_from_slice(&[0x01, 0x00]); // флаги: RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    encode_name(domain, &mut q)?;
    q.extend_from_slice(&RR_TYPE_HTTPS.to_be_bytes()); // QTYPE=HTTPS
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    Ok(q)
}

/// Курсор по DNS-сообщению.
struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Some((hi << 8) | lo)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n).filter(|p| *p <= self.b.len())?;
        Some(())
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|p| *p <= self.b.len())?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Some(s)
    }
    /// Пропустить доменное имя: либо метки до нулевой, либо 2-байтовый указатель.
    fn skip_name(&mut self) -> Option<()> {
        loop {
            let len = self.u8()?;
            if len == 0 {
                return Some(());
            }
            if len & 0xC0 == 0xC0 {
                self.u8()?; // вторая половина указателя
                return Some(());
            }
            self.skip(len as usize)?;
        }
    }
}

/// Вытащить ECHConfigList из DNS-ответа с HTTPS RR.
///
/// Возвращает `None`, если записи нет или в ней нет параметра `ech` — это нормальная
/// ситуация (домен без ECH), а не ошибка формата.
pub fn extract_ech(response: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
    let mut c = Cur { b: response, pos: 0 };
    let _id = c.u16().ok_or_else(|| bad("обрыв заголовка DNS"))?;
    let flags = c.u16().ok_or_else(|| bad("обрыв флагов DNS"))?;
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(bad(format!("DNS вернул RCODE={rcode}")));
    }
    let qd = c.u16().ok_or_else(|| bad("обрыв QDCOUNT"))?;
    let an = c.u16().ok_or_else(|| bad("обрыв ANCOUNT"))?;
    c.skip(4).ok_or_else(|| bad("обрыв NS/AR counts"))?;

    for _ in 0..qd {
        c.skip_name().ok_or_else(|| bad("обрыв имени в вопросе"))?;
        c.skip(4).ok_or_else(|| bad("обрыв QTYPE/QCLASS"))?;
    }

    for _ in 0..an {
        c.skip_name().ok_or_else(|| bad("обрыв имени в ответе"))?;
        let rtype = c.u16().ok_or_else(|| bad("обрыв TYPE"))?;
        c.skip(2 + 4).ok_or_else(|| bad("обрыв CLASS/TTL"))?;
        let rdlen = c.u16().ok_or_else(|| bad("обрыв RDLENGTH"))? as usize;
        let rdata = c.take(rdlen).ok_or_else(|| bad("обрыв RDATA"))?;
        if rtype != RR_TYPE_HTTPS {
            continue;
        }
        if let Some(ech) = ech_from_https_rdata(rdata) {
            return Ok(Some(ech));
        }
    }
    Ok(None)
}

/// Разобрать RDATA записи HTTPS: priority(2) + TargetName + SvcParams.
fn ech_from_https_rdata(rdata: &[u8]) -> Option<Vec<u8>> {
    let mut c = Cur { b: rdata, pos: 0 };
    let priority = c.u16()?;
    // AliasMode (priority 0) не несёт параметров.
    if priority == 0 {
        return None;
    }
    // TargetName: в SVCB/HTTPS сжатие запрещено, поэтому просто метки до нуля.
    loop {
        let len = c.u8()?;
        if len == 0 {
            break;
        }
        c.skip(len as usize)?;
    }
    // SvcParams идут упорядоченно: key(2), len(2), value.
    while c.pos < rdata.len() {
        let key = c.u16()?;
        let len = c.u16()? as usize;
        let val = c.take(len)?;
        if key == SVCPARAM_ECH {
            return Some(val.to_vec());
        }
    }
    None
}

/// Выполнить DoH-запрос и вернуть тело DNS-ответа.
async fn doh_exchange(
    roots: RootCertStore,
    resolver_url: &str,
    query: &[u8],
) -> std::io::Result<Vec<u8>> {
    let (host, path) = split_resolver(resolver_url)?;
    let cfg = crate::tls::client_config(roots).map_err(other)?;
    let tcp = TcpStream::connect((host.as_str(), 443)).await?;
    let name = ServerName::try_from(host.clone()).map_err(|_| bad("плохое имя резолвера"))?;
    let tls = crate::tls::connect(cfg, name, tcp).await?;

    let (send_req, conn) = h2::client::handshake(tls).await.map_err(other)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{host}{path}"))
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        // RFC 8484 не требует, но публичные резолверы отвергают POST без длины тела.
        .header("content-length", query.len().to_string())
        .body(())
        .map_err(other)?;

    let mut sr = send_req.ready().await.map_err(other)?;
    let (resp_fut, mut body) = sr.send_request(req, false).map_err(other)?;
    send_body(&mut body, query).await?;
    let resp = resp_fut.await.map_err(other)?;
    if !resp.status().is_success() {
        return Err(bad(format!("резолвер ответил {}", resp.status())));
    }
    read_body(resp.into_body()).await
}

/// Забрать ECHConfigList носителя для `domain` через DoH-резолвер.
///
/// `Ok(None)` — у домена нет ECH (не ошибка). `roots` должен содержать публичные
/// корни, чтобы проверить сертификат резолвера.
pub async fn fetch_ech_config_list(
    roots: RootCertStore,
    resolver_url: &str,
    domain: &str,
) -> std::io::Result<Option<Vec<u8>>> {
    let query = build_https_query(domain)?;
    let response = doh_exchange(roots, resolver_url, &query).await?;
    extract_ech(&response)
}

/// Тип для читаемости в сигнатурах, если понадобится передавать готовое тело.
pub type DnsMessage = Arc<Bytes>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_has_expected_shape() {
        let q = build_https_query("example.com").unwrap();
        assert_eq!(&q[0..2], &[0, 0], "ID=0 для кэшируемости DoH");
        assert_eq!(&q[2..4], &[0x01, 0x00], "RD=1");
        assert_eq!(&q[4..6], &[0, 1], "QDCOUNT=1");
        // QNAME
        assert_eq!(&q[12..13], &[7]);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(&q[20..21], &[3]);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(&q[24..25], &[0]);
        // QTYPE=65, QCLASS=1
        assert_eq!(&q[25..27], &[0, 65]);
        assert_eq!(&q[27..29], &[0, 1]);
    }

    #[test]
    fn rejects_bad_domain_labels() {
        assert!(build_https_query("").is_err());
        assert!(build_https_query("a..b").is_err());
    }

    #[test]
    fn splits_resolver_url() {
        assert_eq!(
            split_resolver("https://cloudflare-dns.com/dns-query").unwrap(),
            ("cloudflare-dns.com".to_string(), "/dns-query".to_string())
        );
        assert_eq!(
            split_resolver("https://dns.example").unwrap(),
            ("dns.example".to_string(), "/dns-query".to_string())
        );
        assert!(split_resolver("http://insecure/dns-query").is_err());
    }

    /// Собрать ответ DNS с одной HTTPS RR, несущей параметр `ech`.
    fn fixture_response(ech: &[u8], with_pointer_name: bool) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[0, 0]); // ID
        m.extend_from_slice(&[0x81, 0x80]); // ответ, RCODE=0
        m.extend_from_slice(&[0, 1]); // QDCOUNT
        m.extend_from_slice(&[0, 1]); // ANCOUNT
        m.extend_from_slice(&[0, 0, 0, 0]); // NS/AR
        // вопрос: example.com HTTPS IN
        encode_name("example.com", &mut m).unwrap();
        m.extend_from_slice(&[0, 65, 0, 1]);
        // ответ: имя (указатель или полное), TYPE=65, CLASS=IN, TTL, RDLENGTH, RDATA
        if with_pointer_name {
            m.extend_from_slice(&[0xC0, 0x0C]); // сжатый указатель на вопрос
        } else {
            encode_name("example.com", &mut m).unwrap();
        }
        m.extend_from_slice(&[0, 65]); // TYPE=HTTPS
        m.extend_from_slice(&[0, 1]); // CLASS=IN
        m.extend_from_slice(&[0, 0, 0, 60]); // TTL

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&[0, 1]); // priority=1 (ServiceMode)
        rdata.push(0); // TargetName = "." (сам владелец)
        rdata.extend_from_slice(&[0, 1]); // key=1 (alpn)
        rdata.extend_from_slice(&[0, 3]); // len
        rdata.extend_from_slice(&[2, b'h', b'2']); // alpn-list
        rdata.extend_from_slice(&SVCPARAM_ECH.to_be_bytes()); // key=5 (ech)
        rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(ech);

        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&rdata);
        m
    }

    #[test]
    fn extracts_ech_with_compressed_name() {
        let ech = b"\xfe\x0d\x00\x41fake-ech-config-list";
        let msg = fixture_response(ech, true);
        assert_eq!(extract_ech(&msg).unwrap().as_deref(), Some(&ech[..]));
    }

    #[test]
    fn extracts_ech_with_full_name() {
        let ech = b"ech-bytes";
        let msg = fixture_response(ech, false);
        assert_eq!(extract_ech(&msg).unwrap().as_deref(), Some(&ech[..]));
    }

    #[test]
    fn no_ech_param_is_none_not_error() {
        // Ответ без параметра ech: RDATA только с alpn.
        let mut m = Vec::new();
        m.extend_from_slice(&[0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        encode_name("example.com", &mut m).unwrap();
        m.extend_from_slice(&[0, 65, 0, 1]);
        m.extend_from_slice(&[0xC0, 0x0C, 0, 65, 0, 1, 0, 0, 0, 60]);
        let rdata = [0, 1, 0, 0, 1, 0, 3, 2, b'h', b'2'];
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&rdata);
        assert_eq!(extract_ech(&m).unwrap(), None);
    }

    #[test]
    fn nonzero_rcode_is_error() {
        let mut m = vec![0, 0, 0x81, 0x83]; // RCODE=3 (NXDOMAIN)
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(extract_ech(&m).is_err());
    }

    #[test]
    fn truncated_message_is_error_not_panic() {
        for cut in 0..12 {
            let msg = vec![0u8; cut];
            let _ = extract_ech(&msg); // не должно паниковать
        }
        let mut m = fixture_response(b"x", true);
        m.truncate(m.len() - 3);
        let _ = extract_ech(&m);
    }

    /// Живая проверка против публичного резолвера. Требует сети, поэтому `#[ignore]`:
    /// запускать вручную `cargo test -p vlyness-carrier --  --ignored doh_live`.
    #[tokio::test]
    #[ignore]
    async fn doh_live_fetch() {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let res = fetch_ech_config_list(roots, DEFAULT_DOH_RESOLVER, "crypto.cloudflare.com").await;
        match res {
            Ok(Some(list)) => {
                assert!(!list.is_empty());
                println!("ECHConfigList: {} байт", list.len());
                // Главное: добытый из DNS конфиг должен приниматься ECH-конфигурацией —
                // это замыкает цепочку DoH → настоящий ECH.
                let mut roots2 = RootCertStore::empty();
                roots2.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                crate::tls::client_config_ech(roots2, &list)
                    .expect("ECHConfigList из DNS должен приниматься rustls");
                println!("ECH-конфигурация собрана из полученного списка");
            }
            Ok(None) => println!("у домена нет ECH — тоже валидный исход"),
            Err(e) => panic!("DoH-запрос не удался: {e}"),
        }
    }
}
