//! Общие помощники для бинарников VLYNESS: чтение конфигурации из окружения и
//! TOML-файла, кодирование ключей/PSK в base64, работа с сертификатами.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;

pub mod admin;
pub mod client;
pub mod config;

/// Прочитать переменную окружения или значение по умолчанию.
pub fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Прочитать обязательную переменную окружения.
pub fn env_req(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("не задана обязательная переменная {key}"))
}

/// Опциональная переменная окружения.
pub fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim()).map_err(|e| format!("некорректный base64: {e}"))
}

/// Декодировать 32-байтовый PSK из base64.
pub fn decode_psk(s: &str) -> Result<[u8; 32], String> {
    let v = b64_decode(s)?;
    v.try_into().map_err(|_| "PSK должен быть ровно 32 байта".to_string())
}

/// Сгенерировать самоподписанный сертификат для домена: `(цепочка, ключ, PEM)`.
pub fn self_signed(
    domain: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String), String> {
    let ck = rcgen::generate_simple_self_signed(vec![domain.to_string()])
        .map_err(|e| format!("не удалось создать сертификат: {e}"))?;
    let cert_der = ck.cert.der().clone();
    let pem = ck.cert.pem();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    Ok((vec![cert_der], key, pem))
}

/// Загрузить корневой стор из PEM-файла с сертификатом сервера.
pub fn root_store_from_pem(path: &str) -> Result<RootCertStore, String> {
    let data = std::fs::read(path).map_err(|e| format!("не удалось прочитать {path}: {e}"))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| format!("ошибка разбора PEM: {e}"))?;
        roots.add(cert).map_err(|e| format!("не удалось добавить корень: {e}"))?;
    }
    if roots.is_empty() {
        return Err(format!("в {path} нет сертификатов"));
    }
    Ok(roots)
}

/// Загрузить цепочку сертификатов и приватный ключ из PEM-файлов (например, выданных
/// Let's Encrypt: `fullchain.pem` + `privkey.pem`). Ключ — первый найденный PKCS#8/RSA/SEC1.
pub fn load_cert_key_pem(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_data =
        std::fs::read(cert_path).map_err(|e| format!("не удалось прочитать {cert_path}: {e}"))?;
    let mut cr = std::io::BufReader::new(&cert_data[..]);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cr)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("ошибка разбора сертификата {cert_path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("в {cert_path} нет сертификатов"));
    }

    let key_data =
        std::fs::read(key_path).map_err(|e| format!("не удалось прочитать {key_path}: {e}"))?;
    let mut kr = std::io::BufReader::new(&key_data[..]);
    let key = rustls_pemfile::private_key(&mut kr)
        .map_err(|e| format!("ошибка разбора ключа {key_path}: {e}"))?
        .ok_or_else(|| format!("в {key_path} нет приватного ключа"))?;
    Ok((certs, key))
}

/// Публичные корни (webpki) — для носителей с сертификатами от публичных CA (CDN).
pub fn public_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Тип для удобной передачи серверной TLS-конфигурации.
pub type SharedServerConfig = Arc<rustls::ServerConfig>;
