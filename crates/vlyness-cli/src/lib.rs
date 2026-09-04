//! Общие помощники для бинарников VLYNESS: чтение конфигурации из окружения,
//! кодирование ключей/PSK в base64, работа с сертификатами.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;

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

/// Тип для удобной передачи серверной TLS-конфигурации.
pub type SharedServerConfig = Arc<rustls::ServerConfig>;
