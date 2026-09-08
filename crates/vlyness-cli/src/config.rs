//! Конфигурация сервера из TOML-файла (`VLYNESS_CONFIG=path`).
//!
//! Файл убирает копипаст десятка переменных окружения при развёртывании на VPS.
//! Каждое поле имеет эквивалент в окружении (см. `bin/server.rs`); файл — основной
//! путь, окружение остаётся для точечных переопределений и обратной совместимости.

use serde::{Deserialize, Serialize};

/// Полная серверная конфигурация.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// TCP-адрес прослушивания (TLS 1.3 + HTTP/2), напр. `0.0.0.0:443`.
    pub bind: String,
    /// UDP-адрес для QUIC/HTTP-3/WebTransport (RTC-режим). Пусто — QUIC выключен.
    #[serde(default)]
    pub quic: Option<String>,
    /// Домен легенды (SNI сертификата).
    pub domain: String,
    /// Путь туннеля (всё прочее — honest-fallback / reject).
    pub tunnel_path: String,
    /// Общий секрет (32 байта, base64).
    pub psk_b64: String,
    /// Приватный статический ключ сервера (base64).
    pub server_priv_b64: String,
    /// Публичный статический ключ сервера (base64) — для сверки/удобства.
    pub server_pub_b64: String,
    /// PEM с цепочкой сертификатов (Let's Encrypt `fullchain.pem`). Пусто —
    /// самоподписанный на лету (только для теста).
    #[serde(default)]
    pub cert_pem: Option<String>,
    /// PEM с приватным ключом сертификата (`privkey.pem`).
    #[serde(default)]
    pub key_pem: Option<String>,
    /// Файл с телом «настоящего сайта» для honest-fallback. Пусто — встроенная заглушка.
    #[serde(default)]
    pub site_body_path: Option<String>,
}

impl ServerConfig {
    /// Загрузить и разобрать TOML.
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("не удалось прочитать конфиг {path}: {e}"))?;
        toml::from_str(&text).map_err(|e| format!("ошибка разбора {path}: {e}"))
    }

    /// Сериализовать в TOML (для генератора `vlyness-setup`).
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("ServerConfig сериализуется")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_roundtrip() {
        let cfg = ServerConfig {
            bind: "0.0.0.0:443".to_string(),
            quic: Some("0.0.0.0:443".to_string()),
            domain: "rtc.example.tld".to_string(),
            tunnel_path: "/v1/media/s/seg".to_string(),
            psk_b64: "AAAA".to_string(),
            server_priv_b64: "BBBB".to_string(),
            server_pub_b64: "CCCC".to_string(),
            cert_pem: Some("/etc/letsencrypt/live/rtc.example.tld/fullchain.pem".to_string()),
            key_pem: Some("/etc/letsencrypt/live/rtc.example.tld/privkey.pem".to_string()),
            site_body_path: None,
        };
        let text = cfg.to_toml();
        let back = toml::from_str::<ServerConfig>(&text).unwrap();
        assert_eq!(back.bind, cfg.bind);
        assert_eq!(back.quic, cfg.quic);
        assert_eq!(back.domain, cfg.domain);
        assert_eq!(back.cert_pem, cfg.cert_pem);
    }

    #[test]
    fn quic_optional_absent_is_none() {
        let text = r#"
            bind = "0.0.0.0:443"
            domain = "x.tld"
            tunnel_path = "/t"
            psk_b64 = "a"
            server_priv_b64 = "b"
            server_pub_b64 = "c"
        "#;
        let cfg: ServerConfig = toml::from_str(text).unwrap();
        assert!(cfg.quic.is_none());
        assert!(cfg.cert_pem.is_none());
    }
}
