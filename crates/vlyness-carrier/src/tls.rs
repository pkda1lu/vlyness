//! TLS 1.3 носитель поверх реального TCP (rustls + ring).
//!
//! Это внешний слой, который DPI видит первым: настоящий TLS 1.3 к нашему домену
//! (дизайн §4 — своя собственность, не подлог REALITY). `Session` из
//! `vlyness-transport` бежит **внутри** этого TLS как байтовый поток.
//!
//! Провайдер криптографии задаётся явно (`ring`), без опоры на process-global default,
//! и версия жёстко фиксирована TLS 1.3 — набор шифров сам по себе fingerprint (§1).
//!
//! Заметка об уровне: honest-fallback (§7) и перенос AUTH в HTTP-cookie (§6.2) — это
//! HTTP-уровень; он появится с адаптером HTTP/2 поверх этого TLS. Здесь AUTH задаётся
//! вне канала (как в тестах транспорта), а несущая доказывает интеграцию TCP+TLS+Session.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Серверный TLS-поток поверх TCP.
pub type ServerTlsStream = tokio_rustls::server::TlsStream<TcpStream>;
/// Клиентский TLS-поток поверх TCP.
pub type ClientTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Серверная конфигурация: TLS 1.3, без клиентских сертификатов, свой сертификат.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

/// Клиентская конфигурация: TLS 1.3, доверяем переданному набору корней.
pub fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, rustls::Error> {
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Клиентская конфигурация с **GREASE ECH** (анти-ossification, whitelist §5.2/§6).
///
/// Реального ECHConfig нет — клиент шлёт правдоподобную «пустышку» ECH, как это делают
/// браузеры для защиты от окостенения. Настоящий SNI при GREASE **не** шифруется, поэтому
/// это не решает WL-SNI (для этого нужен [`client_config_ech`] с конфигом носителя),
/// но делает ClientHello ECH-образным и работает против любого сервера.
pub fn client_config_grease_ech(roots: RootCertStore) -> Result<Arc<ClientConfig>, rustls::Error> {
    use rustls::client::{EchGreaseConfig, EchMode};
    use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

    let suite = *ALL_SUPPORTED_SUITES
        .first()
        .ok_or(rustls::Error::General("нет HPKE-сюит для ECH".into()))?;
    let (public_key, _secret) = suite.generate_key_pair()?;
    let grease = EchGreaseConfig::new(suite, public_key);

    let cfg = ClientConfig::builder_with_provider(provider())
        .with_ech(EchMode::Grease(grease))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Клиентская конфигурация с **настоящим ECH** (whitelist §5.2, док 05 §2.1).
///
/// `ech_config_list` — ECHConfigList носителя (CDN), обычно из DNS HTTPS RR. Внешний SNI
/// в ClientHello становится public-name носителя, настоящий SNI шифруется. Это и есть
/// путь co-tenancy сквозь WL-SNI. Требует ECH-совместимого фронта (CDN) на той стороне —
/// локально проверяется только сборка конфига, не хендшейк.
pub fn client_config_ech(
    roots: RootCertStore,
    ech_config_list: &[u8],
) -> Result<Arc<ClientConfig>, rustls::Error> {
    use rustls::client::{EchConfig, EchMode};
    use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    use rustls::pki_types::EchConfigListBytes;

    let ech = EchConfig::new(EchConfigListBytes::from(ech_config_list.to_vec()), ALL_SUPPORTED_SUITES)?;
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_ech(EchMode::Enable(ech))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Принять TLS-соединение на уже принятом TCP-сокете.
pub async fn accept(config: Arc<ServerConfig>, tcp: TcpStream) -> std::io::Result<ServerTlsStream> {
    TlsAcceptor::from(config).accept(tcp).await
}

/// Установить TLS-соединение к серверу с именем `server_name`.
pub async fn connect(
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    tcp: TcpStream,
) -> std::io::Result<ClientTlsStream> {
    TlsConnector::from(config).connect(server_name, tcp).await
}
