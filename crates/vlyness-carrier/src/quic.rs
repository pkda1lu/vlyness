//! RTC/datagram-носитель: сессия внутри **HTTP/3 + WebTransport** поверх QUIC.
//!
//! Это самая стойкая по *форме* легенда из дизайна (док 02 §2, док 04 §3, этап 3):
//! наружу — обычный QUIC/UDP к :443 с H3 SETTINGS и WebTransport CONNECT, как у
//! видеозвонка или медиастрима в браузере. Внутри WebTransport-сессии открывается один
//! надёжный двунаправленный стрим, по которому байт-в-байт бежит та же
//! [`vlyness_transport::Session`], что и в h2-носителях. Ненадёжный datagram-канал QUIC
//! (media-форма) остаётся для следующего шага — здесь туннель едет по надёжному стриму,
//! чтобы TCP- и UDP-проброс работали без потерь.
//!
//! Аутентификация — та же единая легенда: токен кладётся в cookie CONNECT-запроса (§6.2)
//! и служит prologue Noise-хендшейка (§4). Сервер извлекает его из заголовков CONNECT,
//! проверяет (`authorize`, тег + окно эпох + анти-реплей) и берёт как prologue.
//! Honest-fallback: CONNECT без валидного токена (или на «не тот» путь) отклоняется
//! `404 Not Found` — ровно так настоящий WebTransport-медиасервер отвечает на неизвестную
//! сессию; зонд не отличает нас от него.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use url::Url;
use web_transport_quinn::proto::ConnectRequest;
use web_transport_quinn::{RecvStream, SendStream, Server, Session as WtSession};

use vlyness_core::auth::{epoch_now, AuthToken, PSK_LEN, TOKEN_LEN};
use vlyness_core::replay::ReplayGuard;
use vlyness_shaping::LenSampler;
use vlyness_transport::datagram::{channel as datagram_channel, Role, DGRAM_OVERHEAD};
use vlyness_transport::{DatagramLink, Session};

use crate::http::authorize_any;

/// Ёмкость очередей зашифрованных датаграмм между релеем и QUIC.
const DGRAM_QUEUE: usize = 256;

/// Поднять нативный datagram-канал поверх WebTransport-сессии: два насоса (наружу с
/// backpressure и внутрь) между mpsc-очередями зашифрованных датаграмм и QUIC. Ключи
/// datagram-канала выводятся из хеша хендшейка сессии (наследуют forward secrecy).
fn build_datagram_link(wt: &WtSession, handshake_hash: &[u8], role: Role) -> DatagramLink {
    let (sealer, opener) = datagram_channel(handshake_hash, role);
    let max_plaintext = wt.max_datagram_size().saturating_sub(DGRAM_OVERHEAD);

    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(DGRAM_QUEUE);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(DGRAM_QUEUE);

    // наружу: очередь → QUIC-датаграмма (send_datagram_wait даёт backpressure).
    let send_wt = wt.clone();
    tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if send_wt.send_datagram_wait(Bytes::from(bytes)).await.is_err() {
                break;
            }
        }
    });
    // внутрь: QUIC-датаграмма → очередь.
    let recv_wt = wt.clone();
    tokio::spawn(async move {
        while let Ok(b) = recv_wt.read_datagram().await {
            if in_tx.send(b.to_vec()).await.is_err() {
                break;
            }
        }
    });

    DatagramLink { outbound: out_tx, inbound: in_rx, sealer, opener, max_plaintext }
}

/// HTTP/3 ALPN — обязателен, чтобы QUIC согласовал H3 (и это же заявляет профиль RTC).
const ALPN_H3: &[u8] = b"h3";

fn other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Байтовый дуплекс поверх одного WebTransport-стрима: `AsyncRead` из [`RecvStream`],
/// `AsyncWrite` в [`SendStream`]. Держит саму WT-сессию (а на клиенте и quinn-endpoint)
/// живыми, пока жив стрим: их сброс закрыл бы QUIC-соединение под туннелем.
pub struct QuicStream {
    recv: RecvStream,
    send: SendStream,
    _session: WtSession,
    _endpoint: Option<quinn::Endpoint>,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// Клиентский quinn-config для QUIC: TLS 1.3, ALPN `h3`, доверие переданным корням.
fn client_config(roots: RootCertStore) -> std::io::Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN_H3.to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(other)?;
    Ok(quinn::ClientConfig::new(Arc::new(qcc)))
}

/// Клиент: установить туннель по HTTP/3 + WebTransport (режим `datagram`).
///
/// `server_addr` — куда реально коннектиться (`host:port`, обычно IP носителя),
/// `sni` — имя в TLS и `:authority` CONNECT (домен легенды). Разделение позволяет
/// ехать на co-tenant-IP, предъявляя разрешённое имя (whitelist §5).
#[allow(clippy::too_many_arguments)]
pub async fn client_datagram(
    roots: RootCertStore,
    server_addr: &str,
    sni: &str,
    tunnel_path: &str,
    psk: &[u8; PSK_LEN],
    server_pub: &[u8],
    client_priv: &[u8],
    user_agent: &str,
    sampler: Option<LenSampler>,
) -> std::io::Result<(Session<QuicStream>, DatagramLink)> {
    // Резолвим все адреса; IPv4 вперёд (серверы по умолчанию слушают 0.0.0.0), затем
    // пробуем каждый с таймаутом — переживаем домен с A+AAAA и dual-stack localhost.
    let mut remotes: Vec<SocketAddr> = tokio::net::lookup_host(server_addr).await?.collect();
    if remotes.is_empty() {
        return Err(other(format!("не резолвится {server_addr}")));
    }
    remotes.sort_by_key(|a| a.is_ipv6()); // false(IPv4) < true(IPv6)

    let cfg = client_config(roots)?;
    let mut last_err = other("нет адресов для подключения");
    let mut conn = None;
    for remote in remotes {
        let bind: SocketAddr = if remote.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let endpoint = match quinn::Endpoint::client(bind) {
            Ok(e) => e,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        let attempt = async {
            endpoint
                .connect_with(cfg.clone(), remote, sni)
                .map_err(other)?
                .await
                .map_err(other)
        };
        match tokio::time::timeout(std::time::Duration::from_secs(5), attempt).await {
            Ok(Ok(c)) => {
                conn = Some((endpoint, c));
                break;
            }
            Ok(Err(e)) => last_err = e,
            Err(_) => last_err = other(format!("таймаут подключения к {remote}")),
        }
    }
    let (endpoint, conn) = conn.ok_or(last_err)?;

    let token = AuthToken::build(psk, epoch_now());
    let auth_raw = token.raw();
    let cookie = format!("sid={}", token.encode());
    let url = Url::parse(&format!("https://{sni}{tunnel_path}")).map_err(other)?;
    let request = ConnectRequest::new(url)
        .with_header("cookie".parse().map_err(other)?, cookie.parse().map_err(other)?)
        .with_header("user-agent".parse().map_err(other)?, user_agent.parse().map_err(other)?);

    let wt = WtSession::connect(conn, request).await.map_err(other)?;
    let (send, recv) = wt.open_bi().await.map_err(other)?;
    let wt_for_dgram = wt.clone();
    let stream = QuicStream { recv, send, _session: wt, _endpoint: Some(endpoint) };

    let session = Session::connect(stream, server_pub, client_priv, &auth_raw, sampler).await?;
    let link = build_datagram_link(&wt_for_dgram, session.handshake_hash(), Role::Client);
    Ok((session, link))
}

/// Параметры серверного RTC-носителя.
#[derive(Clone)]
pub struct QuicServerParams {
    /// Активные PSK (keyring) — как у [`crate::ServerParams`].
    pub psks: crate::PskList,
    pub server_priv: Vec<u8>,
    /// Путь, по которому живёт туннель (иначе CONNECT отклоняется как чужой).
    pub tunnel_path: String,
    /// Общий на все соединения кэш анти-реплея (§3) — тот же, что у h2-носителя.
    pub replay: Arc<Mutex<ReplayGuard>>,
}

/// Обработчик установленной туннельной сессии (например, серверный релей к целям).
pub type QuicSessionHandler = Arc<
    dyn Fn(Session<QuicStream>, Option<DatagramLink>) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Построить серверный QUIC-endpoint (WebTransport) на `addr`: TLS 1.3, ALPN `h3`,
/// свой сертификат.
pub fn build_server(
    addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> std::io::Result<Server> {
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(other)?;
    crypto.alpn_protocols = vec![ALPN_H3.to_vec()];
    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(other)?;
    let config = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    let endpoint = quinn::Endpoint::server(config, addr)?;
    Ok(Server::new(endpoint))
}

/// Извлечь значение cookie `sid=` из заголовков CONNECT-запроса.
fn cookie_sid(req: &ConnectRequest) -> Option<String> {
    let cookie = req.headers.get("cookie")?.to_str().ok()?;
    cookie
        .split(';')
        .find_map(|kv| kv.trim().strip_prefix("sid="))
        .map(|s| s.to_string())
}

/// Обслужить один WebTransport-CONNECT: авторизовать по cookie и пути, принять сессию
/// и отдать её обработчику. Всё, что не прошло, отклоняется `404` (honest-fallback).
async fn handle_request(
    request: web_transport_quinn::Request,
    params: Arc<QuicServerParams>,
    handler: QuicSessionHandler,
) -> std::io::Result<()> {
    let path_ok = request.url.path() == params.tunnel_path;
    let auth_raw: Option<[u8; TOKEN_LEN]> = if path_ok {
        let psks = params.psks.lock().expect("PskList mutex").clone();
        cookie_sid(&request).and_then(|s| authorize_any(&s, &psks, &params.replay))
    } else {
        None
    };

    let Some(auth_raw) = auth_raw else {
        // Настоящий WT-медиасервер отвечает 404 на неизвестную сессию — так же и мы.
        let _ = request.reject(http::StatusCode::NOT_FOUND).await;
        return Ok(());
    };

    let session = request.ok().await.map_err(other)?;
    let (send, recv) = session.accept_bi().await.map_err(other)?;
    let wt_for_dgram = session.clone();
    let stream = QuicStream { recv, send, _session: session, _endpoint: None };

    let tsession = Session::accept(stream, &params.server_priv, &auth_raw, None).await?;
    let link = build_datagram_link(&wt_for_dgram, tsession.handshake_hash(), Role::Server);
    handler(tsession, Some(link)).await
}

/// Сервер: принимать WebTransport-сессии до завершения. Каждая обслуживается отдельной
/// задачей; авторизация — по cookie CONNECT (та же, что у h2), honest-fallback — `404`.
pub async fn serve_datagram(
    mut server: Server,
    params: QuicServerParams,
    handler: QuicSessionHandler,
) -> std::io::Result<()> {
    let params = Arc::new(params);
    while let Some(request) = server.accept().await {
        let params = params.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            let _ = handle_request(request, params, handler).await;
        });
    }
    Ok(())
}
