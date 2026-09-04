//! Полный сетевой стек: реальный TCP + TLS 1.3 + HTTP/2, с сессией VLYNESS внутри
//! одного h2-стрима и honest-fallback для «зондов». AUTH переносится в cookie и служит
//! Noise-prologue.

use std::future::poll_fn;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::BytesMut;
use http::{Method, Request, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::RootCertStore;
use tokio::net::{TcpListener, TcpStream};

use vlyness_carrier::{
    client_segments, client_stream_one, serve, tls, H2Stream, ServerParams, SessionHandler,
};
use vlyness_core::address::{Addr, AddressFrame, Cmd};
use vlyness_core::noise::generate_keypair;
use vlyness_shaping::{LenDistribution, LenSampler};
use vlyness_transport::{MuxEvent, Session};

use std::sync::OnceLock;

const PSK: [u8; 32] = [7u8; 32];
const SITE_BODY: &[u8] = b"<!doctype html><title>Example Media</title><h1>hello from the site</h1>";
const TUNNEL_PATH: &str = "/v1/media/s/seg";

/// Единый самоподписанный серт на весь тест: `(цепочка сертов, PKCS#8-ключ DER)`.
/// Один и тот же для сервера (его сертификат) и для клиента (доверенный корень).
fn shared_cert() -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    static SHARED: OnceLock<(Vec<CertificateDer<'static>>, Vec<u8>)> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            (vec![ck.cert.der().clone()], ck.key_pair.serialize_der())
        })
        .clone()
}

/// Эхо-обработчик туннельной сессии.
fn echo_handler() -> SessionHandler {
    Arc::new(|mut s: Session<H2Stream>| {
        Box::pin(async move {
            loop {
                match s.recv_event().await {
                    Ok(MuxEvent::Data { stream_id, data }) => {
                        s.send_event(&MuxEvent::Data { stream_id, data }).await?;
                    }
                    Ok(MuxEvent::Close { .. }) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>
    })
}

/// Поднять сервер (accept-петля по TCP), вернуть адрес и публичный ключ сервера.
async fn spawn_server() -> (std::net::SocketAddr, Vec<u8>) {
    let (certs, key_der) = shared_cert();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let server_cfg = tls::server_config(certs, key).unwrap();
    let server = generate_keypair().unwrap();
    let server_pub = server.public.clone();

    let params = ServerParams {
        psk: PSK,
        server_priv: server.private.clone(),
        tunnel_path: TUNNEL_PATH.to_string(),
        site_body: bytes::Bytes::from_static(SITE_BODY),
        replay: Arc::new(std::sync::Mutex::new(vlyness_core::replay::ReplayGuard::new())),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let cfg = server_cfg.clone();
            let params = params.clone();
            let handler = echo_handler();
            tokio::spawn(async move {
                if let Ok(tls) = tls::accept(cfg, tcp).await {
                    let _ = serve(tls, params, handler).await;
                }
            });
        }
    });

    (addr, server_pub)
}

async fn connect_tls(addr: std::net::SocketAddr) -> tls::ClientTlsStream {
    let (certs, _key) = shared_cert();
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_cfg = tls::client_config(roots).unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    tls::connect(client_cfg, name, tcp).await.unwrap()
}

/// Сырой h2 GET — эмуляция зонда, проверяющего honest-fallback.
async fn probe(addr: std::net::SocketAddr, path: &str) -> (StatusCode, BytesMut) {
    let tls = connect_tls(addr).await;
    let (send_req, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut send_req = send_req.ready().await.unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://localhost{path}"))
        .body(())
        .unwrap();
    let (resp_fut, _send) = send_req.send_request(req, true).unwrap();
    let resp = resp_fut.await.unwrap();
    let status = resp.status();
    let mut body = resp.into_body();
    let mut data = BytesMut::new();
    while let Some(chunk) = poll_fn(|cx| body.poll_data(cx)).await {
        let c = chunk.unwrap();
        let _ = body.flow_control().release_capacity(c.len());
        data.extend_from_slice(&c);
    }
    (status, data)
}

#[tokio::test]
async fn tunnel_over_tls_h2_with_cookie_auth() {
    let (addr, server_pub) = spawn_server().await;
    let client = generate_keypair().unwrap();

    let tls = connect_tls(addr).await;
    let sampler = LenSampler::new(LenDistribution::media_abr_v1());
    let mut c = client_stream_one(
        tls,
        &PSK,
        &server_pub,
        &client.private,
        "localhost",
        TUNNEL_PATH,
        "ExampleMedia/3.2 (Android 14; okhttp/4.12)",
        Some(sampler),
    )
    .await
    .expect("туннель должен установиться");

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    c.send_event(&MuxEvent::Open(af)).await.unwrap();

    for payload in [b"ping".to_vec(), vec![0xEE; 3000], b"through-h2".to_vec()] {
        c.send_event(&MuxEvent::Data { stream_id: 1, data: payload.clone() })
            .await
            .unwrap();
        match c.recv_event().await.unwrap() {
            MuxEvent::Data { stream_id, data } => {
                assert_eq!(stream_id, 1);
                assert_eq!(data, payload);
            }
            other => panic!("ожидался эхо-Data, получено {other:?}"),
        }
    }
    c.send_event(&MuxEvent::Close { stream_id: 1 }).await.unwrap();
}

#[tokio::test]
async fn tunnel_over_segments_get_post() {
    // Режим segments: отдельные GET (download) и POST (upload), спариваемые по pid.
    let (addr, server_pub) = spawn_server().await;
    let client = generate_keypair().unwrap();

    let tls = connect_tls(addr).await;
    let sampler = LenSampler::new(LenDistribution::media_abr_v1());
    let mut c = client_segments(
        tls,
        &PSK,
        &server_pub,
        &client.private,
        "localhost",
        TUNNEL_PATH,
        "ExampleMedia/3.2 (Android 14; okhttp/4.12)",
        Some(sampler),
    )
    .await
    .expect("сегментный туннель должен установиться");

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    c.send_event(&MuxEvent::Open(af)).await.unwrap();

    for payload in [b"seg-ping".to_vec(), vec![0x5A; 3000]] {
        c.send_event(&MuxEvent::Data { stream_id: 1, data: payload.clone() })
            .await
            .unwrap();
        match c.recv_event().await.unwrap() {
            MuxEvent::Data { stream_id, data } => {
                assert_eq!(stream_id, 1);
                assert_eq!(data, payload);
            }
            other => panic!("ожидался эхо-Data, получено {other:?}"),
        }
    }
    c.send_event(&MuxEvent::Close { stream_id: 1 }).await.unwrap();
}

#[tokio::test]
async fn honest_fallback_serves_real_site() {
    let (addr, _server_pub) = spawn_server().await;

    // Зонд на корень сайта — не туннельный путь → настоящий сайт.
    let (status, body) = probe(addr, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], SITE_BODY);

    // Зонд GET-ом на сам туннельный путь (без POST, без cookie) → тоже сайт, не RST/404.
    let (status2, body2) = probe(addr, TUNNEL_PATH).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(&body2[..], SITE_BODY);
}
