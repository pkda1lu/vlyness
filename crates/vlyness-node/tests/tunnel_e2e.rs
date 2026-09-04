//! Сквозной прокси через весь стек VLYNESS.
//!
//! Топология:
//! ```text
//! [приложение] --duplex--> [TunnelClient] --TLS/h2 туннель--> [VLYNESS server]
//!                                                                    |
//!                                                        реальный TCP-connect
//!                                                                    v
//!                                                            [эхо-цель :port]
//! ```
//! Байты из приложения проходят весь путь до реальной TCP-цели и возвращаются эхом.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::RootCertStore;

use vlyness_carrier::{client_stream_one, serve, tls, ServerParams, SessionHandler, H2Stream};
use vlyness_core::address::Addr;
use vlyness_core::noise::generate_keypair;
use vlyness_core::replay::ReplayGuard;
use vlyness_node::{run_server_relay, TunnelClient};
use vlyness_shaping::{LenDistribution, LenSampler};
use vlyness_transport::Session;

const PSK: [u8; 32] = [0x24; 32];
const TUNNEL_PATH: &str = "/v1/media/s/seg";

fn shared_cert() -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    static SHARED: OnceLock<(Vec<CertificateDer<'static>>, Vec<u8>)> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            (vec![ck.cert.der().clone()], ck.key_pair.serialize_der())
        })
        .clone()
}

/// Простая TCP эхо-цель.
async fn spawn_echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

/// VLYNESS-сервер: TLS+h2, каждый туннель обслуживается серверным релеем.
async fn spawn_vlyness_server() -> (SocketAddr, Vec<u8>) {
    let (certs, key_der) = shared_cert();
    let server_cfg =
        tls::server_config(certs, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der))).unwrap();
    let server = generate_keypair().unwrap();
    let server_pub = server.public.clone();

    let params = ServerParams {
        psk: PSK,
        server_priv: server.private.clone(),
        tunnel_path: TUNNEL_PATH.to_string(),
        site_body: bytes::Bytes::from_static(b"<html>site</html>"),
        replay: Arc::new(std::sync::Mutex::new(ReplayGuard::new())),
    };

    let handler: SessionHandler = Arc::new(|session: Session<H2Stream>| {
        Box::pin(async move {
            let (reader, writer) = session.split();
            run_server_relay(reader, writer).await
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let cfg = server_cfg.clone();
            let params = params.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(tls) = tls::accept(cfg, tcp).await {
                    let _ = serve(tls, params, handler).await;
                }
            });
        }
    });
    (addr, server_pub)
}

async fn connect_client_tunnel(server_addr: SocketAddr, server_pub: &[u8]) -> Arc<TunnelClient> {
    let (certs, _key) = shared_cert();
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_cfg = tls::client_config(roots).unwrap();

    let tcp = TcpStream::connect(server_addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let tls = tls::connect(client_cfg, name, tcp).await.unwrap();

    let client_kp = generate_keypair().unwrap();
    let sampler = LenSampler::new(LenDistribution::media_abr_v1());
    let session = client_stream_one(
        tls,
        &PSK,
        server_pub,
        &client_kp.private,
        "localhost",
        TUNNEL_PATH,
        "ExampleMedia/3.2 (Android 14; okhttp/4.12)",
        Some(sampler),
    )
    .await
    .expect("туннель установлен");

    let (reader, writer) = session.split();
    let (client, _reader_done) = TunnelClient::start(reader, writer);
    client
}

#[tokio::test]
async fn end_to_end_tcp_through_tunnel() {
    let echo_addr = spawn_echo_target().await;
    let (server_addr, server_pub) = spawn_vlyness_server().await;
    let client = connect_client_tunnel(server_addr, &server_pub).await;

    // «Приложение» подключается через duplex; другой конец уходит в туннель к эхо-цели.
    let (mut app, tunnel_end) = tokio::io::duplex(64 * 1024);
    client
        .open(Addr::Ipv4(Ipv4Addr::LOCALHOST), echo_addr.port(), tunnel_end)
        .await
        .unwrap();

    // Небольшое сообщение проходит весь путь и возвращается эхом.
    app.write_all(b"hello vlyness").await.unwrap();
    let mut buf = [0u8; 13];
    app.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello vlyness");

    // Объём: 40 КБ туда-обратно, с фрагментацией по пути.
    let big: Vec<u8> = (0..40_000).map(|i| (i * 17 + 3) as u8).collect();
    app.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    app.read_exact(&mut got).await.unwrap();
    assert_eq!(got, big, "40 КБ должны пройти через туннель без искажений");
}

#[tokio::test]
async fn two_streams_multiplex_over_one_tunnel() {
    // Две независимые цели через ОДИН туннель (мультиплекс, признак №5).
    let echo_a = spawn_echo_target().await;
    let echo_b = spawn_echo_target().await;
    let (server_addr, server_pub) = spawn_vlyness_server().await;
    let client = connect_client_tunnel(server_addr, &server_pub).await;

    let (mut app_a, tun_a) = tokio::io::duplex(16 * 1024);
    let (mut app_b, tun_b) = tokio::io::duplex(16 * 1024);
    client.open(Addr::Ipv4(Ipv4Addr::LOCALHOST), echo_a.port(), tun_a).await.unwrap();
    client.open(Addr::Ipv4(Ipv4Addr::LOCALHOST), echo_b.port(), tun_b).await.unwrap();

    app_a.write_all(b"stream-A").await.unwrap();
    app_b.write_all(b"stream-B").await.unwrap();

    let mut ba = [0u8; 8];
    let mut bb = [0u8; 8];
    app_a.read_exact(&mut ba).await.unwrap();
    app_b.read_exact(&mut bb).await.unwrap();
    assert_eq!(&ba, b"stream-A");
    assert_eq!(&bb, b"stream-B");
}
