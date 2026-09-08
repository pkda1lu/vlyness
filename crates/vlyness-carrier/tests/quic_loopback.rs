//! Интеграция поверх РЕАЛЬНОГО QUIC + HTTP/3 + WebTransport: сервер и клиент связываются
//! на эфемерном UDP-порту 127.0.0.1, проходят настоящий QUIC-хендшейк (самоподписанный
//! сертификат) и WebTransport CONNECT, а внутри WT-стрима бежит полная сессия VLYNESS
//! (cookie-auth → Noise → mux → эхо). Это RTC/datagram-несущая (док 04, этап 3).

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use tokio::sync::mpsc;

use vlyness_carrier::quic::{
    build_server, client_datagram, serve_datagram, QuicServerParams, QuicSessionHandler, QuicStream,
};
use vlyness_core::address::{Addr, AddressFrame, Cmd};
use vlyness_core::noise::generate_keypair;
use vlyness_core::replay::ReplayGuard;
use vlyness_shaping::{LenDistribution, LenSampler};
use vlyness_transport::{MuxEvent, Session};

const PSK: [u8; 32] = [0x9a; 32];
const TUNNEL_PATH: &str = "/v1/media/s/seg";

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, RootCertStore) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der: CertificateDer<'static> = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).unwrap();
    (vec![cert_der], key, roots)
}

/// Отправить payload и собрать эхо по числу байт (shaping дробит крупные Data).
async fn echo_roundtrip(c: &mut Session<QuicStream>, payload: &[u8]) {
    c.send_event(&MuxEvent::Data { stream_id: 1, data: payload.to_vec() })
        .await
        .unwrap();
    let mut got = Vec::new();
    while got.len() < payload.len() {
        match c.recv_event().await.unwrap() {
            MuxEvent::Data { stream_id, data } => {
                assert_eq!(stream_id, 1);
                got.extend_from_slice(&data);
            }
            other => panic!("ожидался эхо-Data, получено {other:?}"),
        }
    }
    assert_eq!(got, payload);
}

/// Обработчик-эхо: отражает Data/Datagram, считает открытия потоков, репортит по Close.
fn echo_handler(report: mpsc::UnboundedSender<usize>) -> QuicSessionHandler {
    Arc::new(move |mut s: Session<QuicStream>| {
        let report = report.clone();
        Box::pin(async move {
            let mut opened = 0usize;
            loop {
                match s.recv_event().await {
                    Ok(MuxEvent::Open(_)) => opened += 1,
                    Ok(MuxEvent::Data { stream_id, data }) => {
                        s.send_event(&MuxEvent::Data { stream_id, data }).await?;
                    }
                    Ok(MuxEvent::Datagram { stream_id, data }) => {
                        s.send_event(&MuxEvent::Datagram { stream_id, data }).await?;
                    }
                    Ok(MuxEvent::Close { .. }) => break,
                    Ok(MuxEvent::KeepAlive) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(_) => break,
                }
            }
            let _ = report.send(opened);
            Ok(())
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>
    })
}

#[tokio::test]
async fn session_over_real_quic_webtransport() {
    let (certs, key, roots) = self_signed();
    let server = build_server("127.0.0.1:0".parse().unwrap(), certs, key).unwrap();
    let addr = server.local_addr().unwrap();

    let kp_server = generate_keypair().unwrap();
    let kp_client = generate_keypair().unwrap();
    let server_pub = kp_server.public.clone();

    let (tx, mut rx) = mpsc::unbounded_channel::<usize>();
    let params = QuicServerParams {
        psk: PSK,
        server_priv: kp_server.private.clone(),
        tunnel_path: TUNNEL_PATH.to_string(),
        replay: Arc::new(Mutex::new(ReplayGuard::new())),
    };
    tokio::spawn(serve_datagram(server, params, echo_handler(tx)));

    // Клиент: QUIC → H3 → WebTransport → сессия с sampler'ом длин.
    let sampler = LenSampler::new(LenDistribution::media_abr_v1());
    let mut c = client_datagram(
        roots,
        &format!("127.0.0.1:{}", addr.port()),
        "localhost",
        TUNNEL_PATH,
        &PSK,
        &server_pub,
        &kp_client.private,
        "ExampleRTC/1.0",
        Some(sampler),
    )
    .await
    .unwrap();

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    c.send_event(&MuxEvent::Open(af)).await.unwrap();

    for payload in [b"hello-rtc".to_vec(), vec![0xCD; 8192], b"over-quic".to_vec()] {
        echo_roundtrip(&mut c, &payload).await;
    }

    c.send_event(&MuxEvent::Close { stream_id: 1 }).await.unwrap();

    let opened = rx.recv().await.expect("сервер должен отрепортить");
    assert_eq!(opened, 1, "сервер должен был увидеть одно открытие потока");
}

#[tokio::test]
async fn wrong_psk_is_rejected_as_fallback() {
    // Неверный PSK → тег токена не проходит → сервер отклоняет CONNECT (honest-fallback
    // 404, как настоящий WT-медиасервер на неизвестную сессию). Клиент не устанавливается.
    let (certs, key, roots) = self_signed();
    let server = build_server("127.0.0.1:0".parse().unwrap(), certs, key).unwrap();
    let addr = server.local_addr().unwrap();

    let kp_server = generate_keypair().unwrap();
    let kp_client = generate_keypair().unwrap();
    let server_pub = kp_server.public.clone();

    let (tx, _rx) = mpsc::unbounded_channel::<usize>();
    let params = QuicServerParams {
        psk: PSK,
        server_priv: kp_server.private.clone(),
        tunnel_path: TUNNEL_PATH.to_string(),
        replay: Arc::new(Mutex::new(ReplayGuard::new())),
    };
    tokio::spawn(serve_datagram(server, params, echo_handler(tx)));

    let mut wrong_psk = PSK;
    wrong_psk[0] ^= 0xff;
    let res = client_datagram(
        roots,
        &format!("127.0.0.1:{}", addr.port()),
        "localhost",
        TUNNEL_PATH,
        &wrong_psk,
        &server_pub,
        &kp_client.private,
        "ExampleRTC/1.0",
        None,
    )
    .await;
    assert!(res.is_err(), "CONNECT с неверным PSK не должен установить сессию");
}
