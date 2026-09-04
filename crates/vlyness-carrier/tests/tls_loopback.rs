//! Интеграция поверх РЕАЛЬНОГО TCP + TLS 1.3: сервер и клиент связываются на
//! эфемерном порту 127.0.0.1, устанавливают настоящий TLS-хендшейк (самоподписанный
//! сертификат), и внутри TLS бежит полная сессия VLYNESS (Noise → mux → эхо).

use std::net::Ipv4Addr;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::RootCertStore;
use tokio::net::{TcpListener, TcpStream};

use vlyness_carrier::tls;
use vlyness_core::address::{Addr, AddressFrame, Cmd};
use vlyness_core::noise::generate_keypair;
use vlyness_shaping::{LenDistribution, LenSampler};
use vlyness_transport::{MuxEvent, Session};

const AUTH: &[u8; 44] = &[0x5a; 44];

/// Самоподписанный сертификат для localhost + корневой стор, доверяющий ему.
fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, RootCertStore) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der: CertificateDer<'static> = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).unwrap();
    (vec![cert_der], key, roots)
}

#[tokio::test]
async fn session_over_real_tls_over_tcp() {
    let (certs, key, roots) = self_signed();
    let server_cfg = tls::server_config(certs, key).unwrap();
    let client_cfg = tls::client_config(roots).unwrap();

    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let server_pub = server.public.clone();
    let server_priv = server.private.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Сервер: принять TCP → TLS → сессию, отражать Data обратно.
    let srv = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await.unwrap();
        let tls = tls::accept(server_cfg, tcp).await.unwrap();
        let mut s = Session::accept(tls, &server_priv, AUTH, None).await.unwrap();
        let mut opened = 0usize;
        loop {
            match s.recv_event().await {
                Ok(MuxEvent::Open(_)) => opened += 1,
                Ok(MuxEvent::Data { stream_id, data }) => {
                    s.send_event(&MuxEvent::Data { stream_id, data }).await.unwrap();
                }
                Ok(MuxEvent::Close { .. }) => break,
                Ok(MuxEvent::KeepAlive) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("сервер: {e}"),
            }
        }
        opened
    });

    // Клиент: TCP → TLS → сессия с sampler'ом длин.
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let tls = tls::connect(client_cfg, name, tcp).await.unwrap();

    let sampler = LenSampler::new(LenDistribution::media_abr_v1());
    let mut c = Session::connect(tls, &server_pub, &client.private, AUTH, Some(sampler))
        .await
        .unwrap();

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    c.send_event(&MuxEvent::Open(af)).await.unwrap();

    for payload in [b"hello".to_vec(), vec![0xCD; 4096], b"over-tls".to_vec()] {
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

    let opened = srv.await.unwrap();
    assert_eq!(opened, 1, "сервер должен был увидеть одно открытие потока");
}

#[tokio::test]
async fn wrong_server_key_breaks_session_inside_tls() {
    // TLS устанавливается штатно, но статический ключ сервера у клиента неверный →
    // Noise-хендшейк ВНУТРИ TLS не сходится: TLS сам по себе нас не аутентифицирует.
    let (certs, key, roots) = self_signed();
    let server_cfg = tls::server_config(certs, key).unwrap();
    let client_cfg = tls::client_config(roots).unwrap();

    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let wrong = generate_keypair().unwrap(); // не тот статический ключ сервера
    let server_priv = server.private.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = tls::accept(server_cfg, tcp).await.unwrap();
        Session::accept(tls, &server_priv, AUTH, None).await.map(|_| ())
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let tls = tls::connect(client_cfg, name, tcp).await.unwrap();

    let res = Session::connect(tls, &wrong.public, &client.private, AUTH, None).await;
    assert!(res.is_err(), "сессия не должна установиться при неверном ключе сервера");
    let _ = srv.await.unwrap();
}

#[tokio::test]
async fn grease_ech_handshake_succeeds() {
    // Клиент шлёт GREASE-ECH ClientHello; сервер (без поддержки ECH) его игнорирует,
    // и обычная сессия внутри TLS проходит. Проверяем, что ECH-образный ClientHello
    // не ломает хендшейк.
    let (certs, key, roots) = self_signed();
    let server_cfg = tls::server_config(certs, key).unwrap();
    let client_cfg = tls::client_config_grease_ech(roots).unwrap();

    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let server_pub = server.public.clone();
    let server_priv = server.private.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = tls::accept(server_cfg, tcp).await.unwrap();
        let mut s = Session::accept(tls, &server_priv, AUTH, None).await.unwrap();
        loop {
            match s.recv_event().await {
                Ok(MuxEvent::Data { stream_id, data }) => {
                    s.send_event(&MuxEvent::Data { stream_id, data }).await.unwrap();
                }
                Ok(MuxEvent::Close { .. }) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let tls = tls::connect(client_cfg, name, tcp).await.unwrap();
    let mut c = Session::connect(tls, &server_pub, &client.private, AUTH, None).await.unwrap();

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::LOCALHOST));
    c.send_event(&MuxEvent::Open(af)).await.unwrap();
    c.send_event(&MuxEvent::Data { stream_id: 1, data: b"ech-grease".to_vec() }).await.unwrap();
    match c.recv_event().await.unwrap() {
        MuxEvent::Data { data, .. } => assert_eq!(data, b"ech-grease"),
        other => panic!("ожидался эхо-Data, получено {other:?}"),
    }
    c.send_event(&MuxEvent::Close { stream_id: 1 }).await.unwrap();
    srv.await.unwrap();
}

#[test]
fn ech_config_rejects_garbage() {
    // Настоящий ECH требует валидного ECHConfigList носителя; мусор отвергается.
    let (_certs, _key, roots) = self_signed();
    let res = tls::client_config_ech(roots, &[0x00, 0x00]);
    assert!(res.is_err(), "битый ECHConfigList должен быть отвергнут");
}
