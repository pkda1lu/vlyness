//! Интеграция клиент↔сервер по loopback-дуплексу: полный сессионный протокол
//! (Noise-хендшейк → мультиплексированные потоки → запечатанные записи) без TLS/сети.

use std::net::Ipv4Addr;

use vlyness_core::address::{Addr, AddressFrame, Cmd};
use vlyness_core::noise::generate_keypair;
use vlyness_shaping::{LenDistribution, LenSampler};
use vlyness_transport::{MuxEvent, Session};

const AUTH: &[u8; 44] = &[0x5a; 44];

/// Эхо-сервер: принимает сессию и отражает Data обратно тому же потоку.
async fn run_echo_server(
    io: tokio::io::DuplexStream,
    server_priv: Vec<u8>,
) -> std::io::Result<Vec<AddressFrame>> {
    let mut server = Session::accept(io, &server_priv, AUTH, None).await?;
    let mut opened = Vec::new();
    loop {
        match server.recv_event().await {
            Ok(MuxEvent::Open(af)) => opened.push(af),
            Ok(MuxEvent::Data { stream_id, data }) => {
                server.send_event(&MuxEvent::Data { stream_id, data }).await?;
            }
            Ok(MuxEvent::Close { .. }) => break,
            Ok(MuxEvent::KeepAlive) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(opened)
}

#[tokio::test]
async fn full_session_open_echo_close() {
    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_priv = server.private.clone();
    let srv = tokio::spawn(run_echo_server(server_io, server_priv));

    // Клиент с sampler'ом длин — исходящие записи дополняются под медиа-распределение.
    let sampler = LenSampler::new(LenDistribution::media_abr_v1());
    let mut c = Session::connect(client_io, &server.public, &client.private, AUTH, Some(sampler))
        .await
        .unwrap();

    // Открываем поток к цели.
    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    c.send_event(&MuxEvent::Open(af.clone())).await.unwrap();

    // Несколько сообщений разного размера — все должны вернуться эхом без искажений.
    for payload in [vec![b'a'; 5], vec![0xAB; 5000], b"vlyness".to_vec()] {
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

    let opened = srv.await.unwrap().unwrap();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0], af);
}

#[tokio::test]
async fn rekey_is_transparent_across_many_frames() {
    // Клиент перевырабатывает исходящий ключ каждые 3 кадра; сервер реагирует на
    // управляющие кадры Rekey. Все 20 сообщений должны пройти эхом без искажений.
    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_priv = server.private.clone();
    let srv = tokio::spawn(run_echo_server(server_io, server_priv));

    let mut c = Session::connect(client_io, &server.public, &client.private, AUTH, None)
        .await
        .unwrap();
    c.set_rekey_interval(3);

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(9, 9, 9, 9)));
    c.send_event(&MuxEvent::Open(af)).await.unwrap();

    for i in 0u32..20 {
        let payload = format!("msg-{i}").into_bytes();
        c.send_event(&MuxEvent::Data { stream_id: 1, data: payload.clone() })
            .await
            .unwrap();
        match c.recv_event().await.unwrap() {
            MuxEvent::Data { stream_id, data } => {
                assert_eq!(stream_id, 1);
                assert_eq!(data, payload, "сообщение {i} должно совпасть после рекеев");
            }
            other => panic!("ожидался эхо-Data, получено {other:?}"),
        }
    }
    c.send_event(&MuxEvent::Close { stream_id: 1 }).await.unwrap();
    srv.await.unwrap().unwrap();
}

#[tokio::test]
async fn full_duplex_concurrent_send_and_recv() {
    // Полный дуплекс: writer шлёт 50 сообщений НЕ дожидаясь эха каждого, а reader
    // собирает эхо параллельно в другой задаче. Непоследовательная сессия так не может.
    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_priv = server.private.clone();
    let srv = tokio::spawn(run_echo_server(server_io, server_priv));

    let c = Session::connect(client_io, &server.public, &client.private, AUTH, None)
        .await
        .unwrap();
    let (mut reader, mut writer) = c.split();

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    writer.send_event(&MuxEvent::Open(af)).await.unwrap();

    // Writer: залпом 50 сообщений, затем Close — в отдельной задаче.
    let writer_task = tokio::spawn(async move {
        for i in 0u32..50 {
            writer
                .send_event(&MuxEvent::Data { stream_id: 1, data: format!("m{i}").into_bytes() })
                .await
                .unwrap();
        }
        writer.send_event(&MuxEvent::Close { stream_id: 1 }).await.unwrap();
    });

    // Reader: параллельно собирает 50 эхо.
    let mut received = 0u32;
    while received < 50 {
        if let MuxEvent::Data { stream_id, .. } = reader.recv_event().await.unwrap() {
            assert_eq!(stream_id, 1);
            received += 1;
        }
    }
    assert_eq!(received, 50);

    writer_task.await.unwrap();
    srv.await.unwrap().unwrap();
}

#[tokio::test]
async fn large_stream_is_fragmented_and_reassembled() {
    // 100 КБ одним вызовом send_stream_data → несколько кадров StreamData; reader
    // склеивает их по порядку и получает исходные байты без искажений.
    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_priv = server.private.clone();
    let srv = tokio::spawn(run_echo_server(server_io, server_priv));

    let c = Session::connect(client_io, &server.public, &client.private, AUTH, None)
        .await
        .unwrap();
    let (mut reader, mut writer) = c.split();

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(4, 4, 4, 4)));
    writer.send_event(&MuxEvent::Open(af)).await.unwrap();

    // Детерминированные псевдослучайные 100 КБ.
    let big: Vec<u8> = (0..100_000).map(|i| (i * 31 + 7) as u8).collect();
    let expected = big.clone();

    let writer_task = tokio::spawn(async move {
        writer.send_stream_data(1, &big).await.unwrap();
        writer.send_event(&MuxEvent::Close { stream_id: 1 }).await.unwrap();
    });

    let mut assembled: Vec<u8> = Vec::new();
    while assembled.len() < expected.len() {
        if let MuxEvent::Data { stream_id, data } = reader.recv_event().await.unwrap() {
            assert_eq!(stream_id, 1);
            assembled.extend_from_slice(&data);
        }
    }
    assert_eq!(assembled, expected, "склеенный поток должен совпасть с исходным");

    writer_task.await.unwrap();
    srv.await.unwrap().unwrap();
}

#[tokio::test]
async fn wrong_auth_prologue_fails_handshake() {
    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let (client_io, server_io) = tokio::io::duplex(4096);

    // Сервер ждёт другой prologue (AUTH) — хендшейк не должен сойтись.
    let server_priv = server.private.clone();
    let srv = tokio::spawn(async move {
        let bad_auth = [0u8; 44];
        Session::accept(server_io, &server_priv, &bad_auth, None).await.map(|_| ())
    });

    let res = Session::connect(client_io, &server.public, &client.private, AUTH, None).await;
    assert!(res.is_err(), "клиент не должен установить сессию при несовпадении AUTH");
    // И серверная сторона тоже завершается ошибкой.
    assert!(srv.await.unwrap().is_err());
}
