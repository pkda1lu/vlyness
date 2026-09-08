//! Измерение «неотличимости» на РЕАЛЬНОЙ сессии (док 04 §2).
//!
//! Мы инструментируем исходящий поток клиента обёрткой [`RecordTap`], которая разбирает
//! `[u16 len]`-фрейминг записей — то же, что делал бы DPI, парсящий TLS-записи, — и
//! собирает размеры. Затем сравниваем распределение размеров с легендой (KS-тест).
//!
//! Это честный измеритель: он и подтверждает, что shaping приближает трафик к легенде,
//! и вскрывает, где ломается (bulk-перекачка уводит размеры записей далеко от легенды).

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use vlyness_core::noise::generate_keypair;
use vlyness_metrics::{ks_two_sample, LegendModel};
use vlyness_shaping::{LenDistribution, LenSampler};
use vlyness_transport::{MuxEvent, Session};

use vlyness_core::address::{Addr, AddressFrame, Cmd};
use std::net::Ipv4Addr;

const AUTH: &[u8; 44] = &[0x5a; 44];

/// Оверхед AEAD-тега на запись (Noise ChaCha20-Poly1305). Наблюдаемый размер записи =
/// plaintext + 16, а легенда задана в plaintext-размерах. Это смещение — common-mode
/// (у легенды поверх TLS тег тоже есть), не сигнал детекта, поэтому при сравнении
/// приводим легенду к наблюдаемой шкале (+16), а не оставляем ложный сдвиг.
const AEAD_TAG: f64 = 16.0;

fn to_observed_scale(legend: &[f64]) -> Vec<f64> {
    legend.iter().map(|x| x + AEAD_TAG).collect()
}

/// Разбирает `[u16 len][body]`-фрейминг из исходящего потока и копит размеры тел записей.
#[derive(Default)]
struct RecordParser {
    hdr: Vec<u8>,
    remaining: usize,
    have_len: bool,
    sizes: Vec<usize>,
}

impl RecordParser {
    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if !self.have_len {
                self.hdr.push(bytes[0]);
                bytes = &bytes[1..];
                if self.hdr.len() == 2 {
                    self.remaining = u16::from_be_bytes([self.hdr[0], self.hdr[1]]) as usize;
                    self.hdr.clear();
                    self.have_len = true;
                    self.sizes.push(self.remaining); // длина тела записи
                    if self.remaining == 0 {
                        self.have_len = false; // пустая запись завершена
                    }
                }
            } else {
                let take = bytes.len().min(self.remaining);
                bytes = &bytes[take..];
                self.remaining -= take;
                if self.remaining == 0 {
                    self.have_len = false;
                }
            }
        }
    }
}

/// Обёртка потока, регистрирующая размеры исходящих записей.
struct RecordTap<S> {
    inner: S,
    parser: Arc<Mutex<RecordParser>>,
}

impl<S> RecordTap<S> {
    fn new(inner: S) -> (Self, Arc<Mutex<RecordParser>>) {
        let parser = Arc::new(Mutex::new(RecordParser::default()));
        (RecordTap { inner, parser: parser.clone() }, parser)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordTap<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordTap<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Считаем только реально записанные байты (poll_write может принять меньше).
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.parser.lock().unwrap().feed(&buf[..n]);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Сервер, только поглощающий события (эхо для замера размеров не нужно).
async fn drain_server(io: tokio::io::DuplexStream, server_priv: Vec<u8>) {
    let mut s = Session::accept(io, &server_priv, AUTH, None).await.unwrap();
    loop {
        match s.recv_event().await {
            Ok(MuxEvent::Close { .. }) | Err(_) => break,
            Ok(_) => {} // поглощаем; downlink пуст → нет обратного давления
        }
    }
}

/// Прогнать клиентскую сессию и вернуть размеры исходящих записей транспорт-режима.
/// `shaped` — включён ли sampler; `bulk` — крупные payload'ы вместо мелких сообщений.
///
/// Сервер только поглощает: нам нужны исходящие размеры (их ловит tap), а не эхо.
async fn capture_outbound_sizes(shaped: bool, bulk: bool) -> Vec<f64> {
    let server = generate_keypair().unwrap();
    let client = generate_keypair().unwrap();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_priv = server.private.clone();
    let srv = tokio::spawn(drain_server(server_io, server_priv));

    let (tap, parser) = RecordTap::new(client_io);
    let sampler = shaped.then(|| LenSampler::new(LenDistribution::media_abr_v1()));
    let mut c = Session::connect(tap, &server.public, &client.private, AUTH, sampler)
        .await
        .unwrap();

    // Отбрасываем записи хендшейка — измеряем именно transport-режим.
    parser.lock().unwrap().sizes.clear();

    let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::LOCALHOST));
    c.send_event(&MuxEvent::Open(af)).await.unwrap();

    if bulk {
        // Крупная перекачка: 300 КБ — как загрузка файла (одним большим Data).
        c.send_event(&MuxEvent::Data { stream_id: 1, data: vec![0xABu8; 300_000] })
            .await
            .unwrap();
    } else {
        // Интерактив: много мелких сообщений (каждое → одна запись).
        for i in 0u32..500 {
            let msg = format!("m{i}").into_bytes();
            c.send_event(&MuxEvent::Data { stream_id: 1, data: msg }).await.unwrap();
        }
    }

    c.send_event(&MuxEvent::Close { stream_id: 1 }).await.unwrap();
    drop(c); // закрываем uplink → сервер видит конец
    srv.await.unwrap();

    let sizes = parser.lock().unwrap().sizes.clone();
    sizes.into_iter().map(|s| s as f64).collect()
}

#[tokio::test]
async fn shaping_moves_traffic_toward_legend() {
    let legend = to_observed_scale(&LegendModel::media().sample_record_sizes(4000, 42));

    let shaped = capture_outbound_sizes(true, false).await;
    let unshaped = capture_outbound_sizes(false, false).await;

    let ks_shaped = ks_two_sample(&shaped, &legend);
    let ks_unshaped = ks_two_sample(&unshaped, &legend);

    eprintln!(
        "интерактив: KS(shaped,legend)={ks_shaped:.3}  KS(unshaped,legend)={ks_unshaped:.3}  \
         (записей: shaped={}, unshaped={})",
        shaped.len(),
        unshaped.len()
    );

    // Без shaping записи крошечные (только оверхед) → далеко от медиа-легенды.
    assert!(ks_unshaped > 0.6, "unshaped должен быть явно отличим, KS={ks_unshaped}");
    // Shaping приближает к легенде — заметно ближе, чем без него.
    assert!(
        ks_shaped < ks_unshaped - 0.3,
        "shaping должен заметно приближать к легенде: shaped={ks_shaped}, unshaped={ks_unshaped}"
    );
}

#[tokio::test]
async fn bulk_transfer_also_matches_legend() {
    // Ранее harness вскрыл зазор: bulk давал записи payload-driven, чуждые легенде.
    // После фикса (shaping режет крупные кадры до целевых размеров, plan_shaped_records)
    // bulk-перекачка тоже ложится на распределение легенды — измеримо это подтверждаем.
    let legend = to_observed_scale(&LegendModel::media().sample_record_sizes(4000, 7));

    let shaped_small = capture_outbound_sizes(true, false).await;
    let shaped_bulk = capture_outbound_sizes(true, true).await;

    let ks_small = ks_two_sample(&shaped_small, &legend);
    let ks_bulk = ks_two_sample(&shaped_bulk, &legend);

    eprintln!(
        "shaped интерактив KS={ks_small:.3}  shaped bulk KS={ks_bulk:.3}  (bulk-записей: {})",
        shaped_bulk.len()
    );

    // Фрагментация до целевых размеров держит bulk близко к легенде — не хуже, чем
    // интерактив, с небольшим запасом на дисперсию.
    assert!(
        ks_bulk < 0.22,
        "bulk после фикса должен быть близок к легенде, KS={ks_bulk}"
    );
    // 300 КБ при максимальном классе (~1453 полезных байт/запись) — не меньше ~206
    // записей; берём безопасную нижнюю границу. Смысл: дробится на сотни, а не единицы.
    assert!(
        shaped_bulk.len() > 200,
        "300 КБ должны раздробиться на сотни записей легенды, получено {}",
        shaped_bulk.len()
    );
}
