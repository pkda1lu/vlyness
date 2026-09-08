//! Мост `AsyncRead + AsyncWrite` поверх HTTP/2 — байтовый канал для сессии.
//!
//! HTTP/2 полнодуплексный, поэтому пара `(SendStream, RecvStream)` образует канал,
//! внутри которого бежит [`vlyness_transport::Session`]. Отдельные логические потоки
//! VLYNESS мультиплексируются уже **внутри** этого канала, так что снаружи виден один
//! h2-стрим — не пачка соединений (признак №5).
//!
//! Половины сделаны перечислениями, потому что режимы носителя дают разные источники:
//!
//! | режим | запись (вверх) | чтение (вниз) |
//! |---|---|---|
//! | `stream-one` / `segments` stream-up | h2 `SendStream` | h2 `RecvStream` |
//! | `segments` **packet-up**, клиент | канал → задача-загрузчик шлёт короткие POST'ы | h2 `RecvStream` (тело GET) |
//! | `segments` **packet-up**, сервер | h2 `SendStream` (тело GET) | канал ← пересобранные POST'ы |
//!
//! Packet-up нужен там, где носитель (CDN) не пропускает бесконечное тело запроса:
//! вместо одного длинного POST идёт череда коротких, как обычный XHR веб-приложения.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// Максимальный кусок за один `poll_write` в h2-режиме.
const MAX_WRITE_CHUNK: usize = 16 * 1024;

fn other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn broken(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, msg.to_string())
}

/// Источник входящих байтов.
enum Reader {
    /// Тело h2-ответа/запроса.
    Stream { recv: RecvStream, buf: Bytes },
    /// Канал с пересобранными по порядку кусками (сервер в режиме packet-up).
    Packets { rx: mpsc::UnboundedReceiver<Vec<u8>>, buf: Bytes },
}

/// Приёмник исходящих байтов.
enum Writer {
    /// Тело h2-запроса/ответа с учётом flow-control.
    Stream { send: SendStream<Bytes>, reserving: bool },
    /// Буфер + канал к задаче-загрузчику: каждый flush становится отдельным POST'ом
    /// (клиент в режиме packet-up). `PollSender` даёт настоящий backpressure.
    Packets { tx: PollSender<Vec<u8>>, buf: Vec<u8> },
}

/// Байтовый канал поверх HTTP/2.
pub struct H2Stream {
    reader: Reader,
    writer: Writer,
}

impl H2Stream {
    /// Обе половины — h2-стримы (`stream-one`, а также `segments` со stream-up).
    pub fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        H2Stream {
            reader: Reader::Stream { recv, buf: Bytes::new() },
            writer: Writer::Stream { send, reserving: false },
        }
    }

    /// Сервер в режиме packet-up: пишем в тело GET, читаем из канала пересобранных POST'ов.
    pub fn packet_up_server(send: SendStream<Bytes>, rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        H2Stream {
            reader: Reader::Packets { rx, buf: Bytes::new() },
            writer: Writer::Stream { send, reserving: false },
        }
    }

    /// Клиент в режиме packet-up: пишем в канал (задача-загрузчик шлёт POST'ы),
    /// читаем тело GET.
    pub fn packet_up_client(tx: mpsc::Sender<Vec<u8>>, recv: RecvStream) -> Self {
        H2Stream {
            reader: Reader::Stream { recv, buf: Bytes::new() },
            writer: Writer::Packets { tx: PollSender::new(tx), buf: Vec::new() },
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        match &mut me.reader {
            Reader::Stream { recv, buf } => {
                if buf.is_empty() {
                    match recv.poll_data(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                        Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(other(e))),
                        Poll::Ready(Some(Ok(data))) => {
                            // Вернуть оконную ёмкость отправителю на объём принятого.
                            let _ = recv.flow_control().release_capacity(data.len());
                            *buf = data;
                        }
                    }
                }
                let n = buf.len().min(out.remaining());
                out.put_slice(&buf[..n]);
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Reader::Packets { rx, buf } => {
                if buf.is_empty() {
                    match rx.poll_recv(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(None) => return Poll::Ready(Ok(())), // канал закрыт = EOF
                        Poll::Ready(Some(chunk)) => *buf = Bytes::from(chunk),
                    }
                }
                let n = buf.len().min(out.remaining());
                out.put_slice(&buf[..n]);
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match &mut me.writer {
            Writer::Stream { send, reserving } => {
                if !*reserving {
                    send.reserve_capacity(data.len().min(MAX_WRITE_CHUNK));
                    *reserving = true;
                }
                match send.poll_capacity(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(None) => Poll::Ready(Err(broken("h2 send stream закрыт"))),
                    Poll::Ready(Some(Err(e))) => Poll::Ready(Err(other(e))),
                    Poll::Ready(Some(Ok(cap))) => {
                        *reserving = false;
                        let n = cap.min(data.len());
                        if n == 0 {
                            *reserving = true;
                            return Poll::Pending;
                        }
                        match send.send_data(Bytes::copy_from_slice(&data[..n]), false) {
                            Ok(()) => Poll::Ready(Ok(n)),
                            Err(e) => Poll::Ready(Err(other(e))),
                        }
                    }
                }
            }
            // Копим в буфер; наружу уйдёт отдельным POST'ом на flush. Слой записей
            // (`record`) флашит после каждой записи, поэтому буфер не растёт бесконтрольно.
            Writer::Packets { buf, .. } => {
                buf.extend_from_slice(data);
                Poll::Ready(Ok(data.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        match &mut me.writer {
            // h2 буферизует и флашит на уровне соединения.
            Writer::Stream { .. } => Poll::Ready(Ok(())),
            Writer::Packets { tx, buf } => {
                if buf.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                // Backpressure: ждём места в очереди загрузчика.
                match tx.poll_reserve(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(_)) => Poll::Ready(Err(broken("загрузчик packet-up остановлен"))),
                    Poll::Ready(Ok(())) => {
                        let chunk = std::mem::take(buf);
                        match tx.send_item(chunk) {
                            Ok(()) => Poll::Ready(Ok(())),
                            Err(_) => Poll::Ready(Err(broken("загрузчик packet-up остановлен"))),
                        }
                    }
                }
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Сначала дослать накопленное, затем закрыть исходящую половину.
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let me = self.get_mut();
        match &mut me.writer {
            Writer::Stream { send, .. } => {
                let _ = send.send_data(Bytes::new(), true);
            }
            Writer::Packets { tx, .. } => tx.close(),
        }
        Poll::Ready(Ok(()))
    }
}
