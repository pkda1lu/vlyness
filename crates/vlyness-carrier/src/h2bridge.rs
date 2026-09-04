//! Мост `AsyncRead + AsyncWrite` поверх одного двунаправленного HTTP/2-потока.
//!
//! HTTP/2 полнодуплексный: клиент может стримить тело запроса, пока сервер стримит
//! тело ответа. Пара `(SendStream, RecvStream)` одного h2-стрима образует байтовый
//! канал, внутри которого бежит [`vlyness_transport::Session`] (режим `stream-one`,
//! дизайн §5). Отдельные логические потоки VLYNESS мультиплексируются уже **внутри**
//! этого канала (mux), так что снаружи виден ровно один h2-стрим — не пачка соединений
//! (признак №5).
//!
//! Учёт flow-control: на чтении освобождаем оконную ёмкость по мере приёма; на записи
//! резервируем ёмкость и ждём её через `poll_capacity`.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Максимальный кусок за один `poll_write` (ограничивает копирования и резерв ёмкости).
const MAX_WRITE_CHUNK: usize = 16 * 1024;

/// Байтовый канал поверх одного h2-стрима.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    /// Остаток последнего принятого чанка, ещё не отданный читателю.
    read_buf: Bytes,
    /// Идёт ли ожидание ёмкости для текущей записи.
    reserving: bool,
}

impl H2Stream {
    pub fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        H2Stream { send, recv, read_buf: Bytes::new(), reserving: false }
    }
}

fn other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.read_buf.is_empty() {
            match me.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF: буфер остаётся пустым
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(other(e))),
                Poll::Ready(Some(Ok(data))) => {
                    // Вернуть оконную ёмкость отправителю на объём принятого.
                    let _ = me.recv.flow_control().release_capacity(data.len());
                    me.read_buf = data;
                }
            }
        }
        let n = me.read_buf.len().min(buf.remaining());
        buf.put_slice(&me.read_buf[..n]);
        me.read_buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !me.reserving {
            me.send.reserve_capacity(buf.len().min(MAX_WRITE_CHUNK));
            me.reserving = true;
        }
        match me.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "h2 send stream закрыт",
                )))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(other(e))),
            Poll::Ready(Some(Ok(cap))) => {
                me.reserving = false;
                let n = cap.min(buf.len());
                if n == 0 {
                    // Ёмкость ещё не выдана — ждать следующего пробуждения.
                    me.reserving = true;
                    return Poll::Pending;
                }
                let chunk = Bytes::copy_from_slice(&buf[..n]);
                match me.send.send_data(chunk, false) {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(other(e))),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // h2 буферизует и флашит на уровне соединения; отдельного flush нет.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        // Закрыть исходящую половину пустым DATA с end_of_stream.
        let _ = me.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}
