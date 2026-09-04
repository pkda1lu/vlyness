//! Сессия: Noise-хендшейк поверх байтового потока, затем обмен запечатанными кадрами.
//!
//! Сессия **не зависит от носителя**: `S` — любой дуплексный поток (loopback-duplex
//! в тестах, TLS/HTTP-2 в бою). Это отражает сменность носителя из дизайна: carrier —
//! адаптер сверху, а сессионный протокол один и тот же.
//!
//! Исходящие кадры дополняются padding'ом до длины, выбранной sampler'ом длин (§8.1),
//! после чего запечатываются Noise-транспортом и уходят как запись `[len][ciphertext]`.

use std::sync::{Arc, Mutex};

use rand::rngs::StdRng;
use rand::SeedableRng;
use tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

use vlyness_core::frame::{Frame, FrameType, HEADER_LEN};
use vlyness_core::noise::{Initiator, Responder, Transport, MAX_PLAINTEXT};
use vlyness_shaping::{pad_to_target, LenSampler};

use crate::mux::{self, MuxEvent};
use crate::record::{read_record, write_record};

/// Порог перевыработки исходящего ключа в кадрах по умолчанию (§4, §6.3: 2^20).
pub const DEFAULT_REKEY_FRAMES: u64 = 1 << 20;

/// Максимум пользовательских данных в одном кадре StreamData. С запасом под заголовок
/// кадра, streamId и AEAD-тег/padding — далеко ниже лимита Noise-записи (65519).
pub const MAX_STREAM_CHUNK: usize = 16 * 1024;

/// Сессия поверх дуплексного потока `S`.
pub struct Session<S> {
    stream: S,
    transport: Transport,
    sampler: Option<LenSampler>,
    rng: StdRng,
    /// После скольких отправленных кадров перевыработать исходящий ключ.
    rekey_interval: u64,
    /// Счётчик отправленных кадров с последнего рекея.
    sent_frames: u64,
}

fn invalid<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// Выбор padding под целевую длину записи от sampler'а, с ограничением под лимит
/// Noise-записи. Общая логика для [`Session`] и [`SessionWriter`].
fn choose_pad(sampler: &mut Option<LenSampler>, rng: &mut StdRng, payload_len: usize) -> u16 {
    let Some(sampler) = sampler.as_mut() else {
        return 0;
    };
    let target = sampler.sample(rng);
    let pad = pad_to_target(payload_len, HEADER_LEN, target);
    let max_pad = MAX_PLAINTEXT.saturating_sub(HEADER_LEN + payload_len);
    pad.min(max_pad.min(u16::MAX as usize) as u16)
}

impl<S> Session<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Клиентское установление: initiator, 0-RTT payload пока пуст.
    pub async fn connect(
        mut stream: S,
        server_pub: &[u8],
        client_priv: &[u8],
        auth: &[u8],
        sampler: Option<LenSampler>,
    ) -> std::io::Result<Self> {
        let mut ini = Initiator::new(server_pub, client_priv, auth).map_err(invalid)?;
        let msg1 = ini.write_msg1(b"").map_err(invalid)?;
        write_record(&mut stream, &msg1).await?;
        let msg2 = read_record(&mut stream).await?;
        let (transport, _p1) = ini.read_msg2(&msg2).map_err(invalid)?;
        Ok(Session::wrap(stream, transport, sampler))
    }

    /// Серверное принятие: responder. `auth` сервер извлекает из cookie до хендшейка.
    pub async fn accept(
        mut stream: S,
        server_priv: &[u8],
        auth: &[u8],
        sampler: Option<LenSampler>,
    ) -> std::io::Result<Self> {
        let mut resp = Responder::new(server_priv, auth).map_err(invalid)?;
        let msg1 = read_record(&mut stream).await?;
        let _p0 = resp.read_msg1(&msg1).map_err(invalid)?;
        let (transport, msg2) = resp.write_msg2(b"").map_err(invalid)?;
        write_record(&mut stream, &msg2).await?;
        Ok(Session::wrap(stream, transport, sampler))
    }

    fn wrap(stream: S, transport: Transport, sampler: Option<LenSampler>) -> Self {
        Session {
            stream,
            transport,
            sampler,
            rng: StdRng::from_entropy(),
            rekey_interval: DEFAULT_REKEY_FRAMES,
            sent_frames: 0,
        }
    }

    /// Задать порог перевыработки исходящего ключа (кадров). Минимум 1.
    /// Используется в тестах, чтобы реально прогнать несколько рекеев.
    pub fn set_rekey_interval(&mut self, frames: u64) {
        self.rekey_interval = frames.max(1);
    }

    /// Отправить кадр ядра: выбрать padding, запечатать, записать. При достижении
    /// порога после отправки — перевыработать исходящий ключ (управляющим кадром Rekey).
    pub async fn send_frame(&mut self, frame: &Frame) -> std::io::Result<()> {
        self.seal_and_write(frame).await?;
        self.sent_frames += 1;
        if self.sent_frames >= self.rekey_interval {
            self.rekey_outgoing().await?;
        }
        Ok(())
    }

    /// Принять кадр ядра: прочитать запись, распечатать, разобрать. Управляющие кадры
    /// Rekey обрабатываются прозрачно (перевыработка входящего ключа) и не возвращаются.
    pub async fn recv_frame(&mut self) -> std::io::Result<Frame> {
        loop {
            let ciphertext = read_record(&mut self.stream).await?;
            let plaintext = self.transport.open(&ciphertext).map_err(invalid)?;
            let frame = Frame::decode(&plaintext).map_err(invalid)?;
            if frame.ftype == FrameType::Rekey {
                // Кадр Rekey был последним на старом ключе; дальше — новый.
                self.transport.rekey_incoming();
                continue;
            }
            return Ok(frame);
        }
    }

    /// Запечатать и записать один кадр (без учёта рекея).
    async fn seal_and_write(&mut self, frame: &Frame) -> std::io::Result<()> {
        let pad = self.choose_pad(frame.payload.len());
        let plaintext = frame.encode(pad).map_err(invalid)?;
        let ciphertext = self.transport.seal(&plaintext).map_err(invalid)?;
        write_record(&mut self.stream, &ciphertext).await
    }

    /// Отправить кадр Rekey (на старом ключе) и перевыработать исходящий ключ.
    async fn rekey_outgoing(&mut self) -> std::io::Result<()> {
        self.seal_and_write(&Frame::new(FrameType::Rekey, Vec::new())).await?;
        self.transport.rekey_outgoing();
        self.sent_frames = 0;
        Ok(())
    }

    /// Удобные обёртки на уровне мультиплексора.
    pub async fn send_event(&mut self, ev: &MuxEvent) -> std::io::Result<()> {
        self.send_frame(&mux::encode(ev)).await
    }

    pub async fn recv_event(&mut self) -> std::io::Result<MuxEvent> {
        let frame = self.recv_frame().await?;
        mux::decode(&frame).map_err(invalid)
    }

    /// Выбор padding под целевую длину записи от sampler'а.
    fn choose_pad(&mut self, payload_len: usize) -> u16 {
        choose_pad(&mut self.sampler, &mut self.rng, payload_len)
    }
}

impl<S> Session<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Разделить сессию на независимые половины чтения и записи для **полного дуплекса**.
    ///
    /// Реальный туннель качает данные в обе стороны одновременно (много логических
    /// потоков), что невозможно при `&mut self` на send и recv. Половины делят один
    /// [`Transport`] под `Mutex`, но блокировка держится только на синхронную крипто-
    /// операцию (seal/open) и **никогда через `.await`**, поэтому чтение и запись идут
    /// параллельно без взаимной блокировки.
    pub fn split(self) -> (SessionReader<ReadHalf<S>>, SessionWriter<WriteHalf<S>>) {
        let (read, write) = split(self.stream);
        let transport = Arc::new(Mutex::new(self.transport));
        let reader = SessionReader { read, transport: transport.clone() };
        let writer = SessionWriter {
            write,
            transport,
            sampler: self.sampler,
            rng: self.rng,
            rekey_interval: self.rekey_interval,
            sent_frames: 0,
        };
        (reader, writer)
    }
}

/// Половина чтения полнодуплексной сессии.
pub struct SessionReader<R> {
    read: R,
    transport: Arc<Mutex<Transport>>,
}

impl<R> SessionReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Принять кадр ядра; кадры Rekey обрабатываются прозрачно.
    pub async fn recv_frame(&mut self) -> std::io::Result<Frame> {
        loop {
            let ciphertext = read_record(&mut self.read).await?;
            // Блокировка только на синхронную распечатку, не через await.
            let plaintext = {
                let mut t = self.transport.lock().expect("Transport mutex не отравлен");
                t.open(&ciphertext).map_err(invalid)?
            };
            let frame = Frame::decode(&plaintext).map_err(invalid)?;
            if frame.ftype == FrameType::Rekey {
                self.transport.lock().expect("Transport mutex").rekey_incoming();
                continue;
            }
            return Ok(frame);
        }
    }

    pub async fn recv_event(&mut self) -> std::io::Result<MuxEvent> {
        let frame = self.recv_frame().await?;
        mux::decode(&frame).map_err(invalid)
    }
}

/// Половина записи полнодуплексной сессии.
pub struct SessionWriter<W> {
    write: W,
    transport: Arc<Mutex<Transport>>,
    sampler: Option<LenSampler>,
    rng: StdRng,
    rekey_interval: u64,
    sent_frames: u64,
}

impl<W> SessionWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Задать порог перевыработки исходящего ключа (кадров).
    pub fn set_rekey_interval(&mut self, frames: u64) {
        self.rekey_interval = frames.max(1);
    }

    /// Отправить кадр ядра; при достижении порога — перевыработать исходящий ключ.
    pub async fn send_frame(&mut self, frame: &Frame) -> std::io::Result<()> {
        self.seal_and_write(frame).await?;
        self.sent_frames += 1;
        if self.sent_frames >= self.rekey_interval {
            self.rekey_outgoing().await?;
        }
        Ok(())
    }

    pub async fn send_event(&mut self, ev: &MuxEvent) -> std::io::Result<()> {
        self.send_frame(&mux::encode(ev)).await
    }

    /// Отправить произвольно большой блок данных потока, разбив его на кадры StreamData
    /// не больше [`MAX_STREAM_CHUNK`]. Приёмная сторона просто читает Data-события по
    /// порядку и склеивает — для байтового потока это и есть сборка (§6).
    pub async fn send_stream_data(&mut self, stream_id: u16, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return self.send_event(&MuxEvent::Data { stream_id, data: Vec::new() }).await;
        }
        for chunk in data.chunks(MAX_STREAM_CHUNK) {
            self.send_event(&MuxEvent::Data { stream_id, data: chunk.to_vec() }).await?;
        }
        Ok(())
    }

    async fn seal_and_write(&mut self, frame: &Frame) -> std::io::Result<()> {
        let pad = choose_pad(&mut self.sampler, &mut self.rng, frame.payload.len());
        let plaintext = frame.encode(pad).map_err(invalid)?;
        let ciphertext = {
            let mut t = self.transport.lock().expect("Transport mutex не отравлен");
            t.seal(&plaintext).map_err(invalid)?
        };
        write_record(&mut self.write, &ciphertext).await
    }

    async fn rekey_outgoing(&mut self) -> std::io::Result<()> {
        self.seal_and_write(&Frame::new(FrameType::Rekey, Vec::new())).await?;
        self.transport.lock().expect("Transport mutex").rekey_outgoing();
        self.sent_frames = 0;
        Ok(())
    }
}
