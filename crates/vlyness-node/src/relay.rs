//! Движок релея: соединяет логические потоки мультиплексора с реальными TCP-сокетами.
//!
//! Актор-модель поверх полнодуплексной сессии ([`SessionReader`]/[`SessionWriter`]):
//! - **один writer-таск** владеет [`SessionWriter`] и мультиплексирует исходящие события
//!   из mpsc-канала (все потоки шлют в один туннель — признак №5);
//! - **один reader-таск** демультиплексирует входящие события по `streamId` в сокеты;
//! - **по два таска на поток**: сокет→туннель и туннель→сокет.
//!
//! Клиентский [`TunnelClient`] дополнительно:
//! - ведёт счётчики трафика [`TunnelStats`] (для blackhole-детектора в супервайзере);
//! - может гонять cadence-драйвер: при простое шлёт padding-кадры для постоянного
//!   ритма (idle-fill, §8.2).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::rngs::StdRng;
use rand::SeedableRng;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use vlyness_core::address::{Addr, AddressFrame, Cmd};
use vlyness_shaping::Cadence;
use vlyness_transport::{MuxEvent, SessionReader, SessionWriter, MAX_STREAM_CHUNK};

type Registry = Arc<Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>>;

/// Флаг «были реальные данные отправлены с прошлого тика cadence».
type Activity = Arc<AtomicBool>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Server,
    Client,
}

fn broken(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, msg.to_string())
}

/// Счётчики трафика туннеля (кумулятивные байты вверх/вниз). Читаются супервайзером
/// клиента для blackhole-детекции (§9): «шлём вверх, ответа вниз нет».
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

impl TunnelStats {
    pub fn new() -> Self {
        TunnelStats::default()
    }
    pub fn bytes_up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }
    pub fn bytes_down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }
    fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }
    fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Серверный релей: обслуживать сессию до её завершения (тело `SessionHandler`).
pub async fn run_server_relay<R, W>(
    reader: SessionReader<R>,
    writer: SessionWriter<W>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out_tx, out_rx) = mpsc::channel::<MuxEvent>(256);
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let activity: Activity = Arc::new(AtomicBool::new(false));
    let stats = TunnelStats::new();
    tokio::spawn(writer_loop(writer, out_rx));
    reader_loop(reader, registry, out_tx, Role::Server, activity, stats).await;
    Ok(())
}

/// Клиентский туннель: writer/reader в фоне, открытие потоков к целям, счётчики и cadence.
pub struct TunnelClient {
    outbound: mpsc::Sender<MuxEvent>,
    registry: Registry,
    next_id: AtomicU16,
    activity: Activity,
    stats: TunnelStats,
}

impl TunnelClient {
    /// Запустить клиентский релей поверх установленной сессии.
    ///
    /// Возвращает клиент и handle reader-таска: его завершение = туннель умер.
    pub fn start<R, W>(
        reader: SessionReader<R>,
        writer: SessionWriter<W>,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>)
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (out_tx, out_rx) = mpsc::channel::<MuxEvent>(256);
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let activity: Activity = Arc::new(AtomicBool::new(false));
        let stats = TunnelStats::new();
        tokio::spawn(writer_loop(writer, out_rx));
        let reader_done = tokio::spawn(reader_loop(
            reader,
            registry.clone(),
            out_tx.clone(),
            Role::Client,
            activity.clone(),
            stats.clone(),
        ));
        let client = Arc::new(TunnelClient {
            outbound: out_tx,
            registry,
            next_id: AtomicU16::new(1),
            activity,
            stats,
        });
        (client, reader_done)
    }

    /// Счётчики трафика (для blackhole-детектора).
    pub fn stats(&self) -> TunnelStats {
        self.stats.clone()
    }

    /// Открыть новый поток к `(addr, port)` и подключить локальный сокет `local`.
    pub async fn open<S>(&self, addr: Addr, port: u16, local: S) -> std::io::Result<u16>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let stream_id = self.next_id.fetch_add(2, Ordering::Relaxed);
        let af = AddressFrame::new(stream_id, Cmd::Tcp, port, addr);
        self.outbound
            .send(MuxEvent::Open(af))
            .await
            .map_err(|_| broken("туннель закрыт"))?;
        wire_stream(
            stream_id,
            local,
            self.outbound.clone(),
            self.registry.clone(),
            self.activity.clone(),
            self.stats.clone(),
        );
        Ok(stream_id)
    }

    /// Включить cadence-драйвер: при простое слать padding-кадры для постоянного ритма
    /// (idle-fill, §8.2). Реальные данные считаются активностью и подавляют лишний
    /// padding в этом тике.
    pub fn enable_cadence(&self, cadence: Cadence) {
        let tx = self.outbound.clone();
        let activity = self.activity.clone();
        tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();
            loop {
                let delay = cadence.next_delay_ms(&mut rng).max(1);
                tokio::time::sleep(Duration::from_millis(delay)).await;
                if !cadence.should_fill_idle() {
                    continue;
                }
                // Был ли реальный трафик с прошлого тика? swap читает и сбрасывает.
                if !activity.swap(false, Ordering::Relaxed)
                    && tx.send(MuxEvent::KeepAlive).await.is_err()
                {
                    break; // туннель закрыт
                }
            }
        });
    }
}

async fn writer_loop<W>(mut writer: SessionWriter<W>, mut rx: mpsc::Receiver<MuxEvent>)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    while let Some(ev) = rx.recv().await {
        if writer.send_event(&ev).await.is_err() {
            break;
        }
    }
}

async fn reader_loop<R>(
    mut reader: SessionReader<R>,
    registry: Registry,
    outbound: mpsc::Sender<MuxEvent>,
    role: Role,
    activity: Activity,
    stats: TunnelStats,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    loop {
        let ev = match reader.recv_event().await {
            Ok(ev) => ev,
            Err(_) => break,
        };
        match ev {
            MuxEvent::Open(af) if role == Role::Server => {
                let stream_id = af.stream_id;
                match connect_target(&af.addr, af.port).await {
                    Ok(sock) => wire_stream(
                        stream_id,
                        sock,
                        outbound.clone(),
                        registry.clone(),
                        activity.clone(),
                        stats.clone(),
                    ),
                    Err(_) => {
                        let _ = outbound.send(MuxEvent::Close { stream_id }).await;
                    }
                }
            }
            MuxEvent::Open(_) => {}
            MuxEvent::Data { stream_id, data } => {
                stats.add_down(data.len());
                let sink = registry.lock().expect("registry").get(&stream_id).cloned();
                if let Some(sink) = sink {
                    let _ = sink.send(data).await;
                }
            }
            MuxEvent::Close { stream_id } => {
                registry.lock().expect("registry").remove(&stream_id);
            }
            MuxEvent::KeepAlive => {}
        }
    }
    registry.lock().expect("registry").clear();
}

/// Подключить сокет к потоку: два таска (сокет→туннель и туннель→сокет).
fn wire_stream<S>(
    stream_id: u16,
    socket: S,
    outbound: mpsc::Sender<MuxEvent>,
    registry: Registry,
    activity: Activity,
    stats: TunnelStats,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = split(socket);
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(32);
    registry.lock().expect("registry").insert(stream_id, in_tx);

    // туннель→сокет
    tokio::spawn(async move {
        while let Some(chunk) = in_rx.recv().await {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    // сокет→туннель: помечаем активность и учитываем исходящие байты.
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_STREAM_CHUNK];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    let _ = outbound.send(MuxEvent::Close { stream_id }).await;
                    break;
                }
                Ok(n) => {
                    activity.store(true, Ordering::Relaxed);
                    stats.add_up(n);
                    let ev = MuxEvent::Data { stream_id, data: buf[..n].to_vec() };
                    if outbound.send(ev).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = outbound.send(MuxEvent::Close { stream_id }).await;
                    break;
                }
            }
        }
        registry.lock().expect("registry").remove(&stream_id);
    });
}

async fn connect_target(addr: &Addr, port: u16) -> std::io::Result<TcpStream> {
    match addr {
        Addr::Ipv4(ip) => TcpStream::connect((*ip, port)).await,
        Addr::Ipv6(ip) => TcpStream::connect((*ip, port)).await,
        Addr::Domain(d) => TcpStream::connect((d.as_str(), port)).await,
    }
}
