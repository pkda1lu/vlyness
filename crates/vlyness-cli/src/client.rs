//! Клиентское ядро: установление туннеля, дисциплина, ротация носителей и локальный
//! SOCKS5 — вынесено из бинарника, чтобы этим управляли и консольный клиент, и GUI.
//!
//! Точка входа — [`run`] (бесконечный цикл дисциплины) либо [`Controller`] (обёртка со
//! своим tokio-рантаймом: `start`/`stop`/`status`/`logs` для GUI). Наблюдаемость идёт
//! через [`Reporter`]: состояние линка, текущий носитель, счётчики трафика, кольцевой
//! буфер лога.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::{sleep, timeout, Duration};

use vlyness_carrier::{
    client_datagram, client_segments, client_segments_packet_up, client_stream_one,
    fetch_ech_config_list, tls, DEFAULT_DOH_RESOLVER,
};
use vlyness_core::noise::generate_keypair;
use vlyness_discipline::backoff::Backoff;
use vlyness_discipline::blackhole::{AfterFreeze, BlackholeDetector, FreezeController};
use vlyness_discipline::budget::ConnectionBudget;
use vlyness_discipline::clock::{OsJitter, SystemClock};
use vlyness_discipline::{ConnectionManager, ManagerAction};
use vlyness_node::{
    accept as socks_accept, build_udp_header, parse_udp_header, reply as socks_reply, SocksRequest,
    TunnelClient, UdpSender, REP_SUCCESS,
};
use vlyness_profile::{validate, CarrierPool, Profile, TrafficMode};
use vlyness_shaping::{Cadence, LenDistribution, LenSampler};

use crate::{b64_decode, decode_psk, env_opt, env_or, env_req, public_roots, root_store_from_pem};

const MONITOR_TICK_MS: u64 = 2000;
/// Столько неудачных попыток подключения подряд к одному носителю — и он меняется.
const MAX_CONNECT_FAILURES: u32 = 3;
/// Сколько строк лога держим в кольцевом буфере для GUI.
const LOG_CAP: usize = 500;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Источник конфигурации клиента.
pub enum Source {
    /// Пул предзагруженных провалидированных профилей (whitelist §5.3). Основной путь GUI.
    Pool(Vec<Profile>),
    /// Одиночная конфигурация из переменных окружения (консольная обратная совместимость).
    Env,
}

/// Загрузить и провалидировать профиль из файла (отказ при несогласованной легенде, §1).
pub fn load_profile(path: &str) -> Result<Profile, String> {
    let json = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    parse_profile(&json).map_err(|e| format!("{path}: {e}"))
}

/// Разобрать и провалидировать профиль из JSON-строки (для импорта вставкой в GUI).
pub fn parse_profile(json: &str) -> Result<Profile, String> {
    let profile = Profile::from_json(json).map_err(|e| format!("разбор профиля: {e}"))?;
    if let Err(errs) = validate(&profile) {
        let codes: Vec<_> = errs.iter().map(|e| format!("{}: {}", e.code, e.message)).collect();
        return Err(format!("профиль '{}' некогерентен (§1): {}", profile.id, codes.join("; ")));
    }
    Ok(profile)
}

// ───────────────────────── Наблюдаемость ─────────────────────────

/// Состояние линка для UI.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkState {
    /// Ещё не начинали / остановлено пользователем.
    Idle,
    /// Идёт подключение.
    Connecting,
    /// Туннель установлен, трафик идёт.
    Up,
    /// Blackhole-детектор: тишина (§9).
    Frozen,
    /// Смена носителя.
    Switching,
    /// Остановлено.
    Stopped,
    /// Фатальная ошибка.
    Error,
}

impl LinkState {
    pub fn label(self) -> &'static str {
        match self {
            LinkState::Idle => "простаивает",
            LinkState::Connecting => "подключение",
            LinkState::Up => "подключено",
            LinkState::Frozen => "заморозка (blackhole)",
            LinkState::Switching => "смена носителя",
            LinkState::Stopped => "остановлено",
            LinkState::Error => "ошибка",
        }
    }
}

/// Снимок состояния клиента для UI.
#[derive(Clone, Debug)]
pub struct StatusSnapshot {
    pub state: LinkState,
    pub carrier_id: String,
    pub mode: String,
    pub socks_addr: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_error: Option<String>,
}

struct StatusInner {
    state: LinkState,
    carrier_id: String,
    mode: String,
    socks_addr: String,
    last_error: Option<String>,
    stats: Option<vlyness_node::TunnelStats>,
}

struct LogBuf {
    lines: VecDeque<(u64, String)>,
    next_seq: u64,
}

/// Разделяемый приёмник статуса и лога. Клонируется дёшево.
#[derive(Clone)]
pub struct Reporter {
    status: Arc<Mutex<StatusInner>>,
    log: Arc<Mutex<LogBuf>>,
    echo: bool,
}

impl Reporter {
    /// `echo` — дублировать лог в stderr (для консоли; GUI читает буфер и ставит `false`).
    pub fn new(echo: bool) -> Self {
        Reporter {
            status: Arc::new(Mutex::new(StatusInner {
                state: LinkState::Idle,
                carrier_id: String::new(),
                mode: String::new(),
                socks_addr: String::new(),
                last_error: None,
                stats: None,
            })),
            log: Arc::new(Mutex::new(LogBuf { lines: VecDeque::new(), next_seq: 0 })),
            echo,
        }
    }

    /// Добавить строку лога (и, если `echo`, вывести в stderr).
    pub fn log(&self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.echo {
            eprintln!("{msg}");
        }
        let mut b = self.log.lock().expect("log mutex");
        let seq = b.next_seq;
        b.next_seq += 1;
        b.lines.push_back((seq, msg));
        while b.lines.len() > LOG_CAP {
            b.lines.pop_front();
        }
    }

    fn set_state(&self, s: LinkState) {
        self.status.lock().expect("status mutex").state = s;
    }

    fn set_carrier(&self, id: &str, mode: &str, socks: &str) {
        let mut st = self.status.lock().expect("status mutex");
        st.carrier_id = id.to_string();
        st.mode = mode.to_string();
        st.socks_addr = socks.to_string();
    }

    fn set_stats(&self, stats: Option<vlyness_node::TunnelStats>) {
        self.status.lock().expect("status mutex").stats = stats;
    }

    fn set_error(&self, e: Option<String>) {
        self.status.lock().expect("status mutex").last_error = e;
    }

    /// Снимок текущего состояния (счётчики — из живого [`TunnelStats`], если линк поднят).
    pub fn snapshot(&self) -> StatusSnapshot {
        let st = self.status.lock().expect("status mutex");
        let (up, down) = st.stats.as_ref().map_or((0, 0), |s| (s.bytes_up(), s.bytes_down()));
        StatusSnapshot {
            state: st.state,
            carrier_id: st.carrier_id.clone(),
            mode: st.mode.clone(),
            socks_addr: st.socks_addr.clone(),
            bytes_up: up,
            bytes_down: down,
            last_error: st.last_error.clone(),
        }
    }

    /// Строки лога с порядковым номером ≥ `since`. Возвращает `(следующий since, строки)`.
    pub fn logs_since(&self, since: u64) -> (u64, Vec<String>) {
        let b = self.log.lock().expect("log mutex");
        let mut out = Vec::new();
        for (seq, line) in &b.lines {
            if *seq >= since {
                out.push(line.clone());
            }
        }
        (b.next_seq, out)
    }
}

// ───────────────────────── Параметры носителя ─────────────────────────

/// Режим несущей: форма трафика, которую видит DPI.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CarrierMode {
    StreamOne,
    Segments,
    PacketUp,
    Datagram,
}

impl CarrierMode {
    fn label(&self) -> &'static str {
        match self {
            CarrierMode::StreamOne => "stream-one",
            CarrierMode::Segments => "segments",
            CarrierMode::PacketUp => "segments/packet-up",
            CarrierMode::Datagram => "datagram (h3/webtransport)",
        }
    }
}

/// Разрешённые параметры подключения к одному носителю.
struct CarrierConn {
    id: String,
    client_cfg: Arc<ClientConfig>,
    roots: RootCertStore,
    server_addr: String,
    sni: String,
    psk: [u8; 32],
    server_pub: Vec<u8>,
    tunnel_path: String,
    ua: String,
    mode: CarrierMode,
    cadence: Cadence,
    budget: BudgetCfg,
}

#[derive(Clone, Copy)]
struct BudgetCfg {
    max_conns: u32,
    min_interval_ms: u64,
    backoff_base_ms: u64,
    backoff_cap_ms: u64,
}

impl Default for BudgetCfg {
    fn default() -> Self {
        BudgetCfg { max_conns: 1, min_interval_ms: 800, backoff_base_ms: 2000, backoff_cap_ms: 300_000 }
    }
}

fn build_manager(b: BudgetCfg) -> ConnectionManager<SystemClock, OsJitter> {
    ConnectionManager::new(
        SystemClock::new(),
        OsJitter,
        ConnectionBudget::new(
            b.max_conns,
            b.min_interval_ms,
            Backoff::new(b.backoff_base_ms, b.backoff_cap_ms),
        ),
        BlackholeDetector::with_defaults(),
        FreezeController::with_defaults(),
    )
}

/// Базовый путь туннеля из шаблона маршрута профиля.
fn base_path_from_route(route: &str) -> String {
    let head = route.split('{').next().unwrap_or(route);
    head.trim_end_matches('/').to_string()
}

/// Собрать параметры подключения из профиля с `endpoint` (режим пула).
async fn resolve_from_profile(p: &Profile, rep: &Reporter) -> Result<CarrierConn, BoxErr> {
    let ep = p.endpoint.as_ref().ok_or_else(|| format!("профиль '{}' без endpoint", p.id))?;

    let roots: RootCertStore = match &ep.ca_pem_path {
        Some(path) => root_store_from_pem(path)?,
        None => public_roots(),
    };
    let roots_for_quic = roots.clone();
    let client_cfg = match ep.ech_config_b64.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(cfg_b64) => {
            let list = b64_decode(cfg_b64)?;
            tls::client_config_ech(roots, &list)?
        }
        None if p.carrier.ech.enabled && p.carrier.ech.config_source == "dns-https-rr" => {
            let resolver = env_or("VLYNESS_DOH_RESOLVER", DEFAULT_DOH_RESOLVER);
            match fetch_ech_config_list(public_roots(), &resolver, &ep.sni).await {
                Ok(Some(list)) => {
                    rep.log(format!("[ech] '{}': ECHConfigList из DNS, {} байт", ep.sni, list.len()));
                    tls::client_config_ech(roots, &list)?
                }
                Ok(None) => {
                    rep.log(format!("[ech] у '{}' нет ECH в DNS — GREASE", ep.sni));
                    tls::client_config_grease_ech(roots)?
                }
                Err(e) => {
                    rep.log(format!("[ech] DoH не удался ({e}) — GREASE"));
                    tls::client_config_grease_ech(roots)?
                }
            }
        }
        None if p.carrier.ech.enabled => tls::client_config_grease_ech(roots)?,
        None => tls::client_config(roots)?,
    };

    Ok(CarrierConn {
        id: p.id.clone(),
        client_cfg,
        roots: roots_for_quic,
        server_addr: ep.server_addr.clone(),
        sni: ep.sni.clone(),
        psk: decode_psk(&ep.psk_b64)?,
        server_pub: b64_decode(&ep.server_pub_b64)?,
        tunnel_path: base_path_from_route(&p.http.routes.seg),
        ua: p.http.ua.clone(),
        mode: match (p.traffic.mode, p.traffic.packet_up) {
            (TrafficMode::Datagram, _) => CarrierMode::Datagram,
            (TrafficMode::Segments, true) => CarrierMode::PacketUp,
            (TrafficMode::Segments, false) => CarrierMode::Segments,
            _ => CarrierMode::StreamOne,
        },
        cadence: Cadence::new(
            p.traffic.seg_interval_ms.max(1000),
            p.traffic.seg_jitter_ms,
            p.traffic.idle_fill,
        ),
        budget: BudgetCfg {
            max_conns: p.budget.max_tls_conns,
            min_interval_ms: p.budget.min_conn_interval_ms,
            backoff_base_ms: p.budget.backoff_base_ms,
            backoff_cap_ms: p.budget.backoff_cap_ms,
        },
    })
}

/// Собрать параметры подключения из окружения (одиночный режим, консоль).
async fn resolve_from_env(rep: &Reporter) -> Result<CarrierConn, BoxErr> {
    let ca_path = env_req("VLYNESS_CA")?;
    let roots = root_store_from_pem(&ca_path)?;
    let roots_for_quic = roots.clone();
    let client_cfg = match (env_opt("VLYNESS_ECH_CONFIG_B64"), env_opt("VLYNESS_ECH")) {
        (Some(cfg_b64), _) => {
            let list = b64_decode(&cfg_b64)?;
            rep.log(format!("[tls] настоящий ECH (ECHConfigList {} байт)", list.len()));
            tls::client_config_ech(roots, &list)?
        }
        (None, Some(m)) if m == "doh" => {
            let domain = env_or("VLYNESS_SNI", "localhost");
            let resolver = env_or("VLYNESS_DOH_RESOLVER", DEFAULT_DOH_RESOLVER);
            match fetch_ech_config_list(public_roots(), &resolver, &domain).await {
                Ok(Some(list)) => {
                    rep.log(format!("[ech] '{domain}': ECHConfigList из DNS, {} байт", list.len()));
                    tls::client_config_ech(roots, &list)?
                }
                Ok(None) => {
                    rep.log(format!("[ech] у '{domain}' нет ECH в DNS — GREASE"));
                    tls::client_config_grease_ech(roots)?
                }
                Err(e) => {
                    rep.log(format!("[ech] DoH не удался ({e}) — GREASE"));
                    tls::client_config_grease_ech(roots)?
                }
            }
        }
        (None, Some(m)) if m == "grease" => {
            rep.log("[tls] GREASE-ECH");
            tls::client_config_grease_ech(roots)?
        }
        _ => tls::client_config(roots)?,
    };

    let profile = match env_opt("VLYNESS_PROFILE") {
        Some(path) => Some(load_profile(&path)?),
        None => None,
    };
    let (cadence, budget) = match &profile {
        Some(p) => (
            Cadence::new(
                p.traffic.seg_interval_ms.max(1000),
                p.traffic.seg_jitter_ms,
                p.traffic.idle_fill,
            ),
            BudgetCfg {
                max_conns: p.budget.max_tls_conns,
                min_interval_ms: p.budget.min_conn_interval_ms,
                backoff_base_ms: p.budget.backoff_base_ms,
                backoff_cap_ms: p.budget.backoff_cap_ms,
            },
        ),
        None => (Cadence::new(15_000, 3_000, true), BudgetCfg::default()),
    };

    Ok(CarrierConn {
        id: "env".to_string(),
        client_cfg,
        roots: roots_for_quic,
        server_addr: env_req("VLYNESS_SERVER_ADDR")?,
        sni: env_or("VLYNESS_SNI", "localhost"),
        psk: decode_psk(&env_req("VLYNESS_PSK_B64")?)?,
        server_pub: b64_decode(&env_req("VLYNESS_SERVER_PUB_B64")?)?,
        tunnel_path: env_or("VLYNESS_TUNNEL_PATH", "/v1/media/s/seg"),
        ua: env_or("VLYNESS_UA", "ExampleMedia/3.2 (Android 14; okhttp/4.12)"),
        mode: match env_or("VLYNESS_MODE", "stream").as_str() {
            "segments" => CarrierMode::Segments,
            "packet" => CarrierMode::PacketUp,
            "datagram" => CarrierMode::Datagram,
            _ => CarrierMode::StreamOne,
        },
        cadence,
        budget,
    })
}

/// Reference-пробер: без него blackhole-детектор остаётся в Suspect и не эскалирует.
fn spawn_reference_prober(addr: Option<String>) -> Option<Arc<AtomicBool>> {
    let addr = addr?;
    let ok = Arc::new(AtomicBool::new(false));
    let ok2 = ok.clone();
    tokio::spawn(async move {
        loop {
            let reachable = timeout(Duration::from_secs(3), TcpStream::connect(&addr))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            ok2.store(reachable, Ordering::Relaxed);
            sleep(Duration::from_secs(5)).await;
        }
    });
    Some(ok)
}

/// Установить один туннель: TCP → TLS(+ECH) → HTTP/2 (stream|segments) → сессия → релей,
/// либо QUIC/HTTP-3/WebTransport для datagram-режима.
async fn establish(
    c: &CarrierConn,
) -> std::io::Result<(Arc<TunnelClient>, tokio::task::JoinHandle<()>)> {
    if c.mode == CarrierMode::Datagram {
        let kp = generate_keypair()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let sampler = LenSampler::new(LenDistribution::media_abr_v1());
        let (session, link) = client_datagram(
            c.roots.clone(), &c.server_addr, &c.sni, &c.tunnel_path, &c.psk, &c.server_pub,
            &kp.private, &c.ua, Some(sampler),
        )
        .await?;
        let (reader, writer) = session.split();
        return Ok(TunnelClient::start(reader, writer, Some(link)));
    }

    let tcp = TcpStream::connect(&c.server_addr).await?;
    let name = ServerName::try_from(c.sni.clone())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "плохое имя SNI"))?;
    let tls_stream = tls::connect(c.client_cfg.clone(), name, tcp).await?;

    let kp = generate_keypair()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let sampler = LenSampler::new(LenDistribution::media_abr_v1());

    let session = match c.mode {
        CarrierMode::PacketUp => {
            client_segments_packet_up(
                tls_stream, &c.psk, &c.server_pub, &kp.private, &c.sni, &c.tunnel_path, &c.ua,
                Some(sampler),
            )
            .await?
        }
        CarrierMode::Segments => {
            client_segments(
                tls_stream, &c.psk, &c.server_pub, &kp.private, &c.sni, &c.tunnel_path, &c.ua,
                Some(sampler),
            )
            .await?
        }
        CarrierMode::StreamOne => {
            client_stream_one(
                tls_stream, &c.psk, &c.server_pub, &kp.private, &c.sni, &c.tunnel_path, &c.ua,
                Some(sampler),
            )
            .await?
        }
        CarrierMode::Datagram => unreachable!("datagram обработан выше"),
    };

    let (reader, writer) = session.split();
    Ok(TunnelClient::start(reader, writer, None))
}

/// Сменить носитель: текущий — в остывание, взять следующий по цене.
async fn rotate_carrier(
    pool: &mut Option<CarrierPool>,
    conn: &mut CarrierConn,
    mgr: &mut ConnectionManager<SystemClock, OsJitter>,
    now_ms: u64,
    rep: &Reporter,
) -> Result<(), BoxErr> {
    let Some(p) = pool else {
        return Ok(());
    };
    p.mark_failed(now_ms);
    match p.select(now_ms) {
        Some(next) => {
            let next = next.clone();
            *conn = resolve_from_profile(&next, rep).await?;
            *mgr = build_manager(conn.budget);
            rep.set_carrier(&conn.id, conn.mode.label(), &rep.snapshot().socks_addr);
            rep.log(format!("[pool] переключение на носитель '{}'", conn.id));
        }
        None => {
            let wait = p
                .next_available_ms(now_ms)
                .map(|t| t.saturating_sub(now_ms))
                .unwrap_or(60_000);
            rep.log(format!("[pool] все носители остывают — ждём {} с", wait / 1000));
            sleep(Duration::from_millis(wait.max(1000))).await;
        }
    }
    Ok(())
}

/// Локальный SOCKS5-цикл: CONNECT → TCP-поток в туннеле; UDP ASSOCIATE → UDP-релей.
async fn run_socks(listener: Arc<TcpListener>, client: Arc<TunnelClient>) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => break,
        };
        let client = client.clone();
        tokio::spawn(async move {
            match socks_accept(&mut sock).await {
                Ok(SocksRequest::Connect { addr, port }) => {
                    if socks_reply(&mut sock, REP_SUCCESS, "0.0.0.0:0".parse().unwrap())
                        .await
                        .is_ok()
                    {
                        let _ = client.open(addr, port, sock).await;
                    }
                }
                Ok(SocksRequest::UdpAssociate) => {
                    let _ = run_udp_associate(sock, client).await;
                }
                Err(_) => {}
            }
        });
    }
}

/// UDP ASSOCIATE (RFC 1928 §7): локальный UDP-релей, мост датаграмм через туннель.
async fn run_udp_associate(mut ctrl: TcpStream, client: Arc<TunnelClient>) -> std::io::Result<()> {
    use std::collections::HashMap;
    use tokio::io::AsyncReadExt;
    use tokio::net::UdpSocket;

    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    socks_reply(&mut ctrl, REP_SUCCESS, relay.local_addr()?).await?;

    let mut targets: HashMap<(String, u16), UdpSender> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut ctrl_buf = [0u8; 256];

    loop {
        tokio::select! {
            r = ctrl.read(&mut ctrl_buf) => {
                match r { Ok(0) | Err(_) => break, Ok(_) => {} }
            }
            r = relay.recv_from(&mut buf) => {
                let (n, client_src) = match r { Ok(v) => v, Err(_) => break };
                let Some((addr, port, off)) = parse_udp_header(&buf[..n]) else { continue };
                let key = (format!("{addr:?}"), port);
                let payload = buf[off..n].to_vec();

                if let Some(sender) = targets.get(&key) {
                    let _ = sender.send(&payload).await;
                    continue;
                }
                let Ok(mut tunnel) = client.open_udp(addr.clone(), port).await else { continue };
                let sender = tunnel.sender();
                let _ = sender.send(&payload).await;
                targets.insert(key, sender);

                let relay_out = relay.clone();
                let hdr = build_udp_header(&addr, port);
                tokio::spawn(async move {
                    while let Some(datagram) = tunnel.recv().await {
                        let mut out = hdr.clone();
                        out.extend_from_slice(&datagram);
                        if relay_out.send_to(&out, client_src).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

// ───────────────────────── Цикл дисциплины ─────────────────────────

/// Бесконечный цикл дисциплины: подключение, мониторинг blackhole, ротация носителей.
/// Завершается по сигналу `stop` (Controller) или при фатальной ошибке.
pub async fn run(
    source: Source,
    socks_bind: String,
    reference: Option<String>,
    rep: Reporter,
    mut stop: watch::Receiver<bool>,
) -> Result<(), BoxErr> {
    let started = Instant::now();
    let now_ms = move || started.elapsed().as_millis() as u64;

    let mut pool: Option<CarrierPool> = match source {
        Source::Pool(profiles) => {
            let pool = CarrierPool::with_defaults(profiles)?;
            rep.log(format!("[pool] носителей: {} → {:?}", pool.len(), pool.ids()));
            Some(pool)
        }
        Source::Env => None,
    };

    let mut conn = match &mut pool {
        Some(p) => {
            let profile = p.select(now_ms()).ok_or("пул пуст")?.clone();
            resolve_from_profile(&profile, &rep).await?
        }
        None => resolve_from_env(&rep).await?,
    };
    let mut mgr = build_manager(conn.budget);
    let mut fail_streak: u32 = 0;

    let reference_ok = spawn_reference_prober(reference);
    let listener = Arc::new(TcpListener::bind(&socks_bind).await?);
    rep.set_carrier(&conn.id, conn.mode.label(), &socks_bind);
    rep.log(format!("[vlyness-client] SOCKS5 на {socks_bind}"));
    rep.log(format!(
        "[carrier] '{}' → {} (SNI {}, режим {})",
        conn.id, conn.server_addr, conn.sni, conn.mode.label()
    ));

    loop {
        if *stop.borrow_and_update() {
            break;
        }
        match mgr.poll() {
            ManagerAction::Connect => {
                rep.set_state(LinkState::Connecting);
                mgr.note_attempt();
                match establish(&conn).await {
                    Ok((client, mut reader_done)) => {
                        mgr.note_success();
                        fail_streak = 0;
                        if let Some(p) = &mut pool {
                            p.mark_healthy();
                        }
                        client.enable_cadence(conn.cadence.clone());
                        let stats = client.stats();
                        rep.set_stats(Some(stats.clone()));
                        rep.set_state(LinkState::Up);
                        rep.set_error(None);
                        let socks = tokio::spawn(run_socks(listener.clone(), client.clone()));
                        rep.log(format!("[tunnel] установлен через '{}'", conn.id));

                        let mut last_up = stats.bytes_up();
                        let mut last_down = stats.bytes_down();
                        let mut switch_carrier = false;
                        let mut stopped = false;
                        loop {
                            tokio::select! {
                                _ = stop.changed() => { stopped = true; break; }
                                _ = &mut reader_done => break,
                                _ = sleep(Duration::from_millis(MONITOR_TICK_MS)) => {
                                    let up = stats.bytes_up();
                                    let down = stats.bytes_down();
                                    let sent = up > last_up;
                                    let recv = down > last_down;
                                    last_up = up;
                                    last_down = down;
                                    if recv {
                                        mgr.note_recv();
                                    } else if sent {
                                        mgr.note_sent();
                                    }
                                    if let Some(ro) = &reference_ok {
                                        mgr.note_reference(ro.load(Ordering::Relaxed));
                                    }
                                    if let ManagerAction::Frozen { then, .. } = mgr.poll() {
                                        switch_carrier = then == AfterFreeze::SwitchProfile;
                                        rep.set_state(LinkState::Frozen);
                                        rep.log(format!(
                                            "[tunnel] blackhole — тишина{}",
                                            if switch_carrier { ", затем смена носителя" } else { "" }
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                        socks.abort();
                        mgr.note_drop();
                        rep.set_stats(None);
                        rep.log("[tunnel] оборван");

                        if stopped {
                            break;
                        }
                        if switch_carrier {
                            rep.set_state(LinkState::Switching);
                            rotate_carrier(&mut pool, &mut conn, &mut mgr, now_ms(), &rep).await?;
                        }
                    }
                    Err(e) => {
                        rep.set_error(Some(e.to_string()));
                        rep.log(format!("[tunnel] не удалось подключиться через '{}': {e}", conn.id));
                        mgr.note_failure();
                        fail_streak += 1;
                        if fail_streak >= MAX_CONNECT_FAILURES {
                            rep.log(format!(
                                "[pool] носитель '{}' недоступен ({fail_streak} попытки) — смена",
                                conn.id
                            ));
                            rep.set_state(LinkState::Switching);
                            rotate_carrier(&mut pool, &mut conn, &mut mgr, now_ms(), &rep).await?;
                            fail_streak = 0;
                        }
                    }
                }
            }
            ManagerAction::Wait(ms) | ManagerAction::NetworkDown(ms) => {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = sleep(Duration::from_millis(ms.max(50))) => {}
                }
            }
            ManagerAction::AtCapacity => {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = sleep(Duration::from_millis(500)) => {}
                }
            }
            ManagerAction::Frozen { .. } => {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = sleep(Duration::from_millis(1000)) => {}
                }
            }
        }
    }
    rep.set_state(LinkState::Stopped);
    rep.set_stats(None);
    rep.log("[vlyness-client] остановлен");
    Ok(())
}

// ───────────────────────── Контроллер для GUI ─────────────────────────

/// Управляемый клиент со своим tokio-рантаймом: `start`/`stop`/`status`/`logs`.
pub struct Controller {
    rt: tokio::runtime::Runtime,
    stop_tx: watch::Sender<bool>,
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    reporter: Reporter,
    running: Arc<AtomicBool>,
}

impl Controller {
    /// Запустить клиента на пуле профилей. Не блокирует: цикл крутится в фоне.
    pub fn start_pool(
        profiles: Vec<Profile>,
        socks_bind: String,
        reference: Option<String>,
    ) -> Result<Controller, BoxErr> {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let reporter = Reporter::new(false);
        let running = Arc::new(AtomicBool::new(true));

        let rep = reporter.clone();
        let run_flag = running.clone();
        let handle = rt.spawn(async move {
            if let Err(e) = run(Source::Pool(profiles), socks_bind, reference, rep.clone(), stop_rx).await {
                rep.set_state(LinkState::Error);
                rep.set_error(Some(e.to_string()));
                rep.log(format!("[fatal] {e}"));
            }
            run_flag.store(false, Ordering::Relaxed);
        });

        Ok(Controller {
            rt,
            stop_tx,
            handle: Mutex::new(Some(handle)),
            reporter,
            running,
        })
    }

    /// Снимок состояния для UI.
    pub fn status(&self) -> StatusSnapshot {
        self.reporter.snapshot()
    }

    /// Строки лога с порядкового номера `since`.
    pub fn logs_since(&self, since: u64) -> (u64, Vec<String>) {
        self.reporter.logs_since(since)
    }

    /// Работает ли цикл (false после остановки или фатальной ошибки).
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Мягко остановить: сигнал циклу, дождаться завершения (закрыть SOCKS и туннель).
    pub fn stop(self) {
        let _ = self.stop_tx.send(true);
        let handle = self.handle.lock().expect("handle mutex").take();
        if let Some(h) = handle {
            // Дать циклу закрыться штатно, затем гарантированно снять рантайм.
            let _ = self.rt.block_on(async {
                let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
            });
        }
        self.rt.shutdown_timeout(Duration::from_secs(1));
    }
}
