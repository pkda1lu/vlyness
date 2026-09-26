//! VLYNESS клиент: локальный SOCKS5-прокси, пробрасывающий соединения через туннель.
//!
//! Дисциплина (§5, §9) и ротация носителей (whitelist §4, §5.3):
//! - `ConnectionManager` (бюджет + backoff) управляет переподключением;
//! - cadence-драйвер держит постоянный ритм (idle-fill, §8.2);
//! - монитор трафика + reference-пробер питают blackhole-детектор;
//! - при третьем срабатывании детектор рекомендует сменить носитель — и здесь
//!   [`CarrierPool`] это исполняет: упавший носитель уходит в остывание, берётся
//!   следующий по цене, дисциплина стартует для него с чистого листа.
//!
//! Два режима конфигурации:
//! - **пул**: `VLYNESS_PROFILES=<a.json,b.json,...>` — носители самодостаточны
//!   (каждый со своим `endpoint`), ротация включена;
//! - **одиночный**: параметры из окружения (`VLYNESS_SERVER_ADDR` и т.д.),
//!   опционально `VLYNESS_PROFILE` задаёт форму (валидируется).
//!
//! Окружение (одиночный режим): VLYNESS_SERVER_ADDR, VLYNESS_SNI, VLYNESS_CA,
//!   VLYNESS_PSK_B64, VLYNESS_SERVER_PUB_B64, VLYNESS_TUNNEL_PATH, VLYNESS_UA,
//!   VLYNESS_MODE (stream|segments), VLYNESS_ECH (grease) / VLYNESS_ECH_CONFIG_B64.
//! Общее: VLYNESS_SOCKS_BIND, VLYNESS_REFERENCE (контрольный хост для blackhole).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};

use vlyness_carrier::{
    client_datagram, client_segments, client_segments_packet_up, client_stream_one,
    fetch_ech_config_list, tls, DEFAULT_DOH_RESOLVER,
};
use vlyness_cli::{
    b64_decode, decode_psk, env_opt, env_or, env_req, public_roots, root_store_from_pem,
};
use vlyness_core::noise::generate_keypair;
use vlyness_discipline::backoff::Backoff;
use vlyness_discipline::blackhole::{AfterFreeze, BlackholeDetector, FreezeController};
use vlyness_discipline::budget::ConnectionBudget;
use vlyness_discipline::clock::{OsJitter, SystemClock};
use vlyness_discipline::{ConnectionManager, ManagerAction};
use vlyness_node::{accept as socks_accept, build_udp_header, parse_udp_header, reply as socks_reply, SocksRequest, TunnelClient, UdpSender, REP_SUCCESS};
use vlyness_profile::{validate, CarrierPool, Profile, TrafficMode};
use vlyness_shaping::{Cadence, LenDistribution, LenSampler};

const MONITOR_TICK_MS: u64 = 2000;
/// Столько неудачных попыток подключения подряд к одному носителю — и он меняется.
/// Недоступный носитель бесполезен так же, как заблокированный.
const MAX_CONNECT_FAILURES: u32 = 3;

type BoxErr = Box<dyn std::error::Error>;

/// Режим несущей: форма трафика, которую видит DPI.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CarrierMode {
    /// Один двунаправленный POST.
    StreamOne,
    /// GET (вниз) + один длинный POST (вверх).
    Segments,
    /// GET (вниз) + череда коротких POST'ов (вверх) — для CDN без бесконечных запросов.
    PacketUp,
    /// HTTP/3 + WebTransport поверх QUIC (RTC-профиль): сессия в надёжном WT-стриме.
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
    /// Корни доверия для QUIC-несущей (datagram-режим строит quinn-config сам).
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

/// Базовый путь туннеля из шаблона маршрута профиля: статический префикс до первого
/// плейсхолдера. `/v1/media/{sid}/seg/{n}.m4s` → `/v1/media`.
fn base_path_from_route(route: &str) -> String {
    let head = route.split('{').next().unwrap_or(route);
    head.trim_end_matches('/').to_string()
}

/// Собрать параметры подключения из профиля с `endpoint` (режим пула).
async fn resolve_from_profile(p: &Profile) -> Result<CarrierConn, BoxErr> {
    let ep = p
        .endpoint
        .as_ref()
        .ok_or_else(|| format!("профиль '{}' без endpoint", p.id))?;

    let roots: RootCertStore = match &ep.ca_pem_path {
        Some(path) => root_store_from_pem(path)?,
        None => public_roots(),
    };
    let roots_for_quic = roots.clone();
    let client_cfg = match ep.ech_config_b64.as_deref().filter(|s| !s.trim().is_empty()) {
        // Конфиг носителя задан явно.
        Some(cfg_b64) => {
            let list = b64_decode(cfg_b64)?;
            tls::client_config_ech(roots, &list)?
        }
        // Профиль просит взять ECHConfigList из DNS (HTTPS RR) через DoH.
        None if p.carrier.ech.enabled && p.carrier.ech.config_source == "dns-https-rr" => {
            let resolver = env_or("VLYNESS_DOH_RESOLVER", DEFAULT_DOH_RESOLVER);
            match fetch_ech_config_list(public_roots(), &resolver, &ep.sni).await {
                Ok(Some(list)) => {
                    eprintln!("[ech] '{}': ECHConfigList из DNS, {} байт", ep.sni, list.len());
                    tls::client_config_ech(roots, &list)?
                }
                // Нет записи или резолвер недоступен — не падаем: GREASE лучше, чем ничего,
                // и честнее, чем притворяться, будто ECH включён.
                Ok(None) => {
                    eprintln!("[ech] у '{}' нет ECH в DNS — GREASE", ep.sni);
                    tls::client_config_grease_ech(roots)?
                }
                Err(e) => {
                    eprintln!("[ech] DoH не удался ({e}) — GREASE");
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

/// Собрать параметры подключения из окружения (одиночный режим).
async fn resolve_from_env() -> Result<CarrierConn, BoxErr> {
    let ca_path = env_req("VLYNESS_CA")?;
    let roots = root_store_from_pem(&ca_path)?;
    let roots_for_quic = roots.clone();
    let client_cfg = match (env_opt("VLYNESS_ECH_CONFIG_B64"), env_opt("VLYNESS_ECH")) {
        (Some(cfg_b64), _) => {
            let list = b64_decode(&cfg_b64)?;
            eprintln!("[tls] настоящий ECH (ECHConfigList {} байт)", list.len());
            tls::client_config_ech(roots, &list)?
        }
        (None, Some(m)) if m == "doh" => {
            let domain = env_or("VLYNESS_SNI", "localhost");
            let resolver = env_or("VLYNESS_DOH_RESOLVER", DEFAULT_DOH_RESOLVER);
            match fetch_ech_config_list(public_roots(), &resolver, &domain).await {
                Ok(Some(list)) => {
                    eprintln!("[ech] '{domain}': ECHConfigList из DNS, {} байт", list.len());
                    tls::client_config_ech(roots, &list)?
                }
                Ok(None) => {
                    eprintln!("[ech] у '{domain}' нет ECH в DNS — GREASE");
                    tls::client_config_grease_ech(roots)?
                }
                Err(e) => {
                    eprintln!("[ech] DoH не удался ({e}) — GREASE");
                    tls::client_config_grease_ech(roots)?
                }
            }
        }
        (None, Some(m)) if m == "grease" => {
            eprintln!("[tls] GREASE-ECH");
            tls::client_config_grease_ech(roots)?
        }
        _ => tls::client_config(roots)?,
    };

    // Опциональный профиль задаёт форму (cadence/budget) и валидируется.
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

/// Загрузить и провалидировать профиль (отказ при несогласованной легенде, §1).
fn load_profile(path: &str) -> Result<Profile, BoxErr> {
    let json = std::fs::read_to_string(path)?;
    let profile = Profile::from_json(&json).map_err(|e| format!("профиль {path}: {e}"))?;
    if let Err(errs) = validate(&profile) {
        for e in &errs {
            eprintln!("[profile {}] нарушение {}: {}", profile.id, e.code, e.message);
        }
        return Err(format!("профиль '{}' некогерентен — отклонён (§1)", profile.id).into());
    }
    Ok(profile)
}

#[tokio::main]
async fn main() -> Result<(), BoxErr> {
    let socks_bind = env_or("VLYNESS_SOCKS_BIND", "127.0.0.1:1080");
    let started = Instant::now();
    let now_ms = move || started.elapsed().as_millis() as u64;

    // Пул носителей (если задан) — иначе одиночная конфигурация из окружения.
    let mut pool = match env_opt("VLYNESS_PROFILES") {
        Some(list) => {
            let mut profiles = Vec::new();
            for path in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                profiles.push(load_profile(path)?);
            }
            let pool = CarrierPool::with_defaults(profiles)?;
            eprintln!("[pool] носителей: {} → {:?}", pool.len(), pool.ids());
            Some(pool)
        }
        None => None,
    };

    let mut conn = match &mut pool {
        Some(p) => {
            let profile = p.select(now_ms()).ok_or("пул пуст")?.clone();
            resolve_from_profile(&profile).await?
        }
        None => resolve_from_env().await?,
    };
    let mut mgr = build_manager(conn.budget);
    let mut fail_streak: u32 = 0;

    let reference_ok = spawn_reference_prober();
    let listener = Arc::new(TcpListener::bind(&socks_bind).await?);
    eprintln!("[vlyness-client] SOCKS5 на {socks_bind}");
    eprintln!(
        "[carrier] '{}' → {} (SNI {}, режим {})",
        conn.id,
        conn.server_addr,
        conn.sni,
        conn.mode.label()
    );

    loop {
        match mgr.poll() {
            ManagerAction::Connect => {
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
                        let socks = tokio::spawn(run_socks(listener.clone(), client.clone()));
                        eprintln!("[tunnel] установлен через '{}'", conn.id);

                        // Монитор: питаем blackhole-детектор до смерти туннеля/заморозки.
                        let mut last_up = stats.bytes_up();
                        let mut last_down = stats.bytes_down();
                        let mut switch_carrier = false;
                        loop {
                            tokio::select! {
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
                                        eprintln!(
                                            "[tunnel] blackhole — тишина{}",
                                            if switch_carrier { ", затем смена носителя" } else { "" }
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        socks.abort();
                        mgr.note_drop();
                        eprintln!("[tunnel] оборван");

                        // Ротация носителя по рекомендации дисциплины (§9 → whitelist §5.3).
                        if switch_carrier {
                            rotate_carrier(&mut pool, &mut conn, &mut mgr, now_ms()).await?;
                        }
                    }
                    Err(e) => {
                        eprintln!("[tunnel] не удалось подключиться через '{}': {e}", conn.id);
                        mgr.note_failure();
                        fail_streak += 1;
                        if fail_streak >= MAX_CONNECT_FAILURES {
                            eprintln!(
                                "[pool] носитель '{}' недоступен ({fail_streak} попытки) — смена",
                                conn.id
                            );
                            rotate_carrier(&mut pool, &mut conn, &mut mgr, now_ms()).await?;
                            fail_streak = 0;
                        }
                    }
                }
            }
            ManagerAction::Wait(ms) | ManagerAction::NetworkDown(ms) => {
                sleep(Duration::from_millis(ms.max(50))).await;
            }
            ManagerAction::AtCapacity => sleep(Duration::from_millis(500)).await,
            ManagerAction::Frozen { .. } => sleep(Duration::from_millis(1000)).await,
        }
    }
}

/// Сменить носитель: текущий — в остывание, взять следующий по цене и перезапустить
/// дисциплину с чистого листа. Если все остывают — подождать ближайшего.
/// Без пула (одиночный режим) ничего не делает.
async fn rotate_carrier(
    pool: &mut Option<CarrierPool>,
    conn: &mut CarrierConn,
    mgr: &mut ConnectionManager<SystemClock, OsJitter>,
    now_ms: u64,
) -> Result<(), BoxErr> {
    let Some(p) = pool else {
        return Ok(());
    };
    p.mark_failed(now_ms);
    match p.select(now_ms) {
        Some(next) => {
            let next = next.clone();
            *conn = resolve_from_profile(&next).await?;
            *mgr = build_manager(conn.budget);
            eprintln!("[pool] переключение на носитель '{}'", conn.id);
        }
        None => {
            let wait = p
                .next_available_ms(now_ms)
                .map(|t| t.saturating_sub(now_ms))
                .unwrap_or(60_000);
            eprintln!("[pool] все носители остывают — ждём {} с", wait / 1000);
            sleep(Duration::from_millis(wait.max(1000))).await;
        }
    }
    Ok(())
}

/// Reference-пробер: без него blackhole-детектор остаётся в Suspect и не эскалирует.
fn spawn_reference_prober() -> Option<Arc<AtomicBool>> {
    let addr = env_opt("VLYNESS_REFERENCE")?;
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

/// Установить один туннель: TCP → TLS(+ECH) → HTTP/2 (stream-one|segments) → сессия → релей.
async fn establish(
    c: &CarrierConn,
) -> std::io::Result<(Arc<TunnelClient>, tokio::task::JoinHandle<()>)> {
    // RTC-профиль: несущая — QUIC/HTTP-3/WebTransport, не TCP+TLS+h2.
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
        // UDP-проброс поедет нативными QUIC-датаграммами (форма RTC-медиа), TCP — по стриму.
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
        CarrierMode::Datagram => unreachable!("datagram-режим обработан ранним return выше"),
    };

    let (reader, writer) = session.split();
    Ok(TunnelClient::start(reader, writer, None))
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
                    // BND в ответе приложению не важен (0.0.0.0:0), затем проброс TCP.
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

/// UDP ASSOCIATE (RFC 1928 §7): биндим локальный UDP-релей, сообщаем его адрес
/// приложению, и мостим датаграммы через туннель. Каждая уникальная цель получает свой
/// `UdpTunnel`; ответы заворачиваются в SOCKS5-заголовок и шлются приложению.
/// Ассоциация живёт, пока открыто управляющее TCP-соединение.
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
            // Закрытие управляющего TCP → конец ассоциации.
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
                // Новая цель: открыть UDP-поток, запустить откачку ответов.
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
