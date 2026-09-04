//! VLYNESS клиент: локальный SOCKS5-прокси, пробрасывающий соединения через туннель.
//!
//! При старте: (опц.) загружает и **валидирует Profile** — при несогласованной легенде
//! отказывается стартовать (§1).
//!
//! Дисциплина (§5, §9):
//! - `ConnectionManager` (бюджет + backoff) управляет переподключением — один туннель,
//!   интервалы, экспоненциальная пауза при сбоях;
//! - cadence-драйвер держит постоянный ритм (idle-fill, §8.2);
//! - монитор трафика + reference-пробер питают blackhole-детектор: при тихом дропе
//!   (шлём вверх, вниз тишина, а контрольный хост доступен) туннель рвётся и соблюдается
//!   тишина.
//!
//! Окружение: VLYNESS_SERVER_ADDR, VLYNESS_SNI, VLYNESS_CA, VLYNESS_PSK_B64,
//!   VLYNESS_SERVER_PUB_B64, VLYNESS_TUNNEL_PATH, VLYNESS_SOCKS_BIND, VLYNESS_UA,
//!   VLYNESS_PROFILE (валидируется), VLYNESS_REFERENCE (host:port контрольного хоста
//!   для blackhole-детекции; без него детектор не эскалирует).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};

use vlyness_carrier::{client_segments, client_stream_one, tls};
use vlyness_cli::{b64_decode, decode_psk, env_opt, env_or, env_req, root_store_from_pem};
use vlyness_core::noise::generate_keypair;
use vlyness_discipline::backoff::Backoff;
use vlyness_discipline::blackhole::{BlackholeDetector, FreezeController};
use vlyness_discipline::budget::ConnectionBudget;
use vlyness_discipline::clock::{OsJitter, SystemClock};
use vlyness_discipline::{ConnectionManager, ManagerAction};
use vlyness_node::{socks5_accept, TunnelClient};
use vlyness_profile::{validate, Profile};
use vlyness_shaping::{Cadence, LenDistribution, LenSampler};

const MONITOR_TICK_MS: u64 = 2000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = env_req("VLYNESS_SERVER_ADDR")?;
    let sni = env_or("VLYNESS_SNI", "localhost");
    let ca_path = env_req("VLYNESS_CA")?;
    let psk = decode_psk(&env_req("VLYNESS_PSK_B64")?)?;
    let server_pub = b64_decode(&env_req("VLYNESS_SERVER_PUB_B64")?)?;
    let tunnel_path = env_or("VLYNESS_TUNNEL_PATH", "/v1/media/s/seg");
    let socks_bind = env_or("VLYNESS_SOCKS_BIND", "127.0.0.1:1080");
    let ua = env_or("VLYNESS_UA", "ExampleMedia/3.2 (Android 14; okhttp/4.12)");

    // Профиль (если задан) валидируется; отказ при несогласованной легенде.
    let profile = match env_opt("VLYNESS_PROFILE") {
        Some(path) => {
            let json = std::fs::read_to_string(&path)?;
            let profile = Profile::from_json(&json).map_err(|e| format!("профиль: {e}"))?;
            if let Err(errs) = validate(&profile) {
                for e in &errs {
                    eprintln!("[profile] нарушение {}: {}", e.code, e.message);
                }
                return Err("профиль некогерентен — запуск отклонён (§1)".into());
            }
            eprintln!("[profile] '{}' валиден", profile.id);
            Some(profile)
        }
        None => None,
    };

    // Бюджет и cadence из профиля или разумных значений по умолчанию.
    let (max_conns, min_int, base, cap) = match &profile {
        Some(p) => (
            p.budget.max_tls_conns,
            p.budget.min_conn_interval_ms,
            p.budget.backoff_base_ms,
            p.budget.backoff_cap_ms,
        ),
        None => (1, 800, 2000, 300_000),
    };
    let cadence = match &profile {
        Some(p) => Cadence::new(
            p.traffic.seg_interval_ms.max(1000),
            p.traffic.seg_jitter_ms,
            p.traffic.idle_fill,
        ),
        None => Cadence::new(15_000, 3_000, true),
    };

    let mode = env_or("VLYNESS_MODE", "stream"); // "stream" | "segments"
    let segments = mode == "segments";

    // TLS-конфигурация с выбором ECH:
    //   VLYNESS_ECH_CONFIG_B64 — настоящий ECHConfigList носителя (co-tenancy, §5.2);
    //   VLYNESS_ECH=grease     — GREASE-ECH (анти-ossification);
    //   иначе                  — обычный TLS.
    let roots = root_store_from_pem(&ca_path)?;
    let client_cfg = match (env_opt("VLYNESS_ECH_CONFIG_B64"), env_opt("VLYNESS_ECH")) {
        (Some(cfg_b64), _) => {
            let list = b64_decode(&cfg_b64)?;
            eprintln!("[tls] настоящий ECH (ECHConfigList {} байт)", list.len());
            tls::client_config_ech(roots, &list)?
        }
        (None, Some(m)) if m == "grease" => {
            eprintln!("[tls] GREASE-ECH");
            tls::client_config_grease_ech(roots)?
        }
        _ => tls::client_config(roots)?,
    };
    eprintln!("[mode] {}", if segments { "segments" } else { "stream-one" });

    let mut mgr = ConnectionManager::new(
        SystemClock::new(),
        OsJitter,
        ConnectionBudget::new(max_conns, min_int, Backoff::new(base, cap)),
        BlackholeDetector::with_defaults(),
        FreezeController::with_defaults(),
    );

    // Reference-пробер (опционально): периодически проверяет доступность контрольного
    // хоста. Без него blackhole-детектор остаётся в Suspect и не эскалирует.
    let reference_ok = spawn_reference_prober();

    let listener = Arc::new(TcpListener::bind(&socks_bind).await?);
    eprintln!("[vlyness-client] SOCKS5 на {socks_bind} → туннель к {server_addr} (SNI {sni})");

    loop {
        match mgr.poll() {
            ManagerAction::Connect => {
                mgr.note_attempt();
                match establish(
                    &client_cfg, &server_addr, &sni, &psk, &server_pub, &tunnel_path, &ua, segments,
                )
                .await
                {
                    Ok((client, mut reader_done)) => {
                        mgr.note_success();
                        client.enable_cadence(cadence.clone());
                        let stats = client.stats();
                        let socks = tokio::spawn(run_socks(listener.clone(), client.clone()));
                        eprintln!("[tunnel] установлен");

                        // Монитор: питаем blackhole-детектор до смерти туннеля/заморозки.
                        let mut last_up = stats.bytes_up();
                        let mut last_down = stats.bytes_down();
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
                                    if matches!(mgr.poll(), ManagerAction::Frozen { .. }) {
                                        eprintln!("[tunnel] blackhole — рвём туннель, тишина");
                                        break;
                                    }
                                }
                            }
                        }
                        socks.abort();
                        mgr.note_drop();
                        eprintln!("[tunnel] оборван, переподключение");
                    }
                    Err(e) => {
                        eprintln!("[tunnel] не удалось подключиться: {e}");
                        mgr.note_failure();
                    }
                }
            }
            ManagerAction::Wait(ms) | ManagerAction::NetworkDown(ms) => {
                sleep(Duration::from_millis(ms.max(50))).await;
            }
            ManagerAction::AtCapacity => sleep(Duration::from_millis(500)).await,
            ManagerAction::Frozen { .. } => {
                sleep(Duration::from_millis(1000)).await;
            }
        }
    }
}

/// Запустить reference-пробер, если задан VLYNESS_REFERENCE. Возвращает флаг доступности.
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

/// Установить один туннель: TCP → TLS → HTTP/2 (cookie-auth) → сессия → релей.
async fn establish(
    client_cfg: &Arc<rustls::ClientConfig>,
    server_addr: &str,
    sni: &str,
    psk: &[u8; 32],
    server_pub: &[u8],
    tunnel_path: &str,
    ua: &str,
    segments: bool,
) -> std::io::Result<(Arc<TunnelClient>, tokio::task::JoinHandle<()>)> {
    let tcp = TcpStream::connect(server_addr).await?;
    let name = ServerName::try_from(sni.to_string())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "плохое имя SNI"))?;
    let tls_stream = tls::connect(client_cfg.clone(), name, tcp).await?;

    let kp = generate_keypair()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let sampler = LenSampler::new(LenDistribution::media_abr_v1());

    let session = if segments {
        client_segments(tls_stream, psk, server_pub, &kp.private, sni, tunnel_path, ua, Some(sampler))
            .await?
    } else {
        client_stream_one(tls_stream, psk, server_pub, &kp.private, sni, tunnel_path, ua, Some(sampler))
            .await?
    };

    let (reader, writer) = session.split();
    Ok(TunnelClient::start(reader, writer))
}

/// Локальный SOCKS5-цикл: каждое соединение → CONNECT → поток в туннеле.
async fn run_socks(listener: Arc<TcpListener>, client: Arc<TunnelClient>) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => break,
        };
        let client = client.clone();
        tokio::spawn(async move {
            if let Ok((addr, port)) = socks5_accept(&mut sock).await {
                let _ = client.open(addr, port, sock).await;
            }
        });
    }
}
