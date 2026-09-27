//! VLYNESS сервер: TLS 1.3 + HTTP/2 (и опционально QUIC/HTTP-3/WebTransport), туннели
//! обслуживает серверный релей (коннект к реальным целям), запросы без валидного токена —
//! honest-fallback (настоящий сайт).
//!
//! Два способа конфигурации:
//!   1. **Файл**: `VLYNESS_CONFIG=/etc/vlyness/server.toml` (основной путь для VPS —
//!      сгенерируй его `vlyness-setup`, правь при необходимости);
//!   2. **Окружение** (если файл не задан): VLYNESS_BIND, VLYNESS_QUIC, VLYNESS_DOMAIN,
//!      VLYNESS_TUNNEL_PATH, VLYNESS_PSK_B64, VLYNESS_SERVER_PRIV_B64/PUB_B64,
//!      VLYNESS_CERT_PEM/VLYNESS_KEY_PEM (настоящий сертификат) либо самоподпись,
//!      VLYNESS_CERT_OUT (куда писать PEM самоподписи для клиента).

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::TcpListener;

use vlyness_carrier::{
    build_quic_server, serve, serve_datagram, tls, QuicServerParams, QuicSessionHandler, QuicStream,
    ServerParams, SessionHandler, H2Stream,
};
use std::path::PathBuf;

use vlyness_cli::admin::{serve_admin, AdminInfo, AdminState, IssueContext, LogRing, ServerMetrics};
use vlyness_cli::config::ServerConfig;
use vlyness_cli::keyring::Keyring;
use vlyness_cli::{
    b64_decode, b64_encode, decode_psk, env_opt, env_or, load_cert_key_pem, self_signed,
};
use vlyness_core::noise::generate_keypair;
use vlyness_core::replay::ReplayGuard;
use vlyness_node::{run_server_relay_with_stats, TunnelStats};
use vlyness_transport::Session;

const SITE_BODY: &[u8] =
    b"<!doctype html><html><head><title>Media</title></head><body>ok</body></html>";

/// Собрать конфигурацию из окружения (когда VLYNESS_CONFIG не задан). Недостающие
/// секреты генерируются и печатаются — удобно для локального теста.
fn config_from_env() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let psk_b64 = match env_opt("VLYNESS_PSK_B64") {
        Some(s) => s,
        None => {
            let mut p = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut p);
            let s = b64_encode(&p);
            println!("[gen] VLYNESS_PSK_B64={s}");
            s
        }
    };
    let (priv_b64, pub_b64) = match (
        env_opt("VLYNESS_SERVER_PRIV_B64"),
        env_opt("VLYNESS_SERVER_PUB_B64"),
    ) {
        (Some(pv), Some(pb)) => (pv, pb),
        _ => {
            let kp = generate_keypair()?;
            let (pv, pb) = (b64_encode(&kp.private), b64_encode(&kp.public));
            println!("[gen] VLYNESS_SERVER_PRIV_B64={pv}");
            println!("[gen] VLYNESS_SERVER_PUB_B64={pb}");
            (pv, pb)
        }
    };
    Ok(ServerConfig {
        bind: env_or("VLYNESS_BIND", "0.0.0.0:8443"),
        quic: env_opt("VLYNESS_QUIC"),
        domain: env_or("VLYNESS_DOMAIN", "localhost"),
        tunnel_path: env_or("VLYNESS_TUNNEL_PATH", "/v1/media/s/seg"),
        psk_b64,
        server_priv_b64: priv_b64,
        server_pub_b64: pub_b64,
        cert_pem: env_opt("VLYNESS_CERT_PEM"),
        key_pem: env_opt("VLYNESS_KEY_PEM"),
        site_body_path: env_opt("VLYNESS_SITE_BODY"),
        admin_bind: env_opt("VLYNESS_ADMIN_BIND"),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = match env_opt("VLYNESS_CONFIG") {
        Some(path) => {
            println!("[vlyness-server] конфиг: {path}");
            ServerConfig::load(&path)?
        }
        None => config_from_env()?,
    };

    decode_psk(&cfg.psk_b64)?; // валидация формата PSK из конфига (сид keyring)
    let server_priv = b64_decode(&cfg.server_priv_b64)?;
    let server_pub = b64_decode(&cfg.server_pub_b64)?;

    // Сертификат: настоящий из PEM (Let's Encrypt) либо самоподписанный на лету.
    let (certs, key) = match (&cfg.cert_pem, &cfg.key_pem) {
        (Some(cert), Some(key)) => {
            println!("[vlyness-server] сертификат из PEM: {cert}");
            load_cert_key_pem(cert, key)?
        }
        _ => {
            let (certs, key, pem) = self_signed(&cfg.domain)?;
            let cert_out = env_or("VLYNESS_CERT_OUT", "./vlyness-cert.pem");
            std::fs::write(&cert_out, pem)?;
            println!("[vlyness-server] самоподписанный сертификат записан в {cert_out}");
            println!("[vlyness-server]   (клиент должен доверять ему через VLYNESS_CA/ca_pem_path)");
            (certs, key)
        }
    };

    // Тело honest-fallback: из файла или встроенная заглушка.
    let site_body = match &cfg.site_body_path {
        Some(path) => Bytes::from(std::fs::read(path)?),
        None => Bytes::from_static(SITE_BODY),
    };

    // Общие для обеих несущих сертификат-производные и анти-реплей.
    let quic_certs = certs.clone();
    let quic_key = key.clone_key();
    let replay = Arc::new(Mutex::new(ReplayGuard::new()));

    // Метрики и лог для веб-панели (панель — опционально, только loopback).
    let metrics = ServerMetrics::new();
    let admin_log = LogRing::new();

    // Keyring: набор клиентских PSK (выпуск/отзыв из панели). Сид — PSK из конфига
    // (клиент `default`), чтобы ранее розданные профили продолжали работать.
    let keyring_path = env_opt("VLYNESS_KEYRING")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/vlyness/keyring.json"));
    let keyring = Keyring::load_or_seed(Some(keyring_path), &cfg.psk_b64);
    let psks = keyring.lock().expect("keyring mutex").psk_list();

    let server_cfg = tls::server_config(certs, key)?;
    let params = ServerParams {
        psks: psks.clone(),
        server_priv: server_priv.clone(),
        tunnel_path: cfg.tunnel_path.clone(),
        site_body,
        replay: replay.clone(),
    };

    // RTC-несущая (HTTP/3 + WebTransport) — если задан QUIC-адрес. Обычно тот же порт,
    // что и TCP: реальные H3-серверы слушают :443 и по UDP, и по TCP.
    if let Some(quic_bind) = &cfg.quic {
        let quic_addr = quic_bind
            .parse()
            .map_err(|e| format!("quic='{quic_bind}': {e}"))?;
        let quic_server = build_quic_server(quic_addr, quic_certs, quic_key)?;
        let quic_params = QuicServerParams {
            psks: psks.clone(),
            server_priv: server_priv.clone(),
            tunnel_path: cfg.tunnel_path.clone(),
            replay: replay.clone(),
        };
        let quic_metrics = metrics.clone();
        let quic_handler: QuicSessionHandler = Arc::new(move |session: Session<QuicStream>, dgram| {
            let metrics = quic_metrics.clone();
            Box::pin(async move {
                let stats = TunnelStats::new();
                let id = metrics.session_start("quic", stats.clone());
                let (reader, writer) = session.split();
                // RTC-несущая: UDP-кадры едут нативными QUIC-датаграммами (форма медиа).
                let res = run_server_relay_with_stats(reader, writer, dgram, stats).await;
                metrics.session_end(id);
                res
            })
                as std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>
        });
        println!("[vlyness-server] QUIC/HTTP-3/WebTransport слушаю {quic_bind} (UDP)");
        tokio::spawn(async move {
            if let Err(e) = serve_datagram(quic_server, quic_params, quic_handler).await {
                eprintln!("[quic] серверный цикл завершился: {e}");
            }
        });
    }

    let tcp_metrics = metrics.clone();
    let handler: SessionHandler = Arc::new(move |session: Session<H2Stream>| {
        let metrics = tcp_metrics.clone();
        Box::pin(async move {
            let stats = TunnelStats::new();
            let id = metrics.session_start("tcp", stats.clone());
            let (reader, writer) = session.split();
            // h2-несущая: без нативных датаграмм — UDP-кадры идут по надёжному стриму.
            let res = run_server_relay_with_stats(reader, writer, None, stats).await;
            metrics.session_end(id);
            res
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>
    });

    // Веб-панель (опционально, только loopback). Доступ снаружи — через SSH-туннель.
    if let Some(admin_bind) = cfg.admin_bind.clone() {
        let port = cfg.bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);
        let state = AdminState {
            metrics: metrics.clone(),
            log: admin_log.clone(),
            info: AdminInfo {
                domain: cfg.domain.clone(),
                tunnel_path: cfg.tunnel_path.clone(),
                tcp_bind: cfg.bind.clone(),
                quic_bind: cfg.quic.clone(),
            },
            keyring: keyring.clone(),
            issue: IssueContext {
                domain: cfg.domain.clone(),
                tunnel_path: cfg.tunnel_path.clone(),
                server_addr: format!("{}:{}", cfg.domain, port),
                server_pub_b64: cfg.server_pub_b64.clone(),
            },
        };
        tokio::spawn(async move {
            if let Err(e) = serve_admin(admin_bind, state).await {
                eprintln!("[admin] панель не поднялась: {e}");
            }
        });
    }

    let listener = TcpListener::bind(&cfg.bind).await?;
    println!("[vlyness-server] TCP (TLS/HTTP-2) слушаю {}", cfg.bind);
    println!("[vlyness-server] домен(SNI)={} путь={}", cfg.domain, cfg.tunnel_path);
    println!("[vlyness-server] server_pub(b64)={}", b64_encode(&server_pub));
    admin_log.push(format!("[server] запущен: домен {} путь {}", cfg.domain, cfg.tunnel_path));

    loop {
        let (tcp, peer) = listener.accept().await?;
        let cfg = server_cfg.clone();
        let params = params.clone();
        let handler = handler.clone();
        let log = admin_log.clone();
        tokio::spawn(async move {
            match tls::accept(cfg, tcp).await {
                Ok(tls_stream) => {
                    if let Err(e) = serve(tls_stream, params, handler).await {
                        eprintln!("[conn {peer}] сессия завершилась: {e}");
                    }
                }
                Err(e) => log.push(format!("[conn {peer}] TLS-хендшейк не удался: {e}")),
            }
        });
    }
}
