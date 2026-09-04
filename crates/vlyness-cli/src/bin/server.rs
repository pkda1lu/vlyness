//! VLYNESS сервер: TLS 1.3 + HTTP/2, туннели обслуживает серверный релей (коннект к
//! реальным целям), запросы без валидного токена — honest-fallback (настоящий сайт).
//!
//! Конфигурация через окружение:
//!   VLYNESS_BIND         адрес прослушивания (default 0.0.0.0:8443)
//!   VLYNESS_DOMAIN       домен для самоподписанного сертификата (default localhost)
//!   VLYNESS_TUNNEL_PATH  путь туннеля (default /v1/media/s/seg)
//!   VLYNESS_PSK_B64      общий секрет (32 байта base64); если нет — сгенерируется
//!   VLYNESS_SERVER_PRIV_B64 / VLYNESS_SERVER_PUB_B64  статическая пара; если нет — сгенерируется
//!   VLYNESS_CERT_OUT     куда записать PEM сертификата для клиента (default ./vlyness-cert.pem)

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::TcpListener;

use vlyness_carrier::{serve, tls, ServerParams, SessionHandler, H2Stream};
use vlyness_cli::{b64_encode, decode_psk, env_or, env_opt, self_signed};
use vlyness_core::noise::generate_keypair;
use vlyness_core::replay::ReplayGuard;
use vlyness_node::run_server_relay;
use vlyness_transport::Session;

const SITE_BODY: &[u8] =
    b"<!doctype html><html><head><title>Media</title></head><body>ok</body></html>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env_or("VLYNESS_BIND", "0.0.0.0:8443");
    let domain = env_or("VLYNESS_DOMAIN", "localhost");
    let tunnel_path = env_or("VLYNESS_TUNNEL_PATH", "/v1/media/s/seg");

    // PSK: из окружения или сгенерировать и показать.
    let psk = match env_opt("VLYNESS_PSK_B64") {
        Some(s) => decode_psk(&s)?,
        None => {
            let mut p = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut p);
            println!("[gen] VLYNESS_PSK_B64={}", b64_encode(&p));
            p
        }
    };

    // Статическая пара сервера.
    let (server_priv, server_pub) = match (
        env_opt("VLYNESS_SERVER_PRIV_B64"),
        env_opt("VLYNESS_SERVER_PUB_B64"),
    ) {
        (Some(pv), Some(pb)) => (vlyness_cli::b64_decode(&pv)?, vlyness_cli::b64_decode(&pb)?),
        _ => {
            let kp = generate_keypair()?;
            println!("[gen] VLYNESS_SERVER_PRIV_B64={}", b64_encode(&kp.private));
            println!("[gen] VLYNESS_SERVER_PUB_B64={}", b64_encode(&kp.public));
            (kp.private, kp.public)
        }
    };

    // Самоподписанный сертификат; PEM — на диск, чтобы клиент ему доверял.
    let (certs, key, pem) = self_signed(&domain)?;
    let cert_out = env_or("VLYNESS_CERT_OUT", "./vlyness-cert.pem");
    std::fs::write(&cert_out, pem)?;

    let server_cfg = tls::server_config(certs, key)?;
    let params = ServerParams {
        psk,
        server_priv,
        tunnel_path: tunnel_path.clone(),
        site_body: Bytes::from_static(SITE_BODY),
        replay: Arc::new(Mutex::new(ReplayGuard::new())),
    };

    let handler: SessionHandler = Arc::new(|session: Session<H2Stream>| {
        Box::pin(async move {
            let (reader, writer) = session.split();
            run_server_relay(reader, writer).await
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>
    });

    let listener = TcpListener::bind(&bind).await?;
    println!("[vlyness-server] слушаю {bind}");
    println!("[vlyness-server] домен(SNI)={domain} путь={tunnel_path}");
    println!("[vlyness-server] server_pub(b64)={}", b64_encode(&server_pub));
    println!("[vlyness-server] сертификат записан в {cert_out}");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let cfg = server_cfg.clone();
        let params = params.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            match tls::accept(cfg, tcp).await {
                Ok(tls_stream) => {
                    if let Err(e) = serve(tls_stream, params, handler).await {
                        eprintln!("[conn {peer}] сессия завершилась: {e}");
                    }
                }
                Err(e) => eprintln!("[conn {peer}] TLS-хендшейк не удался: {e}"),
            }
        });
    }
}
