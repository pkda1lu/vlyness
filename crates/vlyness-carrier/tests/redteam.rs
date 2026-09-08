//! Red-team активного зонда (док 04 §3, признак 10; §7 honest-fallback).
//!
//! Имитируем ТСПУ/GFW, зондирующий наш сервер: пробуем туннельные пути без токена, с
//! мусорным и с подделанным токеном, реплеим валидный cookie, меряем тайминги. Критерий
//! (DoD): зонд **не находит ни одного отличающего ответа или тайминга** — на всё сервер
//! отвечает как обычный сайт (200 + тот же контент), а auth-проверка не выдаёт себя
//! измеримой задержкой.
//!
//! Зонд не знает PSK (как и настоящий цензор), поэтому не может открыть туннель. Там,
//! где тесту нужен валидный токен (реплей), PSK берётся тестом напрямую.

use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use http::{Method, Request, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::RootCertStore;
use tokio::net::{TcpListener, TcpStream};

use vlyness_carrier::{serve, tls, ServerParams, SessionHandler, H2Stream};
use vlyness_core::auth::{epoch_now, AuthToken};
use vlyness_core::noise::generate_keypair;
use vlyness_core::replay::ReplayGuard;
use vlyness_transport::{MuxEvent, Session};

const PSK: [u8; 32] = [0x3c; 32];
const SITE_BODY: &[u8] = b"<!doctype html><title>Example Media</title><h1>welcome</h1>";
const BASE: &str = "/api/v1/media";

fn shared_cert() -> (Vec<CertificateDer<'static>>, Vec<u8>) {
    static SHARED: OnceLock<(Vec<CertificateDer<'static>>, Vec<u8>)> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            (vec![ck.cert.der().clone()], ck.key_pair.serialize_der())
        })
        .clone()
}

/// Туннельный обработчик: просто поглощает (зонды сюда не доходят, но handler обязателен).
fn drain_handler() -> SessionHandler {
    Arc::new(|mut s: Session<H2Stream>| {
        Box::pin(async move {
            loop {
                match s.recv_event().await {
                    Ok(MuxEvent::Close { .. }) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            Ok(())
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>
    })
}

async fn spawn_server() -> SocketAddr {
    let (certs, key_der) = shared_cert();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let server_cfg = tls::server_config(certs, key).unwrap();
    let params = ServerParams {
        psk: PSK,
        server_priv: generate_keypair().unwrap().private,
        tunnel_path: BASE.to_string(),
        site_body: bytes::Bytes::from_static(SITE_BODY),
        replay: Arc::new(std::sync::Mutex::new(ReplayGuard::new())),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let cfg = server_cfg.clone();
            let params = params.clone();
            let handler = drain_handler();
            tokio::spawn(async move {
                if let Ok(tls) = tls::accept(cfg, tcp).await {
                    let _ = serve(tls, params, handler).await;
                }
            });
        }
    });
    addr
}

fn client_cfg() -> Arc<rustls::ClientConfig> {
    let (certs, _key) = shared_cert();
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    tls::client_config(roots).unwrap()
}

/// Результат одной пробы.
struct ProbeResult {
    status: StatusCode,
    content_type: Option<String>,
    body: Vec<u8>,
    elapsed: Duration,
}

/// Одна проба: свежее TLS+h2-соединение, запрос, полное чтение ответа. Тело GET-проб —
/// `None` (end_of_stream), у POST — переданное `body`.
async fn probe(
    addr: SocketAddr,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Option<&[u8]>,
) -> ProbeResult {
    let start = Instant::now();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let tls = tls::connect(client_cfg(), name, tcp).await.unwrap();
    let (send_req, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://localhost{path}"))
        .header("user-agent", "Mozilla/5.0 (probe)");
    if let Some(c) = cookie {
        builder = builder.header("cookie", c);
    }
    let req = builder.body(()).unwrap();

    let mut send_req = send_req.ready().await.unwrap();
    let (resp_fut, mut send_body) = send_req.send_request(req, body.is_none()).unwrap();
    if let Some(b) = body {
        // Короткое тело: одним куском, закрываем стрим.
        let _ = send_body.send_data(bytes::Bytes::copy_from_slice(b), true);
    }
    let resp = resp_fut.await.unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let mut rbody = resp.into_body();
    let mut data = Vec::new();
    while let Some(chunk) = poll_fn(|cx| rbody.poll_data(cx)).await {
        let c = chunk.unwrap();
        let _ = rbody.flow_control().release_capacity(c.len());
        data.extend_from_slice(&c);
    }
    ProbeResult { status, content_type, body: data, elapsed: start.elapsed() }
}

/// Валидный по формату токен (нужной длины base64), но под ЧУЖИМ PSK — decode пройдёт,
/// verify провалится: максимальная стоимость auth-проверки, но всё равно fallback.
fn wrong_psk_cookie() -> String {
    let mut other = PSK;
    other[0] ^= 0xff;
    format!("sid={}", AuthToken::build(&other, epoch_now()).encode())
}

fn assert_is_site(what: &str, r: &ProbeResult) {
    assert_eq!(r.status, StatusCode::OK, "{what}: статус должен быть 200, а не {}", r.status);
    assert_eq!(r.body, SITE_BODY, "{what}: тело должно быть настоящим сайтом");
    assert_eq!(
        r.content_type.as_deref(),
        Some("text/html; charset=utf-8"),
        "{what}: content-type должен быть как у сайта"
    );
}

#[tokio::test]
async fn honest_fallback_is_uniform_across_probes() {
    let addr = spawn_server().await;
    let garbage = "sid=not-a-valid-token";
    let wrong = wrong_psk_cookie();

    // Батарея зондов — каждый должен получить ОДИН И ТОТ ЖЕ ответ настоящего сайта.
    let cases: Vec<(&str, ProbeResult)> = vec![
        ("GET /", probe(addr, Method::GET, "/", None, None).await),
        ("GET /favicon.ico", probe(addr, Method::GET, "/favicon.ico", None, None).await),
        ("GET base (tunnel path)", probe(addr, Method::GET, BASE, None, None).await),
        ("POST base без cookie", probe(addr, Method::POST, BASE, None, Some(b"x")).await),
        ("POST base мусорный cookie", probe(addr, Method::POST, BASE, Some(garbage), Some(b"x")).await),
        ("POST base чужой-PSK cookie", probe(addr, Method::POST, BASE, Some(&wrong), Some(b"x")).await),
        (
            "GET segments/down без cookie",
            probe(addr, Method::GET, &format!("{BASE}/deadbeef/down"), None, None).await,
        ),
        (
            "POST segments/up мусорный cookie",
            probe(addr, Method::POST, &format!("{BASE}/deadbeef/up"), Some(garbage), Some(b"x")).await,
        ),
        (
            "POST packet-up мусорный cookie",
            probe(addr, Method::POST, &format!("{BASE}/deadbeef/up/0"), Some(garbage), Some(b"x")).await,
        ),
    ];

    for (name, r) in &cases {
        assert_is_site(name, r);
    }
}

#[tokio::test]
async fn replayed_valid_cookie_falls_back() {
    let addr = spawn_server().await;
    // Тест знает PSK и строит валидный токен. Первое использование сервер авторизует
    // (и записывает nonce), но Noise поверх мусорного тела не сойдётся. Второе
    // использование того же токена — реплей → honest-fallback (настоящий сайт).
    let cookie = format!("sid={}", AuthToken::build(&PSK, epoch_now()).encode());

    // Первое использование: сервер авторизует и записывает nonce, но Noise поверх
    // мусорного тела не сойдётся и стрим будет сброшен — это ожидаемо, ответ нам не
    // важен (важно только, что nonce теперь в реплей-кэше). Терпим сброс.
    consume_nonce(addr, &cookie).await;
    tokio::time::sleep(Duration::from_millis(50)).await; // дать серверу записать nonce

    // Второе использование того же cookie → реплей → honest-fallback (настоящий сайт).
    let second = probe(addr, Method::POST, BASE, Some(&cookie), Some(b"x")).await;
    assert_is_site("реплей валидного cookie", &second);
}

/// Отправить POST на туннельный путь с валидным cookie и мусорным телом только чтобы
/// сервер авторизовал и записал nonce. Любой сбой (сброс стрима из-за несошедшегося
/// Noise) игнорируется — это ожидаемо.
async fn consume_nonce(addr: SocketAddr, cookie: &str) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let tls = tls::connect(client_cfg(), name, tcp).await.unwrap();
    let (send_req, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://localhost{BASE}"))
        .header("cookie", cookie)
        .body(())
        .unwrap();
    let mut send_req = send_req.ready().await.unwrap();
    if let Ok((resp_fut, mut body)) = send_req.send_request(req, false) {
        let _ = body.send_data(bytes::Bytes::from_static(b"garbage-not-noise"), true);
        let _ = resp_fut.await; // ответ/сброс игнорируем
    }
}

/// Медиана по выборке длительностей.
fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

#[tokio::test]
async fn auth_check_timing_is_not_a_reliable_signal() {
    // Тайминг-канал (§7): путь, который ПРОВЕРЯЕТ токен (POST на туннельный путь), не
    // должен отвечать измеримо дольше пути, который сразу уходит в fallback (POST на
    // посторонний путь). Оба — POST с одинаковым (валидным по формату) cookie, оба дают
    // сайт; разница = стоимость auth-крипто. Она обязана тонуть в сетевом джиттере.
    let addr = spawn_server().await;
    let wrong = wrong_psk_cookie();

    // Прогрев (JIT TLS/h2, кэши).
    for _ in 0..10 {
        let _ = probe(addr, Method::POST, BASE, Some(&wrong), Some(b"x")).await;
        let _ = probe(addr, Method::POST, "/nomatch", Some(&wrong), Some(b"x")).await;
    }

    let n = 80;
    let mut auth_path = Vec::with_capacity(n);
    let mut plain_path = Vec::with_capacity(n);
    for _ in 0..n {
        // Чередуем, чтобы дрейф нагрузки бил по обеим выборкам одинаково.
        auth_path.push(probe(addr, Method::POST, BASE, Some(&wrong), Some(b"x")).await.elapsed);
        plain_path.push(probe(addr, Method::POST, "/nomatch", Some(&wrong), Some(b"x")).await.elapsed);
    }

    let m_auth = median(auth_path);
    let m_plain = median(plain_path);
    let delta = m_auth.as_secs_f64() - m_plain.as_secs_f64();
    eprintln!(
        "тайминг: auth-путь медиана={:.3}мс, обычный={:.3}мс, дельта={:.3}мс",
        m_auth.as_secs_f64() * 1e3,
        m_plain.as_secs_f64() * 1e3,
        delta * 1e3
    );

    // Стоимость auth-крипто (~единицы мкс) должна быть неотличима на фоне джиттера
    // установления TLS+h2. Порог намеренно щедрый: важно, что нет СТАБИЛЬНОГО сдвига
    // в единицы миллисекунд, по которому цензор отличил бы туннельный путь.
    assert!(
        delta.abs() < 1.5e-3,
        "auth-путь выдаёт себя таймингом: дельта {:.3}мс",
        delta * 1e3
    );
}
