//! HTTP/2-носитель: сессия внутри одного h2-стрима, с honest-fallback (§7).
//!
//! Здесь замыкается контур аутентификации: клиент кладёт токен в cookie `sid=` (§6.2),
//! и **те же сырые байты** служат prologue Noise-хендшейка (§4). Сервер извлекает токен
//! из cookie, проверяет его и берёт как prologue. Тем самым cookie и E2E-крипто связаны:
//! подменить токен нельзя — хендшейк не сойдётся.
//!
//! Honest-fallback: запрос без валидного токена (или на «не тот» путь) получает
//! **настоящий ответ сайта** (200 + контент), а не 404/RST. Зонд ТСПУ, пришедший на
//! наш домен, видит обычный сайт и не может отличить нас от него.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

use vlyness_core::auth::{epoch_now, AuthToken, PSK_LEN, TOKEN_LEN};
use vlyness_core::replay::ReplayGuard;
use vlyness_shaping::LenSampler;
use vlyness_transport::Session;

use crate::h2bridge::H2Stream;

fn other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Клиент: установить туннель одним двунаправленным h2-стримом (режим `stream-one`).
///
/// `authority` — значение `:authority`/Host (домен нашего endpoint); `path` — путь
/// туннеля; `user_agent` — из профиля (должен соответствовать fingerprint, см.
/// `vlyness_profile::validate`).
#[allow(clippy::too_many_arguments)]
pub async fn client_stream_one<IO>(
    tls: IO,
    psk: &[u8; PSK_LEN],
    server_pub: &[u8],
    client_priv: &[u8],
    authority: &str,
    path: &str,
    user_agent: &str,
    sampler: Option<LenSampler>,
) -> std::io::Result<Session<H2Stream>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_req, conn) = h2::client::handshake(tls).await.map_err(other)?;
    // Драйвер соединения: без него данные не движутся.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let token = AuthToken::build(psk, epoch_now());
    let cookie = format!("sid={}", token.encode());
    let auth_raw = token.raw();

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{authority}{path}"))
        .header("user-agent", user_agent)
        .header("cookie", cookie)
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(other)?;

    let mut send_req = send_req.ready().await.map_err(other)?;
    let (resp_fut, send_stream) = send_req.send_request(req, false).map_err(other)?;
    let resp = resp_fut.await.map_err(other)?;
    let recv = resp.into_body();

    let stream = H2Stream::new(send_stream, recv);
    Session::connect(stream, server_pub, client_priv, &auth_raw, sampler).await
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Клиент: установить туннель в режиме `segments` — отдельный GET (нисходящий канал) и
/// POST (восходящий), спариваемые по `pid` в пути. Форма трафика ближе к медиа-плееру,
/// чем один двунаправленный POST (`stream-one`).
///
/// `base_path` — общий префикс (`tunnel_path` сервера). `pid` берётся из nonce токена,
/// поэтому уникален и случаен на каждую сессию.
#[allow(clippy::too_many_arguments)]
pub async fn client_segments<IO>(
    tls: IO,
    psk: &[u8; PSK_LEN],
    server_pub: &[u8],
    client_priv: &[u8],
    authority: &str,
    base_path: &str,
    user_agent: &str,
    sampler: Option<LenSampler>,
) -> std::io::Result<Session<H2Stream>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_req, conn) = h2::client::handshake(tls).await.map_err(other)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let token = AuthToken::build(psk, epoch_now());
    let cookie = format!("sid={}", token.encode());
    let auth_raw = token.raw();
    let pid = hex(&token.nonce);

    let get_req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{authority}{base_path}/{pid}/down"))
        .header("user-agent", user_agent)
        .header("cookie", &cookie)
        .body(())
        .map_err(other)?;
    let post_req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{authority}{base_path}/{pid}/up"))
        .header("user-agent", user_agent)
        .header("cookie", &cookie)
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(other)?;

    let mut sr = send_req.ready().await.map_err(other)?;
    // GET без тела (end_of_stream); тело ответа — нисходящий канал.
    let (get_resp_fut, _get_send) = sr.send_request(get_req, true).map_err(other)?;
    // POST с открытым телом запроса — восходящий канал.
    let (_post_resp_fut, upload_send) = sr.send_request(post_req, false).map_err(other)?;

    let get_resp = get_resp_fut.await.map_err(other)?;
    let download_recv = get_resp.into_body();

    let stream = H2Stream::new(upload_send, download_recv);
    Session::connect(stream, server_pub, client_priv, &auth_raw, sampler).await
}

/// Параметры серверного носителя.
#[derive(Clone)]
pub struct ServerParams {
    pub psk: [u8; PSK_LEN],
    pub server_priv: Vec<u8>,
    /// Путь, по которому живёт туннель (всё прочее уходит в honest-fallback).
    pub tunnel_path: String,
    /// Тело «настоящего сайта» для honest-fallback.
    pub site_body: Bytes,
    /// Общий на все соединения кэш анти-реплея (§3).
    pub replay: Arc<Mutex<ReplayGuard>>,
}

/// Обработчик установленной туннельной сессии (например, роутинг потоков к целям).
pub type SessionHandler = Arc<
    dyn Fn(Session<H2Stream>) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Направление сегментного канала.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    Up,
    Down,
}

/// Половина сегментной сессии, ждущая пары (обе идут по одному h2-соединению).
enum PendingHalf {
    Download { send: SendStream<Bytes>, auth: [u8; TOKEN_LEN] },
    Upload { recv: RecvStream, auth: [u8; TOKEN_LEN] },
}

impl PendingHalf {
    fn auth(&self) -> &[u8; TOKEN_LEN] {
        match self {
            PendingHalf::Download { auth, .. } | PendingHalf::Upload { auth, .. } => auth,
        }
    }
}

/// Собрать [`H2Stream`] из двух половин (одна Download, одна Upload).
fn combine(a: PendingHalf, b: PendingHalf) -> Option<(H2Stream, [u8; TOKEN_LEN])> {
    let auth = *a.auth();
    match (a, b) {
        (PendingHalf::Download { send, .. }, PendingHalf::Upload { recv, .. })
        | (PendingHalf::Upload { recv, .. }, PendingHalf::Download { send, .. }) => {
            Some((H2Stream::new(send, recv), auth))
        }
        _ => None, // две одинаковые половины — некорректно
    }
}

/// Разобрать сегментный путь `{base}/{pid}/up|down` под метод. Возвращает `(pid, dir)`.
fn parse_segments(path: &str, base: &str, method: &Method) -> Option<(String, Dir)> {
    let rest = path.strip_prefix(base)?.strip_prefix('/')?;
    let mut it = rest.splitn(2, '/');
    let pid = it.next()?;
    let tail = it.next()?;
    if pid.is_empty() || tail.contains('/') {
        return None;
    }
    match (tail, method) {
        ("up", &Method::POST) => Some((pid.to_string(), Dir::Up)),
        ("down", &Method::GET) => Some((pid.to_string(), Dir::Down)),
        _ => None,
    }
}

fn ok_octet() -> std::io::Result<Response<()>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(other)
}

/// Honest-fallback: настоящий сайт, одинаковый успешный ответ для всех.
fn serve_fallback(respond: &mut SendResponse<Bytes>, site_body: &Bytes) -> std::io::Result<()> {
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(())
        .map_err(other)?;
    let mut send = respond.send_response(resp, false).map_err(other)?;
    let _ = send.send_data(site_body.clone(), true);
    Ok(())
}

/// Извлечь значение cookie `sid=` (для любого тела запроса).
fn cookie_sid<T>(req: &Request<T>) -> Option<String> {
    let cookie = req.headers().get("cookie")?.to_str().ok()?;
    cookie
        .split(';')
        .find_map(|kv| kv.trim().strip_prefix("sid="))
        .map(|s| s.to_string())
}

/// Декодировать и проверить тег токена (без учёта реплея). Возвращает токен и эпоху.
fn verify_only(sid: &str, psk: &[u8; PSK_LEN]) -> Option<(AuthToken, u64)> {
    let token = AuthToken::decode(sid).ok()?;
    let epoch = token.verify(psk, epoch_now())?;
    Some((token, epoch))
}

fn spawn_session(stream: H2Stream, auth_raw: [u8; TOKEN_LEN], params: &Arc<ServerParams>, handler: &SessionHandler) {
    let server_priv = params.server_priv.clone();
    let handler = handler.clone();
    tokio::spawn(async move {
        if let Ok(session) = Session::accept(stream, &server_priv, &auth_raw, None).await {
            let _ = handler(session).await;
        }
    });
}

/// Построить половину сегментной сессии, ответив на запрос нужным образом.
fn build_half(
    dir: Dir,
    respond: &mut SendResponse<Bytes>,
    req: Request<RecvStream>,
    auth: [u8; TOKEN_LEN],
) -> std::io::Result<PendingHalf> {
    match dir {
        // GET: тело ответа = нисходящий канал (сервер пишет в него).
        Dir::Down => {
            let send = respond.send_response(ok_octet()?, false).map_err(other)?;
            Ok(PendingHalf::Download { send, auth })
        }
        // POST: тело запроса = восходящий канал; ответ пустой и сразу закрыт.
        Dir::Up => {
            let empty = Response::builder().status(StatusCode::OK).body(()).map_err(other)?;
            let _ = respond.send_response(empty, true).map_err(other)?;
            Ok(PendingHalf::Upload { recv: req.into_body(), auth })
        }
    }
}

/// Сервер: обслужить одно h2-соединение. Поддерживает оба режима:
/// - `stream-one`: POST на `tunnel_path` — сессия в одном двунаправленном стриме;
/// - `segments`: GET `.../{pid}/down` + POST `.../{pid}/up`, спариваемые по `pid`.
/// Всё прочее — honest-fallback (§7). Спаривание локально: обе половины идут по одному
/// h2-соединению.
pub async fn serve<IO>(
    tls: IO,
    params: ServerParams,
    handler: SessionHandler,
) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = h2::server::handshake(tls).await.map_err(other)?;
    let params = Arc::new(params);
    let mut pending: HashMap<String, PendingHalf> = HashMap::new();

    while let Some(res) = conn.accept().await {
        let (req, mut respond) = res.map_err(other)?;
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // --- режим stream-one ---
        if method == Method::POST && path == params.tunnel_path {
            match cookie_sid(&req).and_then(|s| authorize(&s, &params.psk, &params.replay)) {
                Some(auth_raw) => {
                    let send_stream = respond.send_response(ok_octet()?, false).map_err(other)?;
                    let stream = H2Stream::new(send_stream, req.into_body());
                    spawn_session(stream, auth_raw, &params, &handler);
                }
                None => serve_fallback(&mut respond, &params.site_body)?,
            }
            continue;
        }

        // --- режим segments ---
        if let Some((pid, dir)) = parse_segments(&path, &params.tunnel_path, &method) {
            let Some((token, epoch)) =
                cookie_sid(&req).and_then(|s| verify_only(&s, &params.psk))
            else {
                serve_fallback(&mut respond, &params.site_body)?;
                continue;
            };
            let auth_raw = token.raw();

            if let Some(other_half) = pending.remove(&pid) {
                // Вторая половина: токен должен совпасть; реплей уже проверен на первой.
                if other_half.auth() != &auth_raw {
                    pending.insert(pid, other_half);
                    serve_fallback(&mut respond, &params.site_body)?;
                    continue;
                }
                let this_half = build_half(dir, &mut respond, req, auth_raw)?;
                if let Some((stream, auth)) = combine(other_half, this_half) {
                    spawn_session(stream, auth, &params, &handler);
                }
            } else {
                // Первая половина: проверяем реплей (records nonce once per session).
                let fresh = params
                    .replay
                    .lock()
                    .expect("ReplayGuard mutex")
                    .observe_token(&token, epoch);
                if !fresh {
                    serve_fallback(&mut respond, &params.site_body)?;
                    continue;
                }
                let half = build_half(dir, &mut respond, req, auth_raw)?;
                pending.insert(pid, half);
            }
            continue;
        }

        // --- honest-fallback ---
        serve_fallback(&mut respond, &params.site_body)?;
    }
    Ok(())
}

/// Авторизовать значение cookie `sid`: декодировать токен, проверить тег по окну
/// эпох и отсечь реплей. Возвращает сырые байты токена для Noise-prologue.
///
/// Вынесено отдельной чистой функцией, чтобы логика авторизации тестировалась без
/// HTTP/2. Проверки идут по порядку и без ранних утечек по времени в успешной ветке.
pub fn authorize(
    sid: &str,
    psk: &[u8; PSK_LEN],
    replay: &Mutex<ReplayGuard>,
) -> Option<[u8; TOKEN_LEN]> {
    let token = AuthToken::decode(sid).ok()?;
    let epoch = token.verify(psk, epoch_now())?;
    // Реплей проверяем последним: только валидные токены попадают в кэш.
    let mut guard = replay.lock().expect("ReplayGuard mutex не отравлен");
    if !guard.observe_token(&token, epoch) {
        return None; // повтор — как зонд, уходит в honest-fallback
    }
    Some(token.raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> [u8; PSK_LEN] {
        [0x9a; PSK_LEN]
    }

    #[test]
    fn authorizes_fresh_token_once() {
        let replay = Mutex::new(ReplayGuard::new());
        let sid = AuthToken::build(&psk(), epoch_now()).encode();
        assert!(authorize(&sid, &psk(), &replay).is_some(), "свежий токен проходит");
        assert!(authorize(&sid, &psk(), &replay).is_none(), "повтор того же — реплей, отказ");
    }

    #[test]
    fn rejects_wrong_psk() {
        let replay = Mutex::new(ReplayGuard::new());
        let sid = AuthToken::build(&psk(), epoch_now()).encode();
        let mut other = psk();
        other[0] ^= 0xff;
        assert!(authorize(&sid, &other, &replay).is_none());
    }

    #[test]
    fn rejects_garbage_cookie() {
        let replay = Mutex::new(ReplayGuard::new());
        assert!(authorize("not-a-valid-token", &psk(), &replay).is_none());
    }
}
