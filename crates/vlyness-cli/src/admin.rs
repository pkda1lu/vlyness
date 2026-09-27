//! Локальная веб-панель сервера (только 127.0.0.1).
//!
//! **Никогда** не на публичном интерфейсе: панель на нашем домене выдала бы админку
//! зонду и сломала honest-fallback (§7). Поэтому [`serve_admin`] отказывается слушать
//! не-loopback адрес (если явно не разрешено переменной окружения). Доступ снаружи —
//! только через SSH-туннель: `ssh -L 8088:127.0.0.1:8088 vps`.
//!
//! Панель read-only: статус (аптайм, сессии по транспортам, живой трафик) и хвост лога.
//! HTTP — минимальный (GET, `Connection: close`); этого хватает для loopback-fetch.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use vlyness_node::TunnelStats;

use crate::env_opt;

const LOG_CAP: usize = 300;

/// Статичные сведения о сервере для панели.
#[derive(Clone)]
pub struct AdminInfo {
    pub domain: String,
    pub tunnel_path: String,
    pub tcp_bind: String,
    pub quic_bind: Option<String>,
}

/// Одна активная сессия: транспорт + её живые счётчики.
struct ActiveSession {
    transport: &'static str,
    stats: TunnelStats,
}

/// Метрики сервера: счётчики сессий и трафика, обновляются релеями.
pub struct ServerMetrics {
    start: Instant,
    tcp_total: AtomicU64,
    quic_total: AtomicU64,
    next_id: AtomicU64,
    active: Mutex<HashMap<u64, ActiveSession>>,
    closed_up: AtomicU64,
    closed_down: AtomicU64,
}

impl ServerMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(ServerMetrics {
            start: Instant::now(),
            tcp_total: AtomicU64::new(0),
            quic_total: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
            active: Mutex::new(HashMap::new()),
            closed_up: AtomicU64::new(0),
            closed_down: AtomicU64::new(0),
        })
    }

    /// Зарегистрировать начало сессии; вернуть её id (для [`session_end`]).
    /// `transport` — `"tcp"` или `"quic"`.
    pub fn session_start(&self, transport: &'static str, stats: TunnelStats) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        match transport {
            "tcp" => self.tcp_total.fetch_add(1, Ordering::Relaxed),
            "quic" => self.quic_total.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
        self.active
            .lock()
            .expect("metrics active mutex")
            .insert(id, ActiveSession { transport, stats });
        id
    }

    /// Завершить сессию: перенести её байты в накопленный итог.
    pub fn session_end(&self, id: u64) {
        if let Some(s) = self.active.lock().expect("metrics active mutex").remove(&id) {
            self.closed_up.fetch_add(s.stats.bytes_up(), Ordering::Relaxed);
            self.closed_down.fetch_add(s.stats.bytes_down(), Ordering::Relaxed);
        }
    }

    /// JSON статуса (живой трафик = закрытые + сумма активных).
    fn status_json(&self, info: &AdminInfo) -> String {
        let (mut tcp_active, mut quic_active) = (0u64, 0u64);
        let (mut up, mut down) = (
            self.closed_up.load(Ordering::Relaxed),
            self.closed_down.load(Ordering::Relaxed),
        );
        for s in self.active.lock().expect("metrics active mutex").values() {
            match s.transport {
                "tcp" => tcp_active += 1,
                "quic" => quic_active += 1,
                _ => {}
            }
            up += s.stats.bytes_up();
            down += s.stats.bytes_down();
        }
        let v = serde_json::json!({
            "uptime_secs": self.start.elapsed().as_secs(),
            "domain": info.domain,
            "tunnel_path": info.tunnel_path,
            "tcp_bind": info.tcp_bind,
            "quic_bind": info.quic_bind,
            "version": env!("CARGO_PKG_VERSION"),
            "sessions": {
                "tcp_active": tcp_active,
                "quic_active": quic_active,
                "tcp_total": self.tcp_total.load(Ordering::Relaxed),
                "quic_total": self.quic_total.load(Ordering::Relaxed),
            },
            "bytes": { "up": up, "down": down },
        });
        v.to_string()
    }
}

/// Кольцевой буфер событий сервера для панели.
pub struct LogRing {
    inner: Mutex<VecDeque<String>>,
}

impl LogRing {
    pub fn new() -> Arc<Self> {
        Arc::new(LogRing { inner: Mutex::new(VecDeque::new()) })
    }

    /// Добавить строку (с меткой времени) и продублировать в stderr сервера.
    pub fn push(&self, line: impl Into<String>) {
        let line = line.into();
        let stamped = format!("{} {}", hhmmss(), line);
        eprintln!("{stamped}");
        let mut b = self.inner.lock().expect("log ring mutex");
        b.push_back(stamped);
        while b.len() > LOG_CAP {
            b.pop_front();
        }
    }

    fn json(&self) -> String {
        let b = self.inner.lock().expect("log ring mutex");
        let lines: Vec<&String> = b.iter().collect();
        serde_json::to_string(&lines).unwrap_or_else(|_| "[]".to_string())
    }
}

/// Текущее время как `ЧЧ:ММ:СС` (UTC) — без внешних зависимостей.
fn hhmmss() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let t = secs % 86_400;
    format!("{:02}:{:02}:{:02}", t / 3600, (t % 3600) / 60, t % 60)
}

/// Поднять веб-панель на `bind` (обязан быть loopback). Блокирует до ошибки listener'а.
pub async fn serve_admin(
    bind: String,
    metrics: Arc<ServerMetrics>,
    log: Arc<LogRing>,
    info: AdminInfo,
) -> std::io::Result<()> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("admin_bind '{bind}': {e}")))?;
    if !addr.ip().is_loopback() && env_opt("VLYNESS_ADMIN_ALLOW_NONLOOPBACK").is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "админ-панель обязана слушать loopback (127.0.0.1/::1), а не {addr}. \
                 Доступ снаружи — через SSH-туннель. Форс: VLYNESS_ADMIN_ALLOW_NONLOOPBACK=1"
            ),
        ));
    }
    let listener = TcpListener::bind(addr).await?;
    log.push(format!("[admin] панель на http://{addr}/ (только loopback)"));
    loop {
        let (sock, _) = listener.accept().await?;
        let metrics = metrics.clone();
        let log = log.clone();
        let info = info.clone();
        tokio::spawn(async move {
            let _ = handle_conn(sock, metrics, log, info).await;
        });
    }
}

async fn handle_conn(
    mut sock: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    log: Arc<LogRing>,
    info: AdminInfo,
) -> std::io::Result<()> {
    // Прочитать запрос до конца заголовков (GET — без тела).
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let path = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, ctype, body) = match path {
        "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", PANEL_HTML.to_string()),
        "/api/status" => ("200 OK", "application/json", metrics.status_json(&info)),
        "/api/log" => ("200 OK", "application/json", log.json()),
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found".to_string()),
    };

    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.as_bytes().len()
    );
    sock.write_all(resp.as_bytes()).await?;
    sock.flush().await
}

const PANEL_HTML: &str = r#"<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VLYNESS — панель</title>
<style>
:root{color-scheme:dark light}
body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:#0f1115;color:#e6e8ee}
header{padding:14px 18px;border-bottom:1px solid #232733;display:flex;align-items:center;gap:10px}
h1{font-size:16px;margin:0;font-weight:650;letter-spacing:.3px}
.badge{margin-left:auto;font-size:12px;color:#9aa3b2}
main{padding:18px;max-width:820px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:18px}
.card{background:#161a22;border:1px solid #232733;border-radius:10px;padding:12px 14px}
.card .k{font-size:12px;color:#9aa3b2}
.card .v{font-size:22px;font-weight:650;margin-top:2px}
.card .s{font-size:12px;color:#7b8494;margin-top:2px}
.meta{font-size:13px;color:#9aa3b2;margin-bottom:14px}
.meta code{color:#cdd3df;background:#1c212b;padding:1px 6px;border-radius:5px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:#9aa3b2;margin:18px 0 8px}
#log{background:#0b0d11;border:1px solid #232733;border-radius:10px;padding:10px;height:280px;overflow:auto;
 font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;color:#c3cad6}
.dot{width:9px;height:9px;border-radius:50%;background:#3cb45a;display:inline-block}
</style></head>
<body>
<header><span class="dot"></span><h1>VLYNESS</h1><span class="badge" id="ver"></span></header>
<main>
<div class="meta" id="meta"></div>
<div class="grid">
 <div class="card"><div class="k">Аптайм</div><div class="v" id="uptime">—</div></div>
 <div class="card"><div class="k">Активные сессии</div><div class="v" id="active">—</div><div class="s" id="active_s"></div></div>
 <div class="card"><div class="k">Всего сессий</div><div class="v" id="total">—</div><div class="s" id="total_s"></div></div>
 <div class="card"><div class="k">Трафик ↑ / ↓</div><div class="v" id="bytes">—</div></div>
</div>
<h2>Лог</h2>
<div id="log"></div>
</main>
<script>
function human(n){if(n<1024)return n+" B";const u=["KB","MB","GB","TB"];let v=n,i=-1;do{v/=1024;i++}while(v>=1024&&i<3);return v.toFixed(1)+" "+u[i]}
function dur(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
 if(d)return d+"д "+h+"ч";if(h)return h+"ч "+m+"м";return m+"м "+(s%60)+"с"}
async function tick(){
 try{
  const s=await (await fetch('/api/status',{cache:'no-store'})).json();
  document.getElementById('ver').textContent='v'+s.version;
  document.getElementById('meta').innerHTML=
    'домен <code>'+s.domain+'</code> · путь <code>'+s.tunnel_path+'</code> · TCP <code>'+s.tcp_bind+'</code>'+
    (s.quic_bind?' · QUIC <code>'+s.quic_bind+'</code>':'');
  document.getElementById('uptime').textContent=dur(s.uptime_secs);
  document.getElementById('active').textContent=s.sessions.tcp_active+s.sessions.quic_active;
  document.getElementById('active_s').textContent='TCP '+s.sessions.tcp_active+' · QUIC '+s.sessions.quic_active;
  document.getElementById('total').textContent=s.sessions.tcp_total+s.sessions.quic_total;
  document.getElementById('total_s').textContent='TCP '+s.sessions.tcp_total+' · QUIC '+s.sessions.quic_total;
  document.getElementById('bytes').textContent=human(s.bytes.up)+' / '+human(s.bytes.down);
  const log=await (await fetch('/api/log',{cache:'no-store'})).json();
  const el=document.getElementById('log');const atBottom=el.scrollTop+el.clientHeight>=el.scrollHeight-10;
  el.textContent=log.join('\n');if(atBottom)el.scrollTop=el.scrollHeight;
 }catch(e){}
}
tick();setInterval(tick,2000);
</script>
</body></html>"#;
