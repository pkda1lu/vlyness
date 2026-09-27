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
use vlyness_profile::TrafficMode;

use crate::keyring::Keyring;
use crate::profilegen::build_client_profile;
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

/// Данные для сборки профиля выпускаемого клиента.
#[derive(Clone)]
pub struct IssueContext {
    pub domain: String,
    pub tunnel_path: String,
    /// Куда клиент коннектится (`domain:port`).
    pub server_addr: String,
    pub server_pub_b64: String,
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

/// Всё, что нужно панели для управления клиентами.
#[derive(Clone)]
pub struct AdminState {
    pub metrics: Arc<ServerMetrics>,
    pub log: Arc<LogRing>,
    pub info: AdminInfo,
    pub keyring: Arc<Mutex<Keyring>>,
    pub issue: IssueContext,
}

/// Поднять веб-панель на `bind` (обязан быть loopback). Блокирует до ошибки listener'а.
pub async fn serve_admin(bind: String, state: AdminState) -> std::io::Result<()> {
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
    state.log.push(format!("[admin] панель на http://{addr}/ (только loopback)"));
    loop {
        let (sock, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let _ = handle_conn(sock, state).await;
        });
    }
}

/// Разобрать `Content-Length` из заголовков (регистронезависимо).
fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

async fn handle_conn(mut sock: tokio::net::TcpStream, state: AdminState) -> std::io::Result<()> {
    // Прочитать заголовки; для POST дочитать тело по Content-Length.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];
    let mut header_end = None;
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if header_end.is_none() {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(p + 4);
            }
        }
        if let Some(he) = header_end {
            let want = he + content_length(&String::from_utf8_lossy(&buf[..he]));
            if buf.len() >= want || buf.len() > 1_048_576 {
                break;
            }
        } else if buf.len() > 65536 {
            break; // защита от заголовков без конца
        }
    }
    let he = header_end.unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..he]).to_string();
    let body = &buf[he..];
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    let (status, ctype, out) = route(method, path, body, &state);

    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{out}",
        out.as_bytes().len()
    );
    sock.write_all(resp.as_bytes()).await?;
    sock.flush().await
}

/// Маршрутизация запроса панели.
fn route(
    method: &str,
    path: &str,
    body: &[u8],
    state: &AdminState,
) -> (&'static str, &'static str, String) {
    const JSON: &str = "application/json";
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            ("200 OK", "text/html; charset=utf-8", PANEL_HTML.to_string())
        }
        ("GET", "/api/status") => ("200 OK", JSON, state.metrics.status_json(&state.info)),
        ("GET", "/api/log") => ("200 OK", JSON, state.log.json()),
        ("GET", "/api/clients") => ("200 OK", JSON, clients_json(state)),
        ("POST", "/api/clients") => issue_client(body, state),
        ("POST", "/api/clients/revoke") => revoke_client(body, state),
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found".to_string()),
    }
}

/// Список клиентов без секретов (PSK не отдаём).
fn clients_json(state: &AdminState) -> String {
    let kr = state.keyring.lock().expect("keyring mutex");
    let arr: Vec<serde_json::Value> = kr
        .list()
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id, "label": c.label, "created": c.created, "revoked": c.revoked
            })
        })
        .collect();
    serde_json::Value::Array(arr).to_string()
}

/// Выпустить клиента: сгенерировать PSK, собрать `client.json`, вернуть его текст.
fn issue_client(body: &[u8], state: &AdminState) -> (&'static str, &'static str, String) {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let label = v.get("label").and_then(|x| x.as_str()).unwrap_or("");
    let mode = match v.get("mode").and_then(|x| x.as_str()) {
        Some("stream") => TrafficMode::Stream,
        _ => TrafficMode::Datagram,
    };
    let entry = state.keyring.lock().expect("keyring mutex").issue(label);
    let id_part = mode_id(mode);
    let profile = build_client_profile(
        mode,
        &format!("{id_part}-{}", entry.id),
        &state.info.domain,
        &state.info.tunnel_path,
        &state.issue.server_addr,
        &entry.psk_b64,
        &state.issue.server_pub_b64,
        None, // публичный серт (LE) → системные корни; для self-signed патчит установщик -Cert
    );
    if vlyness_profile::validate(&profile).is_err() {
        return ("500 Internal Server Error", "text/plain; charset=utf-8", "профиль некогерентен".to_string());
    }
    state.log.push(format!("[admin] выпущен клиент '{}' ({})", entry.label, entry.id));
    ("200 OK", "application/json", profile.to_json())
}

fn mode_id(mode: TrafficMode) -> &'static str {
    match mode {
        TrafficMode::Datagram => "datagram-h3",
        TrafficMode::Stream => "stream-h2",
        TrafficMode::Segments => "segments-h2",
    }
}

/// Отозвать клиента по id.
fn revoke_client(body: &[u8], state: &AdminState) -> (&'static str, &'static str, String) {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let Some(id) = v.get("id").and_then(|x| x.as_str()) else {
        return ("400 Bad Request", "application/json", "{\"ok\":false}".to_string());
    };
    let ok = state.keyring.lock().expect("keyring mutex").revoke(id);
    if ok {
        state.log.push(format!("[admin] отозван клиент {id}"));
    }
    ("200 OK", "application/json", format!("{{\"ok\":{ok}}}"))
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
#log{background:#0b0d11;border:1px solid #232733;border-radius:10px;padding:10px;height:220px;overflow:auto;
 font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;color:#c3cad6}
.dot{width:9px;height:9px;border-radius:50%;background:#3cb45a;display:inline-block}
button{background:#2a3140;color:#e6e8ee;border:1px solid #3a4354;border-radius:7px;padding:6px 12px;cursor:pointer;font:13px system-ui}
button:hover{background:#333c4e}
input,select{background:#0b0d11;color:#e6e8ee;border:1px solid #2a3140;border-radius:7px;padding:6px 10px;font:13px system-ui}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #1c212b}
th{color:#9aa3b2;font-weight:600}
td code{color:#cdd3df}
.rev{color:#7b8494;text-decoration:line-through}
.btn-rev{padding:2px 8px;font-size:12px}
.row{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}
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
<h2>Клиенты</h2>
<div class="row">
 <input id="label" placeholder="метка (напр. телефон)">
 <select id="mode"><option value="datagram">datagram · h3</option><option value="stream">stream · h2</option></select>
 <button onclick="issue()">Выпустить + скачать</button>
</div>
<table id="clients"><thead><tr><th>ID</th><th>Метка</th><th>Создан</th><th></th></tr></thead><tbody></tbody></table>
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
function esc(s){return (s||'').replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]))}
function ts(s){return new Date(s*1000).toLocaleString()}
async function loadClients(){
 try{
  const cs=await (await fetch('/api/clients',{cache:'no-store'})).json();
  const tb=document.querySelector('#clients tbody');tb.innerHTML='';
  for(const c of cs){
   const tr=document.createElement('tr');
   const act=c.revoked?'<span class="rev">отозван</span>':'<button class="btn-rev" data-id="'+c.id+'">Отозвать</button>';
   tr.innerHTML='<td><code>'+esc(c.id)+'</code></td><td'+(c.revoked?' class="rev"':'')+'>'+esc(c.label)+
     '</td><td>'+ts(c.created)+'</td><td>'+act+'</td>';
   tb.appendChild(tr);
  }
  tb.querySelectorAll('button[data-id]').forEach(b=>b.onclick=()=>revoke(b.dataset.id));
 }catch(e){}
}
async function issue(){
 const label=document.getElementById('label').value;
 const mode=document.getElementById('mode').value;
 const r=await fetch('/api/clients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,mode})});
 if(!r.ok){alert('ошибка выпуска');return;}
 const txt=await r.text();let id='client';try{id=JSON.parse(txt).id||'client'}catch(e){}
 const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([txt],{type:'application/json'}));
 a.download=id+'.json';a.click();
 document.getElementById('label').value='';loadClients();
}
async function revoke(id){
 if(!confirm('Отозвать '+id+'? Клиент перестанет подключаться.'))return;
 await fetch('/api/clients/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
 loadClients();
}
tick();loadClients();setInterval(tick,2000);
</script>
</body></html>"#;
