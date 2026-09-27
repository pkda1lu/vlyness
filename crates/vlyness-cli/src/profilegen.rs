//! Генератор клиентского профиля (`client.json`) — общий для `vlyness-setup` и
//! веб-панели (выпуск клиента). Профиль когерентный Direct/datagram|stream, проходит
//! валидатор перед использованием.

use vlyness_profile::{
    Budget, Carrier, CarrierType, Ech, Endpoint, Front, Http, Identity, Placement, PlacementMode,
    Profile, Routes, Schedule, Session, Tls, Traffic, TrafficMode, WlLevel,
};

/// Собрать клиентский профиль. `mode` задаёт форму (datagram/h3 или stream/h2),
/// `server_addr` — куда клиент коннектится (`host:port`), `ca_pem_path` — доверенный
/// PEM для самоподписанного сервера (иначе `None` = системные корни).
#[allow(clippy::too_many_arguments)]
pub fn build_client_profile(
    mode: TrafficMode,
    id: &str,
    domain: &str,
    tunnel_path: &str,
    server_addr: &str,
    psk_b64: &str,
    server_pub_b64: &str,
    ca_pem_path: Option<String>,
) -> Profile {
    let is_h3 = mode == TrafficMode::Datagram;
    let (alpn, fp, ua, ver, pq) = if is_h3 {
        (
            "h3",
            "firefox-128",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            3u8,
            true,
        )
    } else {
        ("h2", "okhttp-4", "ExampleMedia/3.2 (Android 14; okhttp/4.12)", 2u8, false)
    };
    Profile {
        id: id.to_string(),
        identity: Identity { domain: domain.to_string(), acme: true },
        placement: Placement { mode: PlacementMode::Direct, target_asn_class: "vps".to_string() },
        carrier: Carrier {
            kind: CarrierType::Direct,
            endpoint_domain: domain.to_string(),
            ech: Ech { enabled: false, public_name: String::new(), config_source: "dns-https-rr".to_string() },
            front: Front::default(),
            wl_level_target: WlLevel::Ip,
        },
        tls: Tls { alpn: vec![alpn.to_string()], fp: fp.to_string(), pq_keyshare: pq },
        http: Http {
            version: ver,
            settings_profile: fp.to_string(),
            ua: ua.to_string(),
            routes: Routes {
                seg: format!("{tunnel_path}/{{sid}}/media/{{n}}"),
                tel: format!("{tunnel_path}/{{sid}}/stats"),
            },
        },
        session: Session { auth_cookie: "sid".to_string(), profile_cookie_val: "v1".to_string() },
        traffic: Traffic {
            mode,
            seg_interval_ms: if is_h3 { 1000 } else { 4000 },
            seg_jitter_ms: if is_h3 { 200 } else { 800 },
            len_profile: "media-abr-v1".to_string(),
            target_ratio_down_up: if is_h3 { 3 } else { 15 },
            idle_fill: true,
            packet_up: false,
        },
        budget: Budget {
            max_tls_conns: 1,
            min_conn_interval_ms: 800,
            backoff_base_ms: 2000,
            backoff_cap_ms: 300_000,
            rotate_fingerprint: false,
        },
        schedule: Schedule { active_hours: [7, 24], max_session_min: 180 },
        endpoint: Some(Endpoint {
            server_addr: server_addr.to_string(),
            sni: domain.to_string(),
            ca_pem_path,
            psk_b64: psk_b64.to_string(),
            server_pub_b64: server_pub_b64.to_string(),
            ech_config_b64: None,
        }),
    }
}
