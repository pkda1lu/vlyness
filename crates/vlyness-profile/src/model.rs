//! Модель Profile (wire-spec §8, whitelist §5.1).
//!
//! Profile — центральный объект дизайна (§1): единая «легенда», из которой
//! детерминированно выводится **всё наблюдаемое**. Пользователь выбирает профиль
//! целиком, а не крутит поля по отдельности — ручное комбинирование несовместимых
//! опций и убивает конфиги сегодня.

use serde::{Deserialize, Serialize};

/// Полный профиль.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub identity: Identity,
    pub placement: Placement,
    pub carrier: Carrier,
    pub tls: Tls,
    pub http: Http,
    pub session: Session,
    pub traffic: Traffic,
    pub budget: Budget,
    pub schedule: Schedule,
}

/// Домен и сертификат легенды.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub domain: String,
    pub acme: bool,
}

/// Класс площадки (док 02 §3).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PlacementMode {
    /// За общим CDN (TLS терминирует носитель).
    Cdn,
    /// Совмещённый хостинг с органическим трафиком.
    Colo,
    /// Голый VPS напрямую.
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Placement {
    pub mode: PlacementMode,
    pub target_asn_class: String,
}

/// Тип носителя (whitelist §2).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CarrierType {
    /// Арендатор общего CDN (co-tenancy).
    CdnCotenant,
    /// Локальное разрешённое облако.
    LocalCloud,
    /// Разрешённый сервис как канал (dead-drop).
    ServiceChannel,
    /// Refraction / decoy routing.
    Refraction,
    /// Прямое подключение, без носителя.
    Direct,
}

/// Целевой уровень строгости whitelist-фильтра (whitelist §1).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WlLevel {
    /// Собрать под все уровни с деградацией.
    Auto,
    /// Фильтр по IP/ASN.
    Ip,
    /// Фильтр по IP + SNI (нужен ECH).
    Sni,
    /// IP + SNI + поведение (нужен полный shaping).
    Behave,
}

/// Конфигурация ECH (whitelist §5.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ech {
    pub enabled: bool,
    /// Внешний (видимый цензору) public-name — должен быть разрешённым именем носителя.
    #[serde(default)]
    pub public_name: String,
    /// Откуда берётся ECHConfig.
    #[serde(default = "default_ech_source")]
    pub config_source: String,
}

fn default_ech_source() -> String {
    "dns-https-rr".to_string()
}

/// Классический domain fronting (по умолчанию выключен — legacy, whitelist §2.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Front {
    pub enabled: bool,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Carrier {
    #[serde(rename = "type")]
    pub kind: CarrierType,
    #[serde(default)]
    pub endpoint_domain: String,
    pub ech: Ech,
    #[serde(default)]
    pub front: Front,
    pub wl_level_target: WlLevel,
}

/// Параметры TLS-легенды.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tls {
    pub alpn: Vec<String>,
    /// Имя fingerprint-профиля (см. реестр устройств в `validate`).
    pub fp: String,
    /// Шлётся ли post-quantum key_share (X25519MLKEM768).
    pub pq_keyshare: bool,
}

/// HTTP-маршруты несущей.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Routes {
    /// Шаблон пути сегмента (нисходящий поток), напр. `/v1/media/{sid}/seg/{n}.m4s`.
    pub seg: String,
    /// Шаблон пути телеметрии (восходящий поток), напр. `/v1/media/{sid}/telemetry`.
    pub tel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http {
    /// Версия HTTP: 2 или 3.
    pub version: u8,
    /// Имя профиля HTTP/2 SETTINGS (должно соответствовать `tls.fp`).
    pub settings_profile: String,
    /// User-Agent (должен соответствовать семейству устройства `tls.fp`).
    pub ua: String,
    pub routes: Routes,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    /// Имя cookie для токена (§6.2).
    pub auth_cookie: String,
    /// Константа профиля во втором cookie.
    pub profile_cookie_val: String,
}

/// Режим трафика несущей (§5).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrafficMode {
    /// Один двунаправленный HTTP/2-стрим.
    Stream,
    /// GET сегментов + POST телеметрии (медиа-профиль).
    Segments,
    /// HTTP/3 + WebTransport datagrams (RTC).
    Datagram,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Traffic {
    pub mode: TrafficMode,
    #[serde(default)]
    pub seg_interval_ms: u64,
    #[serde(default)]
    pub seg_jitter_ms: u64,
    /// Имя эмпирического распределения длин (резолвится модулем shaping).
    #[serde(default)]
    pub len_profile: String,
    /// Целевое соотношение down:up (для медиа ~15).
    pub target_ratio_down_up: u32,
    pub idle_fill: bool,
}

/// Бюджет соединений (совпадает по смыслу с `vlyness-discipline::budget`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Budget {
    pub max_tls_conns: u32,
    pub min_conn_interval_ms: u64,
    pub backoff_base_ms: u64,
    pub backoff_cap_ms: u64,
    /// Ротация fingerprint. Должна быть false: смена под нагрузкой штрафуется (§4, §9).
    pub rotate_fingerprint: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Schedule {
    /// Окно активности [начало, конец) в часах, 0..=24.
    pub active_hours: [u8; 2],
    /// Максимальная длина сессии в минутах.
    pub max_session_min: u32,
}

impl Profile {
    /// Разбор из JSON.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Сериализация в JSON (pretty).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Profile сериализуется")
    }

    /// Валидный референс-профиль по умолчанию: медиа-ABR поверх HTTP/2 за CDN,
    /// собранный под WL-SNI (ECH включён). Совпадает с примером из wire-spec §8.
    pub fn example_media() -> Self {
        Profile {
            id: "media-abr-h2-v1".to_string(),
            identity: Identity { domain: "app.example-media.tld".to_string(), acme: true },
            placement: Placement {
                mode: PlacementMode::Cdn,
                target_asn_class: "cdn".to_string(),
            },
            carrier: Carrier {
                kind: CarrierType::CdnCotenant,
                endpoint_domain: "app.example-media.tld".to_string(),
                ech: Ech {
                    enabled: true,
                    public_name: "cdn-public.example-cdn.net".to_string(),
                    config_source: "dns-https-rr".to_string(),
                },
                front: Front::default(),
                wl_level_target: WlLevel::Sni,
            },
            tls: Tls {
                alpn: vec!["h2".to_string()],
                fp: "okhttp-4".to_string(),
                pq_keyshare: false,
            },
            http: Http {
                version: 2,
                settings_profile: "okhttp-4".to_string(),
                ua: "ExampleMedia/3.2 (Android 14; okhttp/4.12)".to_string(),
                routes: Routes {
                    seg: "/v1/media/{sid}/seg/{n}.m4s".to_string(),
                    tel: "/v1/media/{sid}/telemetry".to_string(),
                },
            },
            session: Session {
                auth_cookie: "sid".to_string(),
                profile_cookie_val: "m1".to_string(),
            },
            traffic: Traffic {
                mode: TrafficMode::Segments,
                seg_interval_ms: 4000,
                seg_jitter_ms: 800,
                len_profile: "media-abr-v1".to_string(),
                target_ratio_down_up: 15,
                idle_fill: true,
            },
            budget: Budget {
                max_tls_conns: 1,
                min_conn_interval_ms: 800,
                backoff_base_ms: 2000,
                backoff_cap_ms: 300_000,
                rotate_fingerprint: false,
            },
            schedule: Schedule { active_hours: [7, 24], max_session_min: 180 },
        }
    }
}
