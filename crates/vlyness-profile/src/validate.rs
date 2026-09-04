//! Валидатор инварианта когерентности (дизайн §1).
//!
//! Главный анти-детект принцип модели угроз: **ТСПУ ловит не «плохой» признак, а
//! несогласованность между слоями** (01 §4, вывод 2). Поэтому профиль проверяется
//! не на «правильность полей по отдельности», а на то, что все наблюдаемые слои —
//! DNS/SNI/сертификат, JA3, HTTP/2 SETTINGS, User-Agent, форма трафика, ASN, ECH —
//! описывают **одно и то же приложение**. Несовместимый профиль отклоняется до старта.
//!
//! Валидатор собирает **все** нарушения, а не первое: чинить легенду удобнее списком.

use crate::model::*;

/// Одно нарушение когерентности.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoherenceError {
    /// Стабильный код для тестов/логов.
    pub code: &'static str,
    /// Человекочитаемое объяснение.
    pub message: String,
}

impl CoherenceError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        CoherenceError { code, message: message.into() }
    }
}

/// Семейство устройства: связывает fingerprint, HTTP/2 SETTINGS, токен User-Agent и
/// признак post-quantum key_share. Все четыре должны сходиться к одному устройству.
struct DeviceFamily {
    fp: &'static str,
    settings_profile: &'static str,
    /// Подстрока, обязанная присутствовать в User-Agent (регистронезависимо).
    ua_contains: &'static str,
    /// Шлёт ли это устройство X25519MLKEM768.
    pq_keyshare: bool,
}

/// Реестр известных «спокойных» профилей (модель угроз 01 §2, L2: массовые
/// клиент-стеки вроде OkHttp/Cronet/NSURLSession, а не абстрактный браузер).
const DEVICE_REGISTRY: &[DeviceFamily] = &[
    DeviceFamily { fp: "okhttp-4", settings_profile: "okhttp-4", ua_contains: "okhttp", pq_keyshare: false },
    DeviceFamily { fp: "cronet-android", settings_profile: "cronet-android", ua_contains: "Cronet", pq_keyshare: true },
    DeviceFamily { fp: "nsurlsession-ios", settings_profile: "nsurlsession-ios", ua_contains: "CFNetwork", pq_keyshare: false },
    DeviceFamily { fp: "firefox-128", settings_profile: "firefox-128", ua_contains: "Firefox", pq_keyshare: true },
];

fn lookup_family(fp: &str) -> Option<&'static DeviceFamily> {
    DEVICE_REGISTRY.iter().find(|d| d.fp == fp)
}

/// Проверить профиль. `Ok(())` — легенда когерентна; иначе список всех нарушений.
pub fn validate(p: &Profile) -> Result<(), Vec<CoherenceError>> {
    let mut errs = Vec::new();

    check_device_coherence(p, &mut errs);
    check_alpn_http_version(p, &mut errs);
    check_carrier_placement(p, &mut errs);
    check_traffic_placement(p, &mut errs);
    check_ech_for_whitelist(p, &mut errs);
    check_ech_front_exclusive(p, &mut errs);
    check_budget(p, &mut errs);
    check_schedule(p, &mut errs);
    check_traffic_params(p, &mut errs);
    check_routes(p, &mut errs);

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// §1/§4: fingerprint ↔ SETTINGS ↔ UA ↔ PQ описывают одно устройство.
fn check_device_coherence(p: &Profile, errs: &mut Vec<CoherenceError>) {
    let Some(fam) = lookup_family(&p.tls.fp) else {
        errs.push(CoherenceError::new(
            "unknown_fingerprint",
            format!("неизвестный fingerprint '{}': нет в реестре устройств", p.tls.fp),
        ));
        return;
    };
    if p.http.settings_profile != fam.settings_profile {
        errs.push(CoherenceError::new(
            "settings_fp_mismatch",
            format!(
                "http.settings_profile '{}' не соответствует fingerprint '{}' (ожидалось '{}')",
                p.http.settings_profile, p.tls.fp, fam.settings_profile
            ),
        ));
    }
    if !p.http.ua.to_lowercase().contains(&fam.ua_contains.to_lowercase()) {
        errs.push(CoherenceError::new(
            "ua_fp_mismatch",
            format!(
                "User-Agent не содержит маркер '{}', ожидаемый для fingerprint '{}'",
                fam.ua_contains, p.tls.fp
            ),
        ));
    }
    if p.tls.pq_keyshare != fam.pq_keyshare {
        errs.push(CoherenceError::new(
            "pq_keyshare_mismatch",
            format!(
                "tls.pq_keyshare={} не соответствует устройству '{}' (ожидалось {}); \
                 имитация с рассогласованием PQ — маркер (01 §2 L2)",
                p.tls.pq_keyshare, p.tls.fp, fam.pq_keyshare
            ),
        ));
    }
}

/// ALPN должен соответствовать версии HTTP.
fn check_alpn_http_version(p: &Profile, errs: &mut Vec<CoherenceError>) {
    let want = match p.http.version {
        2 => "h2",
        3 => "h3",
        other => {
            errs.push(CoherenceError::new(
                "bad_http_version",
                format!("http.version {other} не поддерживается (только 2 или 3)"),
            ));
            return;
        }
    };
    if !p.tls.alpn.iter().any(|a| a == want) {
        errs.push(CoherenceError::new(
            "alpn_http_mismatch",
            format!("ALPN не содержит '{want}' при http.version={}", p.http.version),
        ));
    }
}

/// whitelist §2/§5.1: тип носителя ↔ класс площадки.
fn check_carrier_placement(p: &Profile, errs: &mut Vec<CoherenceError>) {
    let mode = p.placement.mode;
    let ok = match p.carrier.kind {
        CarrierType::CdnCotenant => mode == PlacementMode::Cdn,
        CarrierType::LocalCloud => matches!(mode, PlacementMode::Cdn | PlacementMode::Colo),
        CarrierType::ServiceChannel => mode != PlacementMode::Direct,
        CarrierType::Refraction => true, // особый путь, площадка не ограничена
        CarrierType::Direct => mode == PlacementMode::Direct,
    };
    if !ok {
        errs.push(CoherenceError::new(
            "carrier_placement_mismatch",
            format!(
                "носитель {:?} несовместим с площадкой {:?}",
                p.carrier.kind, mode
            ),
        ));
    }
}

/// док 02 §5: режим трафика ↔ класс площадки.
/// stream — прямое/colo; segments — за CDN/colo; datagram — не через service-channel.
fn check_traffic_placement(p: &Profile, errs: &mut Vec<CoherenceError>) {
    let mode = p.placement.mode;
    match p.traffic.mode {
        TrafficMode::Stream => {
            if mode == PlacementMode::Cdn {
                errs.push(CoherenceError::new(
                    "stream_behind_cdn",
                    "traffic.mode=stream несовместим с placement=cdn: бесконечный \
                     двунаправленный стрим не переживает CDN (нужен segments)",
                ));
            }
        }
        TrafficMode::Segments => {
            if mode == PlacementMode::Direct {
                errs.push(CoherenceError::new(
                    "segments_direct",
                    "traffic.mode=segments рассчитан на носитель (cdn/colo), а не direct",
                ));
            }
        }
        TrafficMode::Datagram => {
            if p.carrier.kind == CarrierType::ServiceChannel {
                errs.push(CoherenceError::new(
                    "datagram_service_channel",
                    "traffic.mode=datagram несовместим с носителем service-channel",
                ));
            }
        }
    }
}

/// whitelist §5.2: под WL-SNI/WL-BEHAVE для co-tenancy обязателен ECH с public-name.
/// REALITY-подмена SNI бесполезна: дроп по IP наступает раньше проверки SNI.
fn check_ech_for_whitelist(p: &Profile, errs: &mut Vec<CoherenceError>) {
    let needs_ech = matches!(p.carrier.wl_level_target, WlLevel::Sni | WlLevel::Behave)
        && matches!(p.carrier.kind, CarrierType::CdnCotenant | CarrierType::LocalCloud);
    if needs_ech {
        if !p.carrier.ech.enabled {
            errs.push(CoherenceError::new(
                "ech_required",
                "для wl_level_target=sni/behave на co-tenancy обязателен ECH \
                 (иначе SNI виден и дропается)",
            ));
        } else if p.carrier.ech.public_name.trim().is_empty() {
            errs.push(CoherenceError::new(
                "ech_public_name_empty",
                "ECH включён, но public_name пуст: внешний SNI обязан быть \
                 разрешённым именем носителя",
            ));
        }
    }
}

/// ECH и legacy-fronting — взаимоисключающие стратегии сокрытия SNI.
fn check_ech_front_exclusive(p: &Profile, errs: &mut Vec<CoherenceError>) {
    if p.carrier.ech.enabled && p.carrier.front.enabled {
        errs.push(CoherenceError::new(
            "ech_front_conflict",
            "одновременно включены ECH и legacy domain fronting — выберите одно",
        ));
    }
}

/// §4/§9: ротация fingerprint запрещена; ёмкость и интервалы осмысленны.
fn check_budget(p: &Profile, errs: &mut Vec<CoherenceError>) {
    if p.budget.rotate_fingerprint {
        errs.push(CoherenceError::new(
            "fingerprint_rotation",
            "budget.rotate_fingerprint=true запрещено: смена fingerprint под нагрузкой \
             даёт расширенный штраф ТСПУ 600 с (§4, §9)",
        ));
    }
    if p.budget.max_tls_conns == 0 {
        errs.push(CoherenceError::new("zero_conns", "budget.max_tls_conns должно быть ≥ 1"));
    }
    if p.budget.max_tls_conns > 2 {
        errs.push(CoherenceError::new(
            "too_many_conns",
            format!(
                "budget.max_tls_conns={} превышает 2: >3 параллельных TLS к одному SNI — \
                 самый частый триггер ТСПУ (признак №5)",
                p.budget.max_tls_conns
            ),
        ));
    }
    if p.budget.backoff_base_ms == 0 || p.budget.backoff_cap_ms < p.budget.backoff_base_ms {
        errs.push(CoherenceError::new(
            "bad_backoff",
            "backoff_base_ms>0 и backoff_cap_ms≥backoff_base_ms",
        ));
    }
}

/// Осмысленность расписания активности.
fn check_schedule(p: &Profile, errs: &mut Vec<CoherenceError>) {
    let [start, end] = p.schedule.active_hours;
    if start >= end || end > 24 {
        errs.push(CoherenceError::new(
            "bad_active_hours",
            format!("active_hours [{start},{end}) некорректны (нужно 0≤start<end≤24)"),
        ));
    }
    if p.schedule.max_session_min == 0 {
        errs.push(CoherenceError::new("zero_session", "max_session_min должно быть > 0"));
    }
}

/// Параметры трафика, специфичные для режима.
fn check_traffic_params(p: &Profile, errs: &mut Vec<CoherenceError>) {
    if p.traffic.target_ratio_down_up == 0 {
        errs.push(CoherenceError::new(
            "zero_ratio",
            "target_ratio_down_up должно быть ≥ 1",
        ));
    }
    if p.traffic.mode == TrafficMode::Segments {
        if p.traffic.seg_interval_ms == 0 {
            errs.push(CoherenceError::new(
                "zero_seg_interval",
                "segments-режим требует seg_interval_ms > 0 (иначе нет cadence)",
            ));
        }
        if p.traffic.len_profile.trim().is_empty() {
            errs.push(CoherenceError::new(
                "no_len_profile",
                "segments-режим требует len_profile (распределение длин для sampler §8.1)",
            ));
        }
    }
}

/// Шаблоны маршрутов должны содержать нужные плейсхолдеры.
fn check_routes(p: &Profile, errs: &mut Vec<CoherenceError>) {
    if p.traffic.mode == TrafficMode::Segments {
        let seg = &p.http.routes.seg;
        if !seg.contains("{sid}") || !seg.contains("{n}") {
            errs.push(CoherenceError::new(
                "bad_seg_route",
                "routes.seg должен содержать {sid} и {n} для segments-режима",
            ));
        }
        if !p.http.routes.tel.contains("{sid}") {
            errs.push(CoherenceError::new(
                "bad_tel_route",
                "routes.tel должен содержать {sid}",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(res: &Result<(), Vec<CoherenceError>>) -> Vec<&'static str> {
        match res {
            Ok(()) => vec![],
            Err(e) => e.iter().map(|c| c.code).collect(),
        }
    }

    #[test]
    fn example_media_is_coherent() {
        let p = Profile::example_media();
        assert_eq!(validate(&p), Ok(()), "референс-профиль обязан проходить");
    }

    #[test]
    fn example_survives_json_roundtrip() {
        let p = Profile::example_media();
        let json = p.to_json();
        let back = Profile::from_json(&json).unwrap();
        assert_eq!(p, back);
        assert_eq!(validate(&back), Ok(()));
    }

    #[test]
    fn detects_settings_fp_mismatch() {
        let mut p = Profile::example_media();
        p.http.settings_profile = "firefox-128".to_string(); // fp остался okhttp-4
        assert!(codes(&validate(&p)).contains(&"settings_fp_mismatch"));
    }

    #[test]
    fn detects_ua_mismatch() {
        let mut p = Profile::example_media();
        p.http.ua = "Mozilla/5.0 (Windows NT 10.0) Firefox/128".to_string();
        let c = codes(&validate(&p));
        assert!(c.contains(&"ua_fp_mismatch"));
    }

    #[test]
    fn detects_pq_mismatch() {
        let mut p = Profile::example_media();
        p.tls.pq_keyshare = true; // okhttp-4 не шлёт MLKEM
        assert!(codes(&validate(&p)).contains(&"pq_keyshare_mismatch"));
    }

    #[test]
    fn detects_unknown_fingerprint() {
        let mut p = Profile::example_media();
        p.tls.fp = "chrome-131-spoof".to_string();
        assert!(codes(&validate(&p)).contains(&"unknown_fingerprint"));
    }

    #[test]
    fn detects_alpn_mismatch() {
        let mut p = Profile::example_media();
        p.tls.alpn = vec!["http/1.1".to_string()];
        assert!(codes(&validate(&p)).contains(&"alpn_http_mismatch"));
    }

    #[test]
    fn detects_stream_behind_cdn() {
        let mut p = Profile::example_media();
        p.traffic.mode = TrafficMode::Stream;
        assert!(codes(&validate(&p)).contains(&"stream_behind_cdn"));
    }

    #[test]
    fn detects_carrier_placement_mismatch() {
        let mut p = Profile::example_media();
        p.placement.mode = PlacementMode::Direct; // cdn-cotenant требует cdn
        let c = codes(&validate(&p));
        assert!(c.contains(&"carrier_placement_mismatch"));
    }

    #[test]
    fn detects_missing_ech_under_wl_sni() {
        let mut p = Profile::example_media();
        p.carrier.ech.enabled = false; // wl=sni + co-tenancy без ECH
        assert!(codes(&validate(&p)).contains(&"ech_required"));
    }

    #[test]
    fn detects_empty_ech_public_name() {
        let mut p = Profile::example_media();
        p.carrier.ech.public_name = "".to_string();
        assert!(codes(&validate(&p)).contains(&"ech_public_name_empty"));
    }

    #[test]
    fn detects_ech_front_conflict() {
        let mut p = Profile::example_media();
        p.carrier.front.enabled = true; // ECH уже включён
        assert!(codes(&validate(&p)).contains(&"ech_front_conflict"));
    }

    #[test]
    fn detects_fingerprint_rotation() {
        let mut p = Profile::example_media();
        p.budget.rotate_fingerprint = true;
        assert!(codes(&validate(&p)).contains(&"fingerprint_rotation"));
    }

    #[test]
    fn detects_too_many_conns() {
        let mut p = Profile::example_media();
        p.budget.max_tls_conns = 5;
        assert!(codes(&validate(&p)).contains(&"too_many_conns"));
    }

    #[test]
    fn detects_bad_schedule() {
        let mut p = Profile::example_media();
        p.schedule.active_hours = [20, 8]; // start >= end
        assert!(codes(&validate(&p)).contains(&"bad_active_hours"));
    }

    #[test]
    fn detects_bad_seg_route() {
        let mut p = Profile::example_media();
        p.http.routes.seg = "/v1/media/stream".to_string(); // нет {sid}/{n}
        assert!(codes(&validate(&p)).contains(&"bad_seg_route"));
    }

    #[test]
    fn collects_multiple_violations_at_once() {
        let mut p = Profile::example_media();
        p.budget.rotate_fingerprint = true;
        p.tls.pq_keyshare = true;
        p.schedule.active_hours = [10, 10];
        let c = codes(&validate(&p));
        assert!(c.contains(&"fingerprint_rotation"));
        assert!(c.contains(&"pq_keyshare_mismatch"));
        assert!(c.contains(&"bad_active_hours"));
        assert!(c.len() >= 3);
    }
}
