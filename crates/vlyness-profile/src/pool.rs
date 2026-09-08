//! Пул носителей и ротация (whitelist §4, §5.3).
//!
//! Дисциплина ([`vlyness_discipline`](../vlyness_discipline)) при третьем срабатывании
//! blackhole рекомендует `AfterFreeze::SwitchProfile` — «сменить профиль целиком».
//! Здесь живёт потребитель этой рекомендации.
//!
//! Зачем пул вообще (док 05 §4): когда белый список уже включён, клиент **не может
//! скачать новый профиль обычным путём** — интернет закрыт. Поэтому носители носятся
//! с собой заранее, и пока жив хоть один — связь есть. Отсюда требования:
//! - профили предзагружены и самодостаточны (у каждого свой [`Endpoint`]);
//! - перебор идёт «дёшево → дорого» ([`CarrierType::cost`]): co-tenancy → … → сервис-канал;
//! - упавший носитель уходит в остывание с **эскалацией** (повторные падения — дольше),
//!   а не выбрасывается: белый список меняется, и носитель может ожить.
//!
//! Модуль чистый: время передаётся снаружи (`now_ms`), как в бюджете соединений, —
//! поэтому ротация детерминированно тестируется.

use crate::model::Profile;
use crate::validate::{validate, CoherenceError};

/// Базовое время остывания упавшего носителя, мс (5 минут).
pub const DEFAULT_COOLDOWN_MS: u64 = 300_000;
/// Потолок остывания, мс (1 час).
pub const MAX_COOLDOWN_MS: u64 = 3_600_000;

/// Ошибка построения пула.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("пул пуст: нужен хотя бы один носитель")]
    Empty,
    #[error("профиль '{id}' некогерентен: {}", format_errs(.errors))]
    Incoherent { id: String, errors: Vec<CoherenceError> },
    #[error("профиль '{0}' не содержит endpoint: он непригоден для пула (нечего подключать)")]
    NoEndpoint(String),
}

fn format_errs(errors: &[CoherenceError]) -> String {
    errors.iter().map(|e| e.code).collect::<Vec<_>>().join(", ")
}

/// Один носитель в пуле.
#[derive(Debug, Clone)]
struct Entry {
    profile: Profile,
    /// До этого времени носитель не предлагается (остывание после падения).
    blocked_until_ms: u64,
    /// Сколько раз подряд падал — определяет длину остывания.
    strikes: u32,
}

/// Пул носителей с ротацией.
#[derive(Debug, Clone)]
pub struct CarrierPool {
    entries: Vec<Entry>,
    /// Индекс текущего выбранного носителя.
    current: Option<usize>,
    cooldown_ms: u64,
}

impl CarrierPool {
    /// Собрать пул. Все профили валидируются на когерентность (§1) и обязаны иметь
    /// [`Endpoint`](crate::model::Endpoint) — иначе к ним нечем подключаться.
    /// Порядок перебора задаётся [`CarrierType::cost`](crate::model::CarrierType::cost).
    pub fn new(profiles: Vec<Profile>, cooldown_ms: u64) -> Result<Self, PoolError> {
        if profiles.is_empty() {
            return Err(PoolError::Empty);
        }
        for p in &profiles {
            if let Err(errors) = validate(p) {
                return Err(PoolError::Incoherent { id: p.id.clone(), errors });
            }
            if p.endpoint.is_none() {
                return Err(PoolError::NoEndpoint(p.id.clone()));
            }
        }
        let mut entries: Vec<Entry> = profiles
            .into_iter()
            .map(|profile| Entry { profile, blocked_until_ms: 0, strikes: 0 })
            .collect();
        // Стабильная сортировка: при равной цене сохраняется порядок из конфигурации.
        entries.sort_by_key(|e| e.profile.carrier.kind.cost());
        Ok(CarrierPool { entries, current: None, cooldown_ms })
    }

    /// Пул с временем остывания по умолчанию.
    pub fn with_defaults(profiles: Vec<Profile>) -> Result<Self, PoolError> {
        Self::new(profiles, DEFAULT_COOLDOWN_MS)
    }

    /// Выбрать лучший доступный носитель на момент `now_ms` и сделать его текущим.
    ///
    /// Возвращает `None`, если все носители остывают — тогда вызывающему остаётся ждать
    /// (см. [`next_available_ms`](CarrierPool::next_available_ms)).
    pub fn select(&mut self, now_ms: u64) -> Option<&Profile> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.blocked_until_ms <= now_ms)?;
        self.current = Some(idx);
        Some(&self.entries[idx].profile)
    }

    /// Текущий выбранный носитель.
    pub fn current(&self) -> Option<&Profile> {
        self.current.map(|i| &self.entries[i].profile)
    }

    /// Текущий носитель не работает (blackhole/сбой): отправить его в остывание и
    /// снять с текущих. Остывание растёт с числом падений подряд.
    pub fn mark_failed(&mut self, now_ms: u64) {
        let Some(idx) = self.current.take() else {
            return;
        };
        let entry = &mut self.entries[idx];
        entry.strikes = entry.strikes.saturating_add(1);
        // Экспоненциальный рост: base * 2^(strikes-1), с потолком.
        let shift = (entry.strikes - 1).min(16);
        let cooldown = (self.cooldown_ms as u128) << shift;
        let cooldown = cooldown.min(MAX_COOLDOWN_MS as u128) as u64;
        entry.blocked_until_ms = now_ms.saturating_add(cooldown);
    }

    /// Текущий носитель работает: сбросить его счётчик падений.
    pub fn mark_healthy(&mut self) {
        if let Some(idx) = self.current {
            self.entries[idx].strikes = 0;
            self.entries[idx].blocked_until_ms = 0;
        }
    }

    /// Сколько носителей доступно прямо сейчас.
    pub fn available(&self, now_ms: u64) -> usize {
        self.entries.iter().filter(|e| e.blocked_until_ms <= now_ms).count()
    }

    /// Когда освободится ближайший носитель (если сейчас все остывают).
    pub fn next_available_ms(&self, now_ms: u64) -> Option<u64> {
        if self.available(now_ms) > 0 {
            return None;
        }
        self.entries.iter().map(|e| e.blocked_until_ms).min()
    }

    /// Всего носителей в пуле.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Идентификаторы носителей в порядке перебора (для логов/диагностики).
    pub fn ids(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.profile.id.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CarrierType, Endpoint, PlacementMode, WlLevel};

    /// Валидный профиль с endpoint и заданным типом носителя.
    fn profile(id: &str, kind: CarrierType) -> Profile {
        let mut p = Profile::example_media();
        p.id = id.to_string();
        p.carrier.kind = kind;
        // Площадка должна быть совместима с носителем (проверяет валидатор).
        p.placement.mode = match kind {
            CarrierType::CdnCotenant => PlacementMode::Cdn,
            CarrierType::LocalCloud => PlacementMode::Cdn,
            CarrierType::Direct => PlacementMode::Direct,
            CarrierType::ServiceChannel => PlacementMode::Colo,
            CarrierType::Refraction => PlacementMode::Cdn,
        };
        // Direct несовместим с segments; для него берём stream и выключаем ECH-требование.
        if kind == CarrierType::Direct {
            p.traffic.mode = crate::model::TrafficMode::Stream;
            p.carrier.wl_level_target = WlLevel::Ip;
            p.carrier.ech.enabled = false;
        }
        p.endpoint = Some(Endpoint {
            server_addr: "example.tld:443".to_string(),
            sni: "example.tld".to_string(),
            ca_pem_path: None,
            psk_b64: "cHNr".to_string(),
            server_pub_b64: "cHVi".to_string(),
            ech_config_b64: Some("ZWNo".to_string()),
        });
        p
    }

    #[test]
    fn orders_by_cost_cheapest_first() {
        let pool = CarrierPool::with_defaults(vec![
            profile("svc", CarrierType::ServiceChannel),
            profile("cdn", CarrierType::CdnCotenant),
            profile("local", CarrierType::LocalCloud),
        ])
        .unwrap();
        assert_eq!(pool.ids(), vec!["cdn", "local", "svc"]);
    }

    #[test]
    fn select_picks_cheapest_then_rotates_on_failure() {
        let mut pool = CarrierPool::new(
            vec![
                profile("cdn", CarrierType::CdnCotenant),
                profile("local", CarrierType::LocalCloud),
                profile("svc", CarrierType::ServiceChannel),
            ],
            1000,
        )
        .unwrap();

        assert_eq!(pool.select(0).unwrap().id, "cdn");
        pool.mark_failed(0); // cdn заблокирован до 1000
        assert_eq!(pool.select(0).unwrap().id, "local");
        pool.mark_failed(0); // local заблокирован до 1000
        assert_eq!(pool.select(0).unwrap().id, "svc");
    }

    #[test]
    fn all_blocked_reports_when_next_frees() {
        let mut pool = CarrierPool::new(vec![profile("cdn", CarrierType::CdnCotenant)], 1000).unwrap();
        pool.select(0);
        pool.mark_failed(0);
        assert_eq!(pool.available(0), 0);
        assert!(pool.select(0).is_none());
        assert_eq!(pool.next_available_ms(0), Some(1000));
        // По истечении остывания носитель снова доступен.
        assert_eq!(pool.select(1000).unwrap().id, "cdn");
        assert_eq!(pool.next_available_ms(1000), None);
    }

    #[test]
    fn cooldown_escalates_with_repeated_failures() {
        let mut pool = CarrierPool::new(vec![profile("cdn", CarrierType::CdnCotenant)], 1000).unwrap();
        pool.select(0);
        pool.mark_failed(0); // страйк 1 → 1000
        assert_eq!(pool.next_available_ms(0), Some(1000));

        pool.select(1000);
        pool.mark_failed(1000); // страйк 2 → 2000 → до 3000
        assert_eq!(pool.next_available_ms(1000), Some(3000));

        pool.select(3000);
        pool.mark_failed(3000); // страйк 3 → 4000 → до 7000
        assert_eq!(pool.next_available_ms(3000), Some(7000));
    }

    #[test]
    fn healthy_resets_escalation() {
        let mut pool = CarrierPool::new(vec![profile("cdn", CarrierType::CdnCotenant)], 1000).unwrap();
        pool.select(0);
        pool.mark_failed(0);
        pool.select(1000);
        pool.mark_healthy();
        pool.mark_failed(1000); // счётчик сброшен → снова базовое остывание
        assert_eq!(pool.next_available_ms(1000), Some(2000));
    }

    #[test]
    fn cooldown_is_capped() {
        let mut pool = CarrierPool::new(vec![profile("cdn", CarrierType::CdnCotenant)], MAX_COOLDOWN_MS).unwrap();
        pool.select(0);
        pool.mark_failed(0);
        pool.select(MAX_COOLDOWN_MS);
        pool.mark_failed(MAX_COOLDOWN_MS);
        // Второе падение не должно превысить потолок остывания.
        assert_eq!(pool.next_available_ms(MAX_COOLDOWN_MS), Some(MAX_COOLDOWN_MS * 2));
    }

    #[test]
    fn rejects_empty_pool() {
        assert!(matches!(CarrierPool::with_defaults(vec![]), Err(PoolError::Empty)));
    }

    #[test]
    fn rejects_profile_without_endpoint() {
        let mut p = profile("cdn", CarrierType::CdnCotenant);
        p.endpoint = None;
        assert!(matches!(
            CarrierPool::with_defaults(vec![p]),
            Err(PoolError::NoEndpoint(_))
        ));
    }

    #[test]
    fn rejects_incoherent_profile() {
        let mut p = profile("cdn", CarrierType::CdnCotenant);
        p.budget.rotate_fingerprint = true; // запрещено (§4, §9)
        assert!(matches!(
            CarrierPool::with_defaults(vec![p]),
            Err(PoolError::Incoherent { .. })
        ));
    }
}
