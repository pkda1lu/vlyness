//! Детектор blackhole и контроллер заморозки (дизайн §9).
//!
//! ТСПУ в 2026 при срабатывании делает **тихий дроп** пакетов на 120–600 с, а не
//! RST (модель угроз 01 §2, L3). Тихий дроп хуже RST: наивный клиент не понимает,
//! что заблокирован, ретраится в цикле и получает расширенный штраф (600 с) —
//! в т.ч. за смену fingerprint под нагрузкой (признак №4).
//!
//! Отсюда две задачи:
//! 1. **Отличить** «нас заморозили» от «сеть/сервер просто упали». Признак заморозки
//!    (§9): исходящее уходит, входящего ноль — **при этом другие хосты доступны**.
//! 2. **Не усугублять**: при заморозке уйти в тишину дольше окна ТСПУ (150 с, затем
//!    600 с), без смены fingerprint/SNI; при повторе — сменить профиль целиком.

use crate::clock::Millis;

/// Оценка состояния канала.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Ответы приходят или тишина ещё в норме.
    Healthy,
    /// Тишина затянулась, но контрольный сигнал не даёт уверенности (нет свежих данных).
    Suspect,
    /// Мы шлём, ответа нет, а контрольные хосты доступны → нас целенаправленно дропают.
    Blackholed,
    /// Мы шлём, ответа нет, и контрольные хосты тоже недоступны → это не про нас.
    NetworkDown,
}

/// Детектор: копит факты об отправке/приёме и о доступности контрольной точки,
/// по запросу выдаёт [`Health`]. Ничего не решает про реакцию — это [`FreezeController`].
#[derive(Debug, Clone)]
pub struct BlackholeDetector {
    /// Сколько тишины после отправки считаем подозрительной.
    silence_threshold_ms: Millis,
    /// Насколько свежей должна быть отметка о контрольной точке, чтобы ей верить.
    reference_fresh_ms: Millis,
    last_recv_ms: Option<Millis>,
    /// Момент первой неотвеченной отправки после последнего приёма (None = всё отвечено).
    unacked_since_ms: Option<Millis>,
    last_reference_ok_ms: Option<Millis>,
    last_reference_bad_ms: Option<Millis>,
}

impl BlackholeDetector {
    pub fn new(silence_threshold_ms: Millis, reference_fresh_ms: Millis) -> Self {
        BlackholeDetector {
            silence_threshold_ms,
            reference_fresh_ms,
            last_recv_ms: None,
            unacked_since_ms: None,
            last_reference_ok_ms: None,
            last_reference_bad_ms: None,
        }
    }

    /// Разумные значения по умолчанию: 8 с тишины = подозрительно, отметка о
    /// контрольной точке свежа 15 с.
    pub fn with_defaults() -> Self {
        Self::new(8_000, 15_000)
    }

    /// Мы отправили данные в канал.
    pub fn on_sent(&mut self, now: Millis) {
        if self.unacked_since_ms.is_none() {
            self.unacked_since_ms = Some(now);
        }
    }

    /// Мы получили хоть что-то из канала (сбрасывает счётчик тишины).
    pub fn on_recv(&mut self, now: Millis) {
        self.last_recv_ms = Some(now);
        self.unacked_since_ms = None;
    }

    /// Сбросить счётчик неотвеченных отправок, не трогая историю контроля.
    ///
    /// Вызывается при входе в заморозку: мы отказываемся от «зависших» отправок,
    /// чтобы по окончании тишины прошёл один чистый пробный коннект (§9), а не
    /// мгновенная повторная заморозка по старому счётчику.
    pub fn clear_pending(&mut self) {
        self.unacked_since_ms = None;
    }

    /// Наблюдение доступности контрольной точки (независимый хост/резолвер).
    pub fn on_reference(&mut self, now: Millis, reachable: bool) {
        if reachable {
            self.last_reference_ok_ms = Some(now);
        } else {
            self.last_reference_bad_ms = Some(now);
        }
    }

    /// Текущая оценка канала.
    pub fn assess(&self, now: Millis) -> Health {
        let Some(since) = self.unacked_since_ms else {
            return Health::Healthy; // нет неотвеченных отправок
        };
        let silent_for = now.saturating_sub(since);
        if silent_for < self.silence_threshold_ms {
            return Health::Healthy;
        }
        // Тишина затянулась. Решаем blackhole vs network-down по свежести контроля.
        let ref_ok_fresh = self.is_fresh(self.last_reference_ok_ms, now);
        let ref_bad_fresh = self.is_fresh(self.last_reference_bad_ms, now);
        match (ref_ok_fresh, ref_bad_fresh) {
            // Контроль доступен, а наш канал молчит → целенаправленный дроп.
            (true, _) => Health::Blackholed,
            // Контроль тоже недоступен → общая проблема сети, не наша.
            (false, true) => Health::NetworkDown,
            // Нет свежих данных о контроле → не берёмся утверждать.
            (false, false) => Health::Suspect,
        }
    }

    fn is_fresh(&self, mark: Option<Millis>, now: Millis) -> bool {
        matches!(mark, Some(t) if now.saturating_sub(t) <= self.reference_fresh_ms)
    }
}

/// Что делать после того, как заморозка закончится.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterFreeze {
    /// Один осторожный пробный коннект (тем же профилем).
    Probe,
    /// Сменить профиль целиком (другой домен/площадка/fingerprint).
    SwitchProfile,
}

/// Директива реакции на подтверждённый blackhole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// Заморозить всякую активность до `until_ms`, затем сделать `then`.
    Freeze { until_ms: Millis, then: AfterFreeze },
}

/// Контроллер эскалации заморозок (§9).
///
/// Политика: 1-е срабатывание — тишина `first_ms` (150 с), затем пробный коннект;
/// 2-е — тишина `repeat_ms` (600 с), затем пробный коннект; 3-е и далее — та же
/// тишина, но рекомендация сменить профиль. «Быстрее нельзя» — окна не сокращаются.
#[derive(Debug, Clone)]
pub struct FreezeController {
    first_ms: Millis,
    repeat_ms: Millis,
    strikes: u32,
    silent_until_ms: Option<Millis>,
}

impl FreezeController {
    pub fn new(first_ms: Millis, repeat_ms: Millis) -> Self {
        FreezeController { first_ms, repeat_ms, strikes: 0, silent_until_ms: None }
    }

    /// Значения из дизайна §9: 150 с и 600 с (окна дольше наблюдаемых у ТСПУ).
    pub fn with_defaults() -> Self {
        Self::new(150_000, 600_000)
    }

    /// Зафиксировать подтверждённый blackhole и получить директиву заморозки.
    ///
    /// Идемпотентно в пределах уже идущей тишины: если ещё замолчены, повторный
    /// вызов не наращивает страйки и не сдвигает окно (см. [`is_silent`]).
    ///
    /// [`is_silent`]: FreezeController::is_silent
    pub fn trip(&mut self, now: Millis) -> Reaction {
        if self.is_silent(now) {
            // Уже в заморозке — возвращаем текущее окно без эскалации.
            return self.current();
        }
        self.strikes = self.strikes.saturating_add(1);
        let dur = if self.strikes <= 1 { self.first_ms } else { self.repeat_ms };
        self.silent_until_ms = Some(now + dur);
        self.current()
    }

    /// Текущая директива без эскалации — для отчёта во время идущей тишины.
    pub fn current(&self) -> Reaction {
        let then = if self.strikes >= 3 { AfterFreeze::SwitchProfile } else { AfterFreeze::Probe };
        Reaction::Freeze { until_ms: self.silent_until_ms.unwrap_or(0), then }
    }

    /// Идёт ли сейчас заморозка.
    pub fn is_silent(&self, now: Millis) -> bool {
        matches!(self.silent_until_ms, Some(u) if now < u)
    }

    /// Канал восстановился (после пробного коннекта пришли ответы): сбросить эскалацию.
    pub fn on_recovered(&mut self) {
        self.strikes = 0;
        self.silent_until_ms = None;
    }

    pub fn strikes(&self) -> u32 {
        self.strikes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> BlackholeDetector {
        BlackholeDetector::new(8_000, 15_000)
    }

    #[test]
    fn healthy_when_nothing_pending() {
        let d = detector();
        assert_eq!(d.assess(1_000_000), Health::Healthy);
    }

    #[test]
    fn healthy_while_within_silence_threshold() {
        let mut d = detector();
        d.on_sent(1000);
        assert_eq!(d.assess(5000), Health::Healthy); // прошло 4 с < 8 с
    }

    #[test]
    fn recv_clears_pending() {
        let mut d = detector();
        d.on_sent(1000);
        d.on_recv(1500);
        assert_eq!(d.assess(20_000), Health::Healthy);
    }

    #[test]
    fn blackhole_when_silent_and_reference_reachable() {
        let mut d = detector();
        d.on_sent(1000);
        d.on_reference(2000, true); // контроль доступен
        // 1000+8000 = 9000 порог; на 9500 тишина превышена, контроль свеж (2000, ≤15с).
        assert_eq!(d.assess(9500), Health::Blackholed);
    }

    #[test]
    fn network_down_when_silent_and_reference_unreachable() {
        let mut d = detector();
        d.on_sent(1000);
        d.on_reference(2000, false); // контроль тоже недоступен
        assert_eq!(d.assess(9500), Health::NetworkDown);
    }

    #[test]
    fn suspect_when_no_fresh_reference() {
        let mut d = detector();
        d.on_sent(1000);
        d.on_reference(2000, true);
        // На 30000 отметка контроля (2000) уже несвежая (>15с) → не берёмся судить.
        assert_eq!(d.assess(30_000), Health::Suspect);
    }

    #[test]
    fn escalation_first_then_repeat_then_switch() {
        let mut fc = FreezeController::new(150_000, 600_000);

        // Страйк 1: 150 с, затем пробный коннект.
        let r = fc.trip(0);
        assert_eq!(r, Reaction::Freeze { until_ms: 150_000, then: AfterFreeze::Probe });
        assert!(fc.is_silent(149_999));
        assert!(!fc.is_silent(150_000));

        // Страйк 2 (после окончания тишины): 600 с, снова пробный коннект.
        let r = fc.trip(150_000);
        assert_eq!(r, Reaction::Freeze { until_ms: 750_000, then: AfterFreeze::Probe });

        // Страйк 3: 600 с и уже смена профиля.
        let r = fc.trip(750_000);
        assert_eq!(r, Reaction::Freeze { until_ms: 1_350_000, then: AfterFreeze::SwitchProfile });
        assert_eq!(fc.strikes(), 3);
    }

    #[test]
    fn trip_is_idempotent_within_silence() {
        let mut fc = FreezeController::new(150_000, 600_000);
        fc.trip(0);
        // Повторный trip во время тишины не наращивает страйки и окно.
        let r = fc.trip(1000);
        assert_eq!(r, Reaction::Freeze { until_ms: 150_000, then: AfterFreeze::Probe });
        assert_eq!(fc.strikes(), 1);
    }

    #[test]
    fn recovery_resets_escalation() {
        let mut fc = FreezeController::new(150_000, 600_000);
        fc.trip(0);
        fc.trip(150_000);
        assert_eq!(fc.strikes(), 2);
        fc.on_recovered();
        assert_eq!(fc.strikes(), 0);
        // После восстановления первый trip снова короткий.
        let r = fc.trip(1_000_000);
        assert_eq!(r, Reaction::Freeze { until_ms: 1_150_000, then: AfterFreeze::Probe });
    }
}
