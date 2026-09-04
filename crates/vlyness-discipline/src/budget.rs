//! Менеджер бюджета соединений (дизайн §5).
//!
//! Закрывает самый частый триггер ТСПУ 2026 (признак №5): «>3 параллельных TLS к
//! одному SNI с малой задержкой». Гарантирует:
//! - не более `max_conns` одновременных соединений (по умолчанию 1);
//! - минимальный интервал между попытками установления (по умолчанию ≥800 мс);
//! - экспоненциальный backoff при сбоях/разрывах — **без реконнект-шторма**.
//!
//! Модуль ничего не открывает сам: он лишь **разрешает или откладывает** попытку,
//! а результат ему сообщают через `on_*`. Так логика проверяется на мок-часах.

use crate::backoff::Backoff;
use crate::clock::{Jitter, Millis};

/// Вердикт бюджета на попытку соединения «прямо сейчас».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Можно открывать. Вызови [`ConnectionBudget::on_attempt`] и дальше `on_*` по итогу.
    Allow,
    /// Ещё рано (интервал/backoff). Подожди `Millis` и опроси снова.
    Wait(Millis),
    /// Достигнут потолок одновременных соединений.
    AtCapacity,
}

/// Бюджет соединений одной точки (носителя/сервера).
#[derive(Debug, Clone)]
pub struct ConnectionBudget {
    max_conns: u32,
    min_interval_ms: Millis,
    active: u32,
    /// Раньше этого времени новую попытку начинать нельзя.
    next_allowed_ms: Millis,
    backoff: Backoff,
}

impl ConnectionBudget {
    pub fn new(max_conns: u32, min_interval_ms: Millis, backoff: Backoff) -> Self {
        assert!(max_conns >= 1, "нужно хотя бы одно соединение");
        ConnectionBudget {
            max_conns,
            min_interval_ms,
            active: 0,
            next_allowed_ms: 0,
            backoff,
        }
    }

    /// Опросить бюджет в момент `now`.
    pub fn poll(&self, now: Millis) -> GateDecision {
        if self.active >= self.max_conns {
            return GateDecision::AtCapacity;
        }
        if now < self.next_allowed_ms {
            return GateDecision::Wait(self.next_allowed_ms - now);
        }
        GateDecision::Allow
    }

    /// Отметить начало попытки (мы начали дозваниваться). Разносит попытки во
    /// времени: следующую нельзя начать раньше, чем через `min_interval_ms`.
    pub fn on_attempt(&mut self, now: Millis) {
        self.bump_next_allowed(now + self.min_interval_ms);
    }

    /// Попытка удалась: +1 активное соединение, backoff сброшен.
    pub fn on_success(&mut self, _now: Millis) {
        self.active += 1;
        self.backoff.reset();
    }

    /// Попытка НЕ удалась (не дозвонились): отложить по backoff.
    pub fn on_failure(&mut self, now: Millis, jitter: &mut impl Jitter) {
        let delay = self.backoff.next_delay(jitter);
        self.bump_next_allowed(now + delay);
    }

    /// Установленное соединение оборвалось неожиданно: −1 активное и backoff-пауза
    /// (разрыв трактуем как сбой для темпа — не даём мгновенный реконнект).
    pub fn on_drop(&mut self, now: Millis, jitter: &mut impl Jitter) {
        self.active = self.active.saturating_sub(1);
        let delay = self.backoff.next_delay(jitter);
        self.bump_next_allowed(now + delay.max(self.min_interval_ms));
    }

    /// Мы сами закрыли соединение штатно: −1 активное, backoff не трогаем,
    /// но следующую попытку всё равно разносим на `min_interval_ms`.
    pub fn on_close(&mut self, now: Millis) {
        self.active = self.active.saturating_sub(1);
        self.bump_next_allowed(now + self.min_interval_ms);
    }

    /// Принудительно заморозить попытки до `until_ms` (используется реакцией на
    /// blackhole — см. модуль `blackhole`). Никогда не сокращает существующую паузу.
    pub fn freeze_until(&mut self, until_ms: Millis) {
        self.bump_next_allowed(until_ms);
    }

    /// Освободить все активные соединения без изменения паузы. Применяется при
    /// blackhole: тихо задропанное соединение мертво, но числится активным.
    pub fn release_all(&mut self) {
        self.active = 0;
    }

    pub fn active(&self) -> u32 {
        self.active
    }

    pub fn next_allowed_ms(&self) -> Millis {
        self.next_allowed_ms
    }

    /// Продлевает паузу вперёд, но никогда не сокращает её.
    fn bump_next_allowed(&mut self, when: Millis) {
        if when > self.next_allowed_ms {
            self.next_allowed_ms = when;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedFraction;

    fn budget(max: u32) -> ConnectionBudget {
        ConnectionBudget::new(max, 800, Backoff::new(2000, 300_000))
    }

    #[test]
    fn allows_first_then_spaces_by_min_interval() {
        let mut b = budget(2);
        assert_eq!(b.poll(0), GateDecision::Allow);
        b.on_attempt(0);
        b.on_success(0);
        // Второе соединение ещё не пущено раньше min_interval, хотя ёмкость есть.
        assert_eq!(b.poll(100), GateDecision::Wait(700));
        assert_eq!(b.poll(800), GateDecision::Allow);
    }

    #[test]
    fn enforces_capacity() {
        let mut b = budget(1);
        b.on_attempt(0);
        b.on_success(0);
        assert_eq!(b.poll(10_000), GateDecision::AtCapacity);
        b.on_close(10_000);
        // После закрытия — снова можно, но с интервалом.
        assert_eq!(b.poll(10_000), GateDecision::Wait(800));
        assert_eq!(b.poll(10_800), GateDecision::Allow);
    }

    #[test]
    fn failure_triggers_backoff() {
        let mut b = budget(1);
        let mut jmax = FixedFraction::new(1, 1);
        b.on_attempt(0);
        b.on_failure(0, &mut jmax); // ceil 2000 → задержка 2001
        assert_eq!(b.poll(1000), GateDecision::Wait(1001));
        assert_eq!(b.poll(2001), GateDecision::Allow);
    }

    #[test]
    fn repeated_failures_grow_backoff() {
        let mut b = budget(1);
        let mut jmax = FixedFraction::new(1, 1);
        b.on_attempt(0);
        b.on_failure(0, &mut jmax); // ~2001
        assert_eq!(b.poll(0), GateDecision::Wait(2001));
        b.on_attempt(2001);
        b.on_failure(2001, &mut jmax); // ceil 4000 → 4001
        assert_eq!(b.poll(2001), GateDecision::Wait(4001));
    }

    #[test]
    fn success_resets_backoff() {
        let mut b = budget(1);
        let mut jmax = FixedFraction::new(1, 1);
        b.on_attempt(0);
        b.on_failure(0, &mut jmax);
        b.on_attempt(5000);
        b.on_success(5000);
        b.on_close(5000);
        // После успеха backoff сброшен: следующая пауза — обычный min_interval.
        assert_eq!(b.poll(5000), GateDecision::Wait(800));
    }

    #[test]
    fn drop_decrements_and_backs_off() {
        let mut b = budget(1);
        let mut jmax = FixedFraction::new(1, 1);
        b.on_attempt(0);
        b.on_success(0);
        b.on_drop(1000, &mut jmax); // active→0, backoff ceil 2000
        assert_eq!(b.active(), 0);
        assert_eq!(b.poll(1000), GateDecision::Wait(2001));
    }

    #[test]
    fn freeze_never_shortens_pause() {
        let mut b = budget(1);
        b.freeze_until(100_000);
        assert_eq!(b.poll(0), GateDecision::Wait(100_000));
        // Попытка «сократить» паузу игнорируется.
        b.freeze_until(500);
        assert_eq!(b.poll(0), GateDecision::Wait(100_000));
    }
}
