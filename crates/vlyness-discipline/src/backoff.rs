//! Экспоненциальный backoff с полным джиттером (дизайн §5).
//!
//! «Полный джиттер» (AWS full jitter): задержка = uniform(0, min(cap, base·2ⁿ)).
//! Джиттер обязателен — синхронный ретрай многих клиентов сам создаёт всплеск,
//! который ТСПУ и ловит (признак №5). База 2 с, потолок 300 с — из профиля.

use crate::clock::{Jitter, Millis};

/// Состояние backoff для одной точки (носителя/сервера).
#[derive(Debug, Clone)]
pub struct Backoff {
    base_ms: Millis,
    cap_ms: Millis,
    attempt: u32,
}

impl Backoff {
    pub fn new(base_ms: Millis, cap_ms: Millis) -> Self {
        Backoff { base_ms, cap_ms, attempt: 0 }
    }

    /// Верхняя граница окна для текущей попытки: min(cap, base·2ⁿ), насыщающе.
    pub fn ceiling(&self) -> Millis {
        // Сдвиг ограничиваем 63, дальше всё равно упрёмся в cap.
        let shifted = (self.base_ms as u128) << self.attempt.min(63);
        shifted.min(self.cap_ms as u128) as Millis
    }

    /// Следующая задержка с полным джиттером и инкремент счётчика попыток.
    pub fn next_delay(&mut self, jitter: &mut impl Jitter) -> Millis {
        let ceil = self.ceiling();
        // Полный джиттер по [0, ceil]; +1, чтобы верхняя граница была достижима.
        let delay = jitter.below(ceil.saturating_add(1));
        self.attempt = self.attempt.saturating_add(1);
        delay
    }

    /// Сбросить счётчик (после успешного соединения).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedFraction;

    #[test]
    fn ceiling_grows_then_caps() {
        let b = Backoff::new(2000, 300_000);
        assert_eq!(b.ceiling(), 2000); // attempt 0: 2000
        let mut b1 = b.clone();
        b1.attempt = 1;
        assert_eq!(b1.ceiling(), 4000);
        let mut b3 = b.clone();
        b3.attempt = 3;
        assert_eq!(b3.ceiling(), 16000);
        let mut b_big = b.clone();
        b_big.attempt = 40;
        assert_eq!(b_big.ceiling(), 300_000); // упёрлись в потолок
    }

    #[test]
    fn full_jitter_max_follows_ceiling() {
        // FixedFraction(1,1) даёт максимум окна.
        let mut b = Backoff::new(2000, 300_000);
        let mut jmax = FixedFraction::new(1, 1);
        assert_eq!(b.next_delay(&mut jmax), 2001); // ceil 2000, +1
        assert_eq!(b.next_delay(&mut jmax), 4001);
        assert_eq!(b.next_delay(&mut jmax), 8001);
    }

    #[test]
    fn full_jitter_can_be_zero() {
        let mut b = Backoff::new(2000, 300_000);
        let mut jzero = FixedFraction::new(0, 1);
        assert_eq!(b.next_delay(&mut jzero), 0);
        assert_eq!(b.attempt(), 1);
    }

    #[test]
    fn reset_returns_to_base() {
        let mut b = Backoff::new(2000, 300_000);
        let mut jmax = FixedFraction::new(1, 1);
        b.next_delay(&mut jmax);
        b.next_delay(&mut jmax);
        assert_eq!(b.attempt(), 2);
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.ceiling(), 2000);
    }
}
