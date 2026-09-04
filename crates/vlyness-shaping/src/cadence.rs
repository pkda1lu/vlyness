//! Cadence-генератор (дизайн §8.2).
//!
//! Медиа-профиль подразумевает **постоянный ритм** запросов сегментов, независимо от
//! того, есть ли пользовательские данные. Это убирает признаки «on/off по запросам
//! пользователя» и «длинные idle»: idle-туннель выглядит как воспроизведение видео.
//! Цена — фоновый трафик в простое; включается флагом `idle_fill` профиля.

use rand::Rng;

/// Генератор интервалов между запросами сегментов.
#[derive(Debug, Clone)]
pub struct Cadence {
    interval_ms: u64,
    jitter_ms: u64,
    idle_fill: bool,
}

impl Cadence {
    /// `interval_ms` — базовый интервал; `jitter_ms` — симметричный разброс (±);
    /// `idle_fill` — продолжать ли ритм при отсутствии данных.
    pub fn new(interval_ms: u64, jitter_ms: u64, idle_fill: bool) -> Self {
        Cadence { interval_ms, jitter_ms, idle_fill }
    }

    /// Задержка до следующего запроса: `interval ± uniform(0..=jitter)`, не меньше 0.
    pub fn next_delay_ms<R: Rng + ?Sized>(&self, rng: &mut R) -> u64 {
        if self.jitter_ms == 0 {
            return self.interval_ms;
        }
        let offset = rng.gen_range(0..=2 * self.jitter_ms); // [0, 2j]
        // interval + (offset - jitter) → [interval - jitter, interval + jitter]
        (self.interval_ms + offset).saturating_sub(self.jitter_ms)
    }

    /// Нужно ли слать сегмент, когда пользовательских данных нет.
    ///
    /// `true` → отправить сегмент, заполненный padding'ом (idle-fill), чтобы ритм не
    /// прерывался. `false` (idle_fill выключен) → можно промолчать, экономя трафик,
    /// ценой появления idle-периодов.
    pub fn should_fill_idle(&self) -> bool {
        self.idle_fill
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn delay_stays_within_jitter_band() {
        let c = Cadence::new(4000, 800, true);
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..10_000 {
            let d = c.next_delay_ms(&mut rng);
            assert!((3200..=4800).contains(&d), "delay={d} вне полосы джиттера");
        }
    }

    #[test]
    fn zero_jitter_is_exact() {
        let c = Cadence::new(4000, 0, true);
        let mut rng = StdRng::seed_from_u64(3);
        assert_eq!(c.next_delay_ms(&mut rng), 4000);
    }

    #[test]
    fn jitter_reaches_both_extremes() {
        let c = Cadence::new(1000, 500, true);
        let mut rng = StdRng::seed_from_u64(11);
        let mut min = u64::MAX;
        let mut max = 0;
        for _ in 0..50_000 {
            let d = c.next_delay_ms(&mut rng);
            min = min.min(d);
            max = max.max(d);
        }
        assert_eq!(min, 500); // interval - jitter
        assert_eq!(max, 1500); // interval + jitter
    }

    #[test]
    fn idle_fill_flag_propagates() {
        assert!(Cadence::new(4000, 800, true).should_fill_idle());
        assert!(!Cadence::new(4000, 800, false).should_fill_idle());
    }
}
