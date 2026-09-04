//! Абстракция времени и джиттера — чтобы вся дисциплина была детерминированно
//! тестируемой (симуляция заморозки ТСПУ на мок-часах, без реального ожидания).

use std::cell::Cell;

/// Монотонное время в миллисекундах.
pub type Millis = u64;

/// Источник монотонного времени.
pub trait Clock {
    fn now_ms(&self) -> Millis;
}

/// Системные монотонные часы (миллисекунды от момента создания).
pub struct SystemClock {
    start: std::time::Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        SystemClock { start: std::time::Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> Millis {
        self.start.elapsed().as_millis() as Millis
    }
}

/// Ручные часы для тестов и симуляций: время двигается только явными вызовами.
pub struct ManualClock {
    now: Cell<Millis>,
}

impl ManualClock {
    pub fn new(start: Millis) -> Self {
        ManualClock { now: Cell::new(start) }
    }

    /// Сдвинуть время вперёд на `ms`.
    pub fn advance(&self, ms: Millis) {
        self.now.set(self.now.get() + ms);
    }

    /// Установить абсолютное время.
    pub fn set(&self, ms: Millis) {
        self.now.set(ms);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> Millis {
        self.now.get()
    }
}

/// Источник джиттера: равномерное значение в диапазоне `[0, bound)`.
///
/// Инъектируется, чтобы backoff/интервалы были детерминированы в тестах.
pub trait Jitter {
    fn below(&mut self, bound: Millis) -> Millis;
}

/// Криптостойкий джиттер поверх ГПСЧ ОС.
pub struct OsJitter;

impl Jitter for OsJitter {
    fn below(&mut self, bound: Millis) -> Millis {
        if bound == 0 {
            return 0;
        }
        use rand::Rng;
        rand::thread_rng().gen_range(0..bound)
    }
}

/// Детерминированный джиттер для тестов: возвращает `bound * num / den`.
///
/// `FixedFraction::new(1, 1)` — всегда максимум (bound−1 эффективно как доля),
/// `new(0, 1)` — всегда 0, `new(1, 2)` — половина.
pub struct FixedFraction {
    num: u64,
    den: u64,
}

impl FixedFraction {
    pub fn new(num: u64, den: u64) -> Self {
        assert!(den != 0, "знаменатель не может быть нулём");
        FixedFraction { num, den }
    }
}

impl Jitter for FixedFraction {
    fn below(&mut self, bound: Millis) -> Millis {
        // Насыщающее умножение через u128, затем деление.
        let v = (bound as u128) * (self.num as u128) / (self.den as u128);
        v.min(u64::MAX as u128) as Millis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances() {
        let c = ManualClock::new(1000);
        assert_eq!(c.now_ms(), 1000);
        c.advance(500);
        assert_eq!(c.now_ms(), 1500);
        c.set(42);
        assert_eq!(c.now_ms(), 42);
    }

    #[test]
    fn fixed_fraction_is_deterministic() {
        assert_eq!(FixedFraction::new(0, 1).below(1000), 0);
        assert_eq!(FixedFraction::new(1, 1).below(1000), 1000);
        assert_eq!(FixedFraction::new(1, 2).below(1000), 500);
        assert_eq!(FixedFraction::new(3, 4).below(2000), 1500);
    }

    #[test]
    fn os_jitter_stays_in_range() {
        let mut j = OsJitter;
        for _ in 0..1000 {
            assert!(j.below(100) < 100);
        }
        assert_eq!(j.below(0), 0);
    }
}
