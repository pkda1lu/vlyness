//! Симметризатор соотношения up/down (дизайн §8.3).
//!
//! Реальный веб/медиа-трафик резко download-heavy (для медиа ~1:15), а туннель по
//! природе симметричнее (~1:3). Признак асимметрии (№7) лечится дросселированием и
//! дополнением восходящего канала под целевое соотношение down:up из профиля.
//!
//! Инвариант: держим `down / up ≥ target_ratio`. Отсюда бюджет восходящего канала —
//! сколько ещё байт можно отправить вверх при текущем накопленном down.

/// Учёт объёмов и расчёт бюджета восходящего канала.
#[derive(Debug, Clone)]
pub struct Symmetrizer {
    /// Целевое соотношение down:up (≥1). Для медиа ~15.
    target_ratio: u64,
    down: u64,
    up: u64,
}

impl Symmetrizer {
    pub fn new(target_ratio: u32) -> Self {
        assert!(target_ratio >= 1, "соотношение down:up должно быть ≥ 1");
        Symmetrizer { target_ratio: target_ratio as u64, down: 0, up: 0 }
    }

    /// Учесть полученные (нисходящие) байты.
    pub fn on_down(&mut self, bytes: u64) {
        self.down = self.down.saturating_add(bytes);
    }

    /// Учесть отправленные (восходящие) байты.
    pub fn on_up(&mut self, bytes: u64) {
        self.up = self.up.saturating_add(bytes);
    }

    /// Сколько ещё байт разрешено отправить вверх, не нарушив `down/up ≥ ratio`.
    ///
    /// = `down / ratio − up`, но не меньше 0. Когда бюджет 0 — восходящий канал надо
    /// дросселировать (придержать отправку) до прихода новых нисходящих данных.
    pub fn up_budget(&self) -> u64 {
        (self.down / self.target_ratio).saturating_sub(self.up)
    }

    /// Нужно ли добить нисходящий канал padding'ом, чтобы «покрыть» уже отправленный
    /// вверх объём: сколько down-байт не хватает для соблюдения соотношения.
    ///
    /// = `up * ratio − down`, но не меньше 0. Используется, когда вверх пришлось
    /// отправить больше бюджета (управляющий трафик) и нужно восстановить асимметрию.
    pub fn down_deficit(&self) -> u64 {
        self.up.saturating_mul(self.target_ratio).saturating_sub(self.down)
    }

    pub fn down(&self) -> u64 {
        self.down
    }

    pub fn up(&self) -> u64 {
        self.up
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_grows_with_down() {
        let mut s = Symmetrizer::new(15);
        s.on_down(1500);
        assert_eq!(s.up_budget(), 100); // 1500/15 - 0
        s.on_up(40);
        assert_eq!(s.up_budget(), 60); // 100 - 40
    }

    #[test]
    fn budget_is_zero_when_overspent() {
        let mut s = Symmetrizer::new(15);
        s.on_down(150); // бюджет 10
        s.on_up(50); // потратили больше бюджета
        assert_eq!(s.up_budget(), 0);
    }

    #[test]
    fn down_deficit_tracks_overspend() {
        let mut s = Symmetrizer::new(15);
        s.on_up(50); // для 50 вверх нужно 750 вниз
        assert_eq!(s.down_deficit(), 750);
        s.on_down(600);
        assert_eq!(s.down_deficit(), 150); // 750 - 600
        s.on_down(200);
        assert_eq!(s.down_deficit(), 0); // покрыто
    }

    #[test]
    fn ratio_one_is_symmetric() {
        let mut s = Symmetrizer::new(1);
        s.on_down(1000);
        assert_eq!(s.up_budget(), 1000);
        s.on_up(1000);
        assert_eq!(s.up_budget(), 0);
        assert_eq!(s.down_deficit(), 0);
    }
}
