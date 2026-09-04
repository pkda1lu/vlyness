//! Анти-реплей: кэш клиентских nonce по окну эпох (wire-spec §3).
//!
//! Токен ([`crate::auth::AuthToken`]) проверяется по тегу, но валидный тег сам по себе
//! не спасает от **повтора**: пойманный cookie можно переиграть в пределах того же
//! часа. Поэтому сервер держит кэш виденных `clientNonce` за последние эпохи и отвергает
//! повтор. С повтором обращаются как с зондом (honest-fallback), а не как с ошибкой.
//!
//! Nonce — 12 случайных байт на сессию, поэтому коллизии у легитимных клиентов
//! практически исключены, а совпадение = почти наверняка реплей.

use std::collections::{BTreeMap, HashSet};

use crate::auth::{AuthToken, NONCE_LEN};

/// Сколько последних эпох держим в кэше. `verify` принимает epoch ∈ {now−1, now, now+1},
/// так что трёх достаточно, чтобы покрыть всё окно приёма.
const KEEP_EPOCHS: usize = 3;

/// Кэш виденных nonce, сгруппированных по эпохе.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    window: BTreeMap<u64, HashSet<[u8; NONCE_LEN]>>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        ReplayGuard { window: BTreeMap::new() }
    }

    /// Зафиксировать nonce для эпохи. `true` — свежий (записан), `false` — реплей.
    pub fn observe(&mut self, epoch: u64, nonce: &[u8; NONCE_LEN]) -> bool {
        let fresh = self.window.entry(epoch).or_default().insert(*nonce);
        self.prune();
        fresh
    }

    /// Как [`observe`](ReplayGuard::observe), но берёт nonce из токена.
    pub fn observe_token(&mut self, token: &AuthToken, epoch: u64) -> bool {
        self.observe(epoch, &token.nonce)
    }

    /// Оставить только `KEEP_EPOCHS` новейших эпох (удаляем самые старые ключи).
    fn prune(&mut self) {
        while self.window.len() > KEEP_EPOCHS {
            let oldest = *self.window.keys().next().expect("непустая карта");
            self.window.remove(&oldest);
        }
    }

    /// Сколько эпох сейчас в кэше (для тестов/метрик).
    pub fn tracked_epochs(&self) -> usize {
        self.window.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthToken, PSK_LEN};

    fn psk() -> [u8; PSK_LEN] {
        [0x33; PSK_LEN]
    }

    #[test]
    fn first_sighting_is_fresh_repeat_is_replay() {
        let mut g = ReplayGuard::new();
        let nonce = [1u8; NONCE_LEN];
        assert!(g.observe(100, &nonce), "первый раз — свежий");
        assert!(!g.observe(100, &nonce), "повтор — реплей");
        assert!(!g.observe(100, &nonce), "и снова реплей");
    }

    #[test]
    fn different_nonces_same_epoch_are_independent() {
        let mut g = ReplayGuard::new();
        assert!(g.observe(5, &[1u8; NONCE_LEN]));
        assert!(g.observe(5, &[2u8; NONCE_LEN]));
        assert!(!g.observe(5, &[1u8; NONCE_LEN]));
    }

    #[test]
    fn same_nonce_different_epoch_tracked_separately() {
        // Один и тот же nonce в разных эпохах — разные записи (nonce всё равно
        // случайный, но семантика окна должна быть по (epoch, nonce)).
        let mut g = ReplayGuard::new();
        let nonce = [7u8; NONCE_LEN];
        assert!(g.observe(10, &nonce));
        assert!(g.observe(11, &nonce));
    }

    #[test]
    fn old_epochs_are_pruned() {
        let mut g = ReplayGuard::new();
        for epoch in 0..10u64 {
            g.observe(epoch, &[epoch as u8; NONCE_LEN]);
        }
        assert_eq!(g.tracked_epochs(), KEEP_EPOCHS);
        // Старая эпоха выпала из кэша → её nonce снова «свежий» (окно уже прошло,
        // а к тому времени и токен по времени невалиден на уровне verify).
        assert!(g.observe(0, &[0u8; NONCE_LEN]));
    }

    #[test]
    fn integrates_with_real_token() {
        let mut g = ReplayGuard::new();
        let epoch = 42;
        let token = AuthToken::build(&psk(), epoch);
        assert!(g.observe_token(&token, epoch));
        assert!(!g.observe_token(&token, epoch), "тот же токен — реплей");
    }
}
