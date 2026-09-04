//! # vlyness-discipline
//!
//! Дисциплина подключений VLYNESS — приоритет **P0** дорожной карты (док 04): по
//! модели угроз это даёт больше практической стойкости к ТСПУ 2026, чем любой шифр,
//! потому что большинство сегодняшних срабатываний ловит не криптографию, а
//! неаккуратное поведение клиента (пачки соединений, ретрай-штормы, ротацию
//! fingerprint под штрафом).
//!
//! Слои:
//! - [`clock`] — абстракция времени и джиттера (детерминированные тесты);
//! - [`backoff`] — экспоненциальный backoff с полным джиттером (§5);
//! - [`budget`] — бюджет соединений: потолок, интервалы, без реконнект-шторма (§5);
//! - [`blackhole`] — детектор тихого дропа и эскалация заморозок (§9).
//!
//! [`ConnectionManager`] сводит их в одну машину состояний. Вся логика чистая и
//! работает от инъектируемых [`clock::Clock`]/[`clock::Jitter`] — сокеты
//! подключаются сверху, а поведение проверяется симуляцией на мок-часах.

#![forbid(unsafe_code)]

pub mod backoff;
pub mod blackhole;
pub mod budget;
pub mod clock;

use blackhole::{AfterFreeze, BlackholeDetector, FreezeController, Health, Reaction};
use budget::{ConnectionBudget, GateDecision};
use clock::{Clock, Jitter, Millis};

/// Итоговая директива менеджера в конкретный момент.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerAction {
    /// Бюджет разрешает — можно дозваниваться. Дальше вызвать `note_attempt` и по
    /// итогу `note_success`/`note_failure`.
    Connect,
    /// Ещё рано (интервал/backoff) — подождать столько мс и опросить снова.
    Wait(Millis),
    /// Достигнут потолок одновременных соединений.
    AtCapacity,
    /// Действует реакция на blackhole: тишина до `until_ms`, затем `then`.
    Frozen { until_ms: Millis, then: AfterFreeze },
    /// Тишина в канале, но контрольные хосты тоже недоступны — проблема не наша.
    /// Профиль менять не нужно; ждать восстановления сети, соблюдая темп бюджета.
    NetworkDown(Millis),
}

/// Оркестратор дисциплины подключений одной точки (профиля/носителя).
pub struct ConnectionManager<C: Clock, J: Jitter> {
    clock: C,
    jitter: J,
    budget: ConnectionBudget,
    detector: BlackholeDetector,
    freeze: FreezeController,
}

impl<C: Clock, J: Jitter> ConnectionManager<C, J> {
    pub fn new(
        clock: C,
        jitter: J,
        budget: ConnectionBudget,
        detector: BlackholeDetector,
        freeze: FreezeController,
    ) -> Self {
        ConnectionManager { clock, jitter, budget, detector, freeze }
    }

    /// Главное решение «что делать сейчас».
    ///
    /// Порядок проверок важен: сначала действующая заморозка, потом здоровье канала
    /// (может завести новую заморозку), и только затем бюджет.
    pub fn poll(&mut self) -> ManagerAction {
        let now = self.clock.now_ms();

        // 1. Уже в заморозке — не трогаем ничего, ждём окончания тишины.
        if self.freeze.is_silent(now) {
            return self.frozen_action();
        }

        // 2. Здоровье канала.
        match self.detector.assess(now) {
            Health::Blackholed => {
                let Reaction::Freeze { until_ms, then } = self.freeze.trip(now);
                self.budget.freeze_until(until_ms);
                // Тихо задропанное соединение мертво — освобождаем ёмкость, иначе по
                // окончании тишины бюджет упрётся в потолок и не пустит пробный коннект.
                self.budget.release_all();
                // Сбрасываем «зависшие» отправки, чтобы по окончании тишины прошёл
                // ровно один пробный коннект, а не мгновенная повторная заморозка.
                self.detector.clear_pending();
                return ManagerAction::Frozen { until_ms, then };
            }
            Health::NetworkDown => {
                // Не эскалируем и не меняем профиль: ждём восстановления сети,
                // соблюдая обычный темп бюджета.
                if let GateDecision::Wait(d) = self.budget.poll(now) {
                    return ManagerAction::NetworkDown(d);
                }
                return ManagerAction::NetworkDown(0);
            }
            Health::Healthy | Health::Suspect => {}
        }

        // 3. Бюджет.
        match self.budget.poll(now) {
            GateDecision::Allow => ManagerAction::Connect,
            GateDecision::Wait(d) => ManagerAction::Wait(d),
            GateDecision::AtCapacity => ManagerAction::AtCapacity,
        }
    }

    fn frozen_action(&self) -> ManagerAction {
        match self.freeze.current() {
            Reaction::Freeze { until_ms, then } => ManagerAction::Frozen { until_ms, then },
        }
    }

    // --- события подключения (стамп времени берётся из часов) ---

    /// Мы начали дозваниваться.
    pub fn note_attempt(&mut self) {
        self.budget.on_attempt(self.clock.now_ms());
    }

    /// Соединение установлено.
    pub fn note_success(&mut self) {
        self.budget.on_success(self.clock.now_ms());
    }

    /// Не дозвонились.
    pub fn note_failure(&mut self) {
        let now = self.clock.now_ms();
        self.budget.on_failure(now, &mut self.jitter);
    }

    /// Установленное соединение оборвалось неожиданно.
    pub fn note_drop(&mut self) {
        let now = self.clock.now_ms();
        self.budget.on_drop(now, &mut self.jitter);
    }

    /// Мы сами штатно закрыли соединение.
    pub fn note_close(&mut self) {
        self.budget.on_close(self.clock.now_ms());
    }

    // --- события трафика (для детектора blackhole) ---

    /// Мы отправили данные в канал.
    pub fn note_sent(&mut self) {
        self.detector.on_sent(self.clock.now_ms());
    }

    /// Мы получили данные из канала — значит канал живой: снимаем эскалацию.
    pub fn note_recv(&mut self) {
        let now = self.clock.now_ms();
        self.detector.on_recv(now);
        self.freeze.on_recovered();
    }

    /// Наблюдение доступности независимой контрольной точки.
    pub fn note_reference(&mut self, reachable: bool) {
        self.detector.on_reference(self.clock.now_ms(), reachable);
    }

    pub fn active(&self) -> u32 {
        self.budget.active()
    }

    pub fn strikes(&self) -> u32 {
        self.freeze.strikes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backoff::Backoff;
    use crate::clock::{FixedFraction, ManualClock};

    fn manager(clock: ManualClock) -> ConnectionManager<ManualClock, FixedFraction> {
        ConnectionManager::new(
            clock,
            FixedFraction::new(1, 2), // детерминированный «средний» джиттер
            ConnectionBudget::new(1, 800, Backoff::new(2000, 300_000)),
            BlackholeDetector::new(8_000, 15_000),
            FreezeController::new(150_000, 600_000),
        )
    }

    #[test]
    fn happy_path_connect_and_capacity() {
        let clock = ManualClock::new(0);
        let mut m = manager(clock);
        assert_eq!(m.poll(), ManagerAction::Connect);
        m.note_attempt();
        m.note_success();
        assert_eq!(m.active(), 1);
        // Второй коннект не пускается: потолок 1.
        assert_eq!(m.poll(), ManagerAction::AtCapacity);
    }

    #[test]
    fn full_tspu_freeze_scenario() {
        // Симуляция сценария из модели угроз: установили канал, ТСПУ ушёл в тихий
        // дроп, клиент обязан замолчать (150 с → 600 с) и не менять профиль раньше.
        let clock = ManualClock::new(0);
        let mut m = manager(clock);

        // t=0: подключаемся, шлём данные, контроль доступен.
        assert_eq!(m.poll(), ManagerAction::Connect);
        m.note_attempt();
        m.note_success();
        m.clock.advance(100);
        m.note_sent();
        m.clock.advance(100); // t=200
        m.note_reference(true);

        // t=9000: ответа нет 8.9 с, контроль свеж → blackhole, первая заморозка 150 с.
        m.clock.set(9000);
        m.note_reference(true); // держим контроль свежим
        match m.poll() {
            ManagerAction::Frozen { until_ms, then } => {
                assert_eq!(until_ms, 9000 + 150_000);
                assert_eq!(then, AfterFreeze::Probe);
            }
            other => panic!("ожидалась заморозка, получено {other:?}"),
        }
        assert_eq!(m.strikes(), 1);

        // Во время тишины — по-прежнему Frozen, никаких попыток.
        m.clock.set(100_000);
        assert!(matches!(m.poll(), ManagerAction::Frozen { .. }));

        // t=159000: тишина кончилась, детектор сброшен → проходит ОДИН пробный коннект.
        m.clock.set(159_000);
        assert_eq!(m.poll(), ManagerAction::Connect);
        m.note_attempt();
        m.note_success();
        m.note_sent(); // пробуем снова слать
        m.note_reference(true);

        // t=168000: пробный коннект тоже в чёрной дыре → страйк 2, заморозка 600 с.
        m.clock.set(168_000);
        m.note_reference(true);
        match m.poll() {
            ManagerAction::Frozen { until_ms, then } => {
                assert_eq!(until_ms, 168_000 + 600_000);
                assert_eq!(then, AfterFreeze::Probe);
            }
            other => panic!("ожидалась вторая заморозка, получено {other:?}"),
        }
        assert_eq!(m.strikes(), 2);

        // Третий страйк → рекомендация сменить профиль.
        m.clock.set(768_000);
        m.note_reference(true);
        m.detector_on_sent_at(768_000); // есть неотвеченная отправка для оценки
        m.clock.set(777_000);
        m.note_reference(true);
        match m.poll() {
            ManagerAction::Frozen { then, .. } => assert_eq!(then, AfterFreeze::SwitchProfile),
            other => panic!("ожидалась смена профиля, получено {other:?}"),
        }
        assert_eq!(m.strikes(), 3);
    }

    #[test]
    fn network_down_does_not_escalate() {
        let clock = ManualClock::new(0);
        let mut m = manager(clock);
        m.poll();
        m.note_attempt();
        m.note_success();
        m.note_sent();
        m.note_reference(false); // и наш канал, и контроль недоступны
        m.clock.set(9000);
        m.note_reference(false);
        assert!(matches!(m.poll(), ManagerAction::NetworkDown(_)));
        // Профиль не эскалируется: страйков нет.
        assert_eq!(m.strikes(), 0);
    }

    #[test]
    fn recovery_after_freeze_resets_strikes() {
        let clock = ManualClock::new(0);
        let mut m = manager(clock);
        m.poll();
        m.note_attempt();
        m.note_success();
        m.note_sent();
        m.note_reference(true);
        m.clock.set(9000);
        m.note_reference(true);
        assert!(matches!(m.poll(), ManagerAction::Frozen { .. }));
        assert_eq!(m.strikes(), 1);

        // Тишина кончилась, пробный коннект, и на этот раз пришёл ответ.
        m.clock.set(159_000);
        assert_eq!(m.poll(), ManagerAction::Connect);
        m.note_recv(); // канал ожил
        assert_eq!(m.strikes(), 0);
    }

    // Вспомогательное: подсунуть детектору неотвеченную отправку в заданный момент.
    impl ConnectionManager<ManualClock, FixedFraction> {
        fn detector_on_sent_at(&mut self, at: Millis) {
            self.clock.set(at);
            self.note_sent();
        }
    }
}
