//! Наблюдаемый поток и его признаки — то, что видит и на чём учится ТСПУ (01 §3).
//!
//! Мы собираем ровно те величины, по которым идёт поведенческий детект: размеры
//! записей, направления, тайминги. Признаки затем сравниваются с легендой
//! ([`crate::distance`]).

/// Направление записи относительно клиента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Клиент → сервер (uplink).
    Up,
    /// Сервер → клиент (downlink).
    Down,
}

/// Одно наблюдение: момент, направление, размер записи на проводе.
#[derive(Debug, Clone, Copy)]
pub struct Obs {
    pub t_ms: u64,
    pub dir: Dir,
    pub len: usize,
}

/// Записанный поток наблюдений.
#[derive(Debug, Clone, Default)]
pub struct Flow {
    pub obs: Vec<Obs>,
}

impl Flow {
    pub fn new() -> Self {
        Flow::default()
    }

    pub fn record(&mut self, t_ms: u64, dir: Dir, len: usize) {
        self.obs.push(Obs { t_ms, dir, len });
    }

    /// Размеры записей заданного направления (для сравнения распределений).
    pub fn lengths(&self, dir: Dir) -> Vec<f64> {
        self.obs.iter().filter(|o| o.dir == dir).map(|o| o.len as f64).collect()
    }

    /// Все размеры записей независимо от направления.
    pub fn all_lengths(&self) -> Vec<f64> {
        self.obs.iter().map(|o| o.len as f64).collect()
    }

    /// Суммарные байты по направлению.
    pub fn total(&self, dir: Dir) -> u64 {
        self.obs.iter().filter(|o| o.dir == dir).map(|o| o.len as u64).sum()
    }

    /// Соотношение down:up (сколько нисходящих байт на один восходящий).
    /// Для медиа-легенды велико (~15); у симметричного туннеля близко к 1.
    pub fn down_up_ratio(&self) -> f64 {
        let up = self.total(Dir::Up).max(1) as f64;
        self.total(Dir::Down) as f64 / up
    }

    /// Длительность потока в мс (от первого до последнего наблюдения).
    pub fn duration_ms(&self) -> u64 {
        match (self.obs.first(), self.obs.last()) {
            (Some(a), Some(b)) => b.t_ms.saturating_sub(a.t_ms),
            _ => 0,
        }
    }

    /// Межпакетные интервалы (IAT) в мс — по всем наблюдениям в порядке записи.
    pub fn inter_arrival_ms(&self) -> Vec<f64> {
        self.obs
            .windows(2)
            .map(|w| w[1].t_ms.saturating_sub(w[0].t_ms) as f64)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.obs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Flow {
        let mut f = Flow::new();
        f.record(0, Dir::Up, 100);
        f.record(10, Dir::Down, 1400);
        f.record(25, Dir::Down, 1400);
        f.record(40, Dir::Up, 50);
        f
    }

    #[test]
    fn lengths_by_direction() {
        let f = sample();
        assert_eq!(f.lengths(Dir::Up), vec![100.0, 50.0]);
        assert_eq!(f.lengths(Dir::Down), vec![1400.0, 1400.0]);
    }

    #[test]
    fn totals_and_ratio() {
        let f = sample();
        assert_eq!(f.total(Dir::Up), 150);
        assert_eq!(f.total(Dir::Down), 2800);
        assert!((f.down_up_ratio() - 2800.0 / 150.0).abs() < 1e-9);
    }

    #[test]
    fn duration_and_iat() {
        let f = sample();
        assert_eq!(f.duration_ms(), 40);
        assert_eq!(f.inter_arrival_ms(), vec![10.0, 15.0, 15.0]);
    }

    #[test]
    fn empty_flow_is_safe() {
        let f = Flow::new();
        assert_eq!(f.duration_ms(), 0);
        assert_eq!(f.down_up_ratio(), 0.0);
        assert!(f.inter_arrival_ms().is_empty());
    }
}
