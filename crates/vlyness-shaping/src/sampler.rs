//! Sampler длин записей (дизайн §8.1).
//!
//! Не uniform random padding — он **сам по себе аномалия**: реальный HTTPS даёт
//! бимодальное распределение (пик на MSS ~1460 и пик на мелких служебных записях),
//! а равномерный шум такого профиля не имеет. Поэтому длины сэмплируются из
//! **эмпирического распределения** приложения-легенды: марковская цепочка по классам
//! длин (мелкая/средняя/крупная) + равномерный выбор конкретного размера внутри класса.

use rand::Rng;

/// Класс длин: диапазон размеров записи в байтах.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LenClass {
    pub min: usize,
    pub max: usize,
}

impl LenClass {
    pub fn new(min: usize, max: usize) -> Self {
        assert!(min <= max, "min ≤ max");
        LenClass { min, max }
    }
}

/// Ошибки построения распределения.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum DistError {
    #[error("нужен хотя бы один класс длин")]
    NoClasses,
    #[error("матрица переходов не квадратная под число классов")]
    BadMatrixShape,
    #[error("строка {row} матрицы переходов не суммируется в 1 (сумма {sum})")]
    RowNotStochastic { row: usize, sum: f64 },
    #[error("начальное распределение не суммируется в 1 (сумма {0})")]
    InitialNotStochastic(f64),
}

/// Эмпирическое распределение длин: классы + марковские переходы между ними.
#[derive(Debug, Clone)]
pub struct LenDistribution {
    classes: Vec<LenClass>,
    /// `transition[i][j]` — вероятность перейти из класса i в класс j.
    transition: Vec<Vec<f64>>,
    initial: Vec<f64>,
}

const STOCHASTIC_EPS: f64 = 1e-6;

impl LenDistribution {
    pub fn new(
        classes: Vec<LenClass>,
        transition: Vec<Vec<f64>>,
        initial: Vec<f64>,
    ) -> Result<Self, DistError> {
        let n = classes.len();
        if n == 0 {
            return Err(DistError::NoClasses);
        }
        if transition.len() != n || transition.iter().any(|r| r.len() != n) || initial.len() != n {
            return Err(DistError::BadMatrixShape);
        }
        for (i, row) in transition.iter().enumerate() {
            let sum: f64 = row.iter().sum();
            if (sum - 1.0).abs() > STOCHASTIC_EPS {
                return Err(DistError::RowNotStochastic { row: i, sum });
            }
        }
        let isum: f64 = initial.iter().sum();
        if (isum - 1.0).abs() > STOCHASTIC_EPS {
            return Err(DistError::InitialNotStochastic(isum));
        }
        Ok(LenDistribution { classes, transition, initial })
    }

    /// Референс-распределение `media-abr-v1` (имя используется в Profile):
    /// бимодальность — много мелких «служебных» и крупных «медийных» записей,
    /// средние редки; крупные склонны идти сериями (высокая самопетля).
    pub fn media_abr_v1() -> Self {
        let classes = vec![
            LenClass::new(40, 120),     // small: ACK-подобные/keepalive
            LenClass::new(200, 900),    // medium
            LenClass::new(1200, 1460),  // large: близко к MSS
        ];
        // Крупные тянут крупные (стрим сегмента), мелкие перемежаются.
        let transition = vec![
            vec![0.30, 0.20, 0.50],
            vec![0.35, 0.15, 0.50],
            vec![0.15, 0.10, 0.75],
        ];
        let initial = vec![0.25, 0.10, 0.65];
        // Значения статичны и корректны, поэтому new не может провалиться.
        LenDistribution::new(classes, transition, initial).expect("валидное распределение")
    }

    pub fn classes(&self) -> &[LenClass] {
        &self.classes
    }
}

/// Сэмплер, хранящий текущее состояние марковской цепочки.
#[derive(Debug, Clone)]
pub struct LenSampler {
    dist: LenDistribution,
    /// Текущий класс; None до первого сэмпла (тогда берётся `initial`).
    state: Option<usize>,
}

impl LenSampler {
    pub fn new(dist: LenDistribution) -> Self {
        LenSampler { dist, state: None }
    }

    /// Следующая целевая длина записи: выбрать класс по цепочке, затем размер в классе.
    pub fn sample<R: Rng + ?Sized>(&mut self, rng: &mut R) -> usize {
        let row = match self.state {
            None => &self.dist.initial,
            Some(i) => &self.dist.transition[i],
        };
        let next = pick_index(row, rng.gen::<f64>());
        self.state = Some(next);
        let class = self.dist.classes[next];
        if class.min == class.max {
            class.min
        } else {
            rng.gen_range(class.min..=class.max)
        }
    }

    /// Текущее состояние (для тестов/отладки).
    pub fn state(&self) -> Option<usize> {
        self.state
    }
}

/// Выбор индекса по кумулятивной вероятности для `r ∈ [0,1)`.
fn pick_index(weights: &[f64], r: f64) -> usize {
    let mut acc = 0.0;
    for (i, w) in weights.iter().enumerate() {
        acc += *w;
        if r < acc {
            return i;
        }
    }
    weights.len() - 1 // страховка от погрешности округления
}

/// Padding для кадра: сколько байт добить, чтобы plaintext-запись достигла `target`.
///
/// `overhead` — фиксированный заголовок кадра (в VLYNESS это `frame::HEADER_LEN`).
/// Возвращает `pad`, ограниченный `u16`. Если payload с заголовком уже ≥ target,
/// padding не добавляется (0) — дробление длинных записей остаётся за транспортом.
pub fn pad_to_target(payload_len: usize, overhead: usize, target: usize) -> u16 {
    let base = payload_len + overhead;
    if base >= target {
        return 0;
    }
    (target - base).min(u16::MAX as usize) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn rejects_non_stochastic_rows() {
        let classes = vec![LenClass::new(1, 2), LenClass::new(3, 4)];
        let bad = vec![vec![0.5, 0.4], vec![0.5, 0.5]]; // строка 0 не сумма 1
        let init = vec![0.5, 0.5];
        assert!(matches!(
            LenDistribution::new(classes, bad, init),
            Err(DistError::RowNotStochastic { row: 0, .. })
        ));
    }

    #[test]
    fn rejects_bad_shape() {
        let classes = vec![LenClass::new(1, 2)];
        let bad = vec![vec![0.5, 0.5]]; // 1 класс, но строка длины 2
        assert!(matches!(
            LenDistribution::new(classes, bad, vec![1.0]),
            Err(DistError::BadMatrixShape)
        ));
    }

    #[test]
    fn samples_stay_within_class_bounds() {
        let mut s = LenSampler::new(LenDistribution::media_abr_v1());
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..10_000 {
            let len = s.sample(&mut rng);
            assert!((40..=1460).contains(&len), "len={len} вне общих границ");
        }
    }

    #[test]
    fn degenerate_chain_is_deterministic() {
        // Всегда класс 1 (диапазон 500..=500) вне зависимости от rng.
        let classes = vec![LenClass::new(100, 100), LenClass::new(500, 500)];
        let transition = vec![vec![0.0, 1.0], vec![0.0, 1.0]];
        let initial = vec![0.0, 1.0];
        let dist = LenDistribution::new(classes, transition, initial).unwrap();
        let mut s = LenSampler::new(dist);
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..100 {
            assert_eq!(s.sample(&mut rng), 500);
            assert_eq!(s.state(), Some(1));
        }
    }

    #[test]
    fn distribution_is_bimodal_not_uniform() {
        // Проверяем, что крупных и мелких заметно больше средних (бимодальность).
        let mut s = LenSampler::new(LenDistribution::media_abr_v1());
        let mut rng = StdRng::seed_from_u64(99);
        let (mut small, mut medium, mut large) = (0, 0, 0);
        for _ in 0..30_000 {
            match s.sample(&mut rng) {
                l if l <= 120 => small += 1,
                l if l <= 900 => medium += 1,
                _ => large += 1,
            }
        }
        assert!(large > medium, "крупных ({large}) должно быть больше средних ({medium})");
        assert!(small > medium, "мелких ({small}) должно быть больше средних ({medium})");
    }

    #[test]
    fn pad_to_target_math() {
        assert_eq!(pad_to_target(100, 5, 200), 95); // 200 - (100+5)
        assert_eq!(pad_to_target(200, 5, 200), 0); // уже больше target
        assert_eq!(pad_to_target(0, 5, 5), 0); // ровно target
        // Ограничение u16.
        assert_eq!(pad_to_target(0, 0, 1_000_000), u16::MAX);
    }
}
