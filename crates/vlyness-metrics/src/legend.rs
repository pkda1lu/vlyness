//! Модель легенды: эталонное распределение, под которое мы маскируемся (§8.1).
//!
//! Легенда — это то приложение, в чей класс трафика мы хотим попасть (медиа-стриминг).
//! Здесь она задаётся тем же эмпирическим распределением длин, что и sampler shaping'а
//! ([`vlyness_shaping::LenDistribution`]). Из неё генерируются «эталонные» размеры
//! записей, с которыми [`crate::distance`] сравнивает наблюдаемый трафик.
//!
//! Важно про не-цикличность: наблюдаемые размеры записей VLYNESS **не совпадают** с
//! выходом sampler'а — на них влияют payload, превышающий выбранную цель, оверхед
//! AEAD/префикса и (в некоторых режимах) отсутствие padding. Именно этот зазор и
//! измеряет harness; совпадение распределений здесь ничем не гарантировано заранее.

use rand::rngs::StdRng;
use rand::SeedableRng;

use vlyness_shaping::{LenDistribution, LenSampler};

/// Эталонные классы длин для гистограммного сравнения (правые границы, байты).
/// Совпадают с бимодальностью медиа-профиля: мелкие служебные / средние / крупные.
pub const MEDIA_CLASS_EDGES: [f64; 2] = [120.0, 900.0];

/// Модель легенды поверх распределения длин.
pub struct LegendModel {
    dist: LenDistribution,
}

impl LegendModel {
    pub fn new(dist: LenDistribution) -> Self {
        LegendModel { dist }
    }

    /// Референс-медиа-легенда (`media-abr-v1`) — та же, что и в shaping.
    pub fn media() -> Self {
        LegendModel::new(LenDistribution::media_abr_v1())
    }

    /// Сгенерировать `n` эталонных размеров записей (детерминированно по `seed`).
    pub fn sample_record_sizes(&self, n: usize, seed: u64) -> Vec<f64> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut sampler = LenSampler::new(self.dist.clone());
        (0..n).map(|_| sampler.sample(&mut rng) as f64).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distance::ks_two_sample;

    #[test]
    fn two_legend_draws_are_close() {
        // Две независимые выборки из одной легенды должны быть статистически близки —
        // это калибровка «нуля» для harness: KS у совпадающих источников мал.
        let legend = LegendModel::media();
        let a = legend.sample_record_sizes(4000, 1);
        let b = legend.sample_record_sizes(4000, 2);
        let d = ks_two_sample(&a, &b);
        assert!(d < 0.1, "две выборки одной легенды должны быть близки, KS={d}");
    }

    #[test]
    fn legend_sizes_are_within_range() {
        let legend = LegendModel::media();
        for x in legend.sample_record_sizes(2000, 7) {
            assert!((40.0..=1460.0).contains(&x), "размер {x} вне границ легенды");
        }
    }
}
