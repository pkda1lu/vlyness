//! Меры расхождения распределений — сердце измерения «неотличимости» (док 04 §2).
//!
//! Наблюдатель (ТСПУ) отличает наш трафик от легенды, обучив классификатор на
//! потоковых признаках. Мы аппроксимируем его силу двухвыборочными статистиками:
//! насколько распределение наблюдаемых величин (размеры записей, интервалы) отличается
//! от распределения легенды. Малое расхождение ⇒ классификатору не за что зацепиться.

/// Двухвыборочная статистика Колмогорова–Смирнова: `max |CDF_a(x) − CDF_b(x)|`.
///
/// Значение в [0, 1]: 0 — распределения совпадают, 1 — не пересекаются. Это DoD из
/// док 04 §3 для признака «размерный профиль записей неотличим от легенды».
/// Пустые выборки трактуются консервативно как максимально различные.
pub fn ks_two_sample(a: &[f64], b: &[f64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 1.0;
    }
    let mut sa = a.to_vec();
    let mut sb = b.to_vec();
    sa.sort_by(|x, y| x.partial_cmp(y).unwrap());
    sb.sort_by(|x, y| x.partial_cmp(y).unwrap());

    let (na, nb) = (sa.len() as f64, sb.len() as f64);
    let (mut i, mut j) = (0usize, 0usize);
    let mut d: f64 = 0.0;
    // Идём по объединённой отсортированной оси, сравнивая эмпирические CDF.
    while i < sa.len() && j < sb.len() {
        let x = sa[i].min(sb[j]);
        while i < sa.len() && sa[i] <= x {
            i += 1;
        }
        while j < sb.len() && sb[j] <= x {
            j += 1;
        }
        let diff = (i as f64 / na - j as f64 / nb).abs();
        if diff > d {
            d = diff;
        }
    }
    d
}

/// Разбить величину `x` на индекс класса по правым границам `edges` (возрастающие).
/// Значения выше последней границы попадают в последний класс.
fn class_of(x: f64, edges: &[f64]) -> usize {
    for (i, e) in edges.iter().enumerate() {
        if x <= *e {
            return i;
        }
    }
    edges.len()
}

/// Доли выборки по классам (гистограмма, нормированная в 1). Число классов = `edges.len()+1`.
pub fn class_fractions(sample: &[f64], edges: &[f64]) -> Vec<f64> {
    let mut counts = vec![0usize; edges.len() + 1];
    for &x in sample {
        counts[class_of(x, edges)] += 1;
    }
    let total = sample.len().max(1) as f64;
    counts.into_iter().map(|c| c as f64 / total).collect()
}

/// L1-расстояние (полная вариация ×2) между гистограммами по одним и тем же классам.
/// В [0, 2]: 0 — совпадают, 2 — не пересекаются.
pub fn hist_l1(a: &[f64], edges: &[f64], b: &[f64]) -> f64 {
    let fa = class_fractions(a, edges);
    let fb = class_fractions(b, edges);
    fa.iter().zip(&fb).map(|(x, y)| (x - y).abs()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ks_identical_is_zero() {
        let a = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(ks_two_sample(&a, &a), 0.0);
    }

    #[test]
    fn ks_disjoint_is_one() {
        let a = [1.0, 2.0, 3.0, 4.0];
        let b = [10.0, 11.0, 12.0, 13.0];
        assert!((ks_two_sample(&a, &b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ks_partial_overlap_is_between() {
        // Половина b смещена → KS около 0.5.
        let a = [1.0, 2.0, 3.0, 4.0];
        let b = [1.0, 2.0, 30.0, 40.0];
        let d = ks_two_sample(&a, &b);
        assert!((0.4..=0.6).contains(&d), "KS={d}");
    }

    #[test]
    fn ks_is_symmetric() {
        let a = [1.0, 5.0, 5.0, 9.0];
        let b = [2.0, 3.0, 8.0, 8.0, 8.0];
        assert!((ks_two_sample(&a, &b) - ks_two_sample(&b, &a)).abs() < 1e-12);
    }

    #[test]
    fn empty_sample_is_max_distance() {
        assert_eq!(ks_two_sample(&[], &[1.0]), 1.0);
    }

    #[test]
    fn class_fractions_sum_to_one() {
        let edges = [100.0, 900.0]; // 3 класса: ≤100, ≤900, >900
        let f = class_fractions(&[50.0, 200.0, 1500.0, 1600.0], &edges);
        assert_eq!(f, vec![0.25, 0.25, 0.5]);
    }

    #[test]
    fn hist_l1_identical_is_zero() {
        let edges = [100.0, 900.0];
        let a = [50.0, 200.0, 1500.0];
        assert_eq!(hist_l1(&a, &edges, &a), 0.0);
    }

    #[test]
    fn hist_l1_disjoint_is_two() {
        let edges = [100.0];
        let a = [10.0, 20.0]; // весь в классе 0
        let b = [500.0, 600.0]; // весь в классе 1
        assert!((hist_l1(&a, &edges, &b) - 2.0).abs() < 1e-9);
    }
}
