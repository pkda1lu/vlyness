//! # vlyness-shaping
//!
//! Traffic shaping (дизайн §8): форма трафика важнее содержания. Три подсистемы,
//! управляемые Profile, закрывают признаки формы (модель угроз 01 §3):
//!
//! - [`sampler`] — длины записей из эмпирического распределения (не uniform padding,
//!   который сам по себе аномалия) — признак №6;
//! - [`cadence`] — постоянный ритм запросов сегментов, idle-fill — признаки №8, №9;
//! - [`symmetrize`] — дросселирование/дополнение восходящего канала под down:up — №7.
//!
//! Всё чистое и детерминированно тестируемое: RNG инъектируется (в тестах — seedable
//! `StdRng`), состояние объёмов/цепочки хранится явно.

#![forbid(unsafe_code)]

pub mod cadence;
pub mod sampler;
pub mod symmetrize;

pub use cadence::Cadence;
pub use sampler::{pad_to_target, LenClass, LenDistribution, LenSampler};
pub use symmetrize::Symmetrizer;
