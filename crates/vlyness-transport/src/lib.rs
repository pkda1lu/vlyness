//! # vlyness-transport
//!
//! Сессионный транспорт VLYNESS: length-prefixed запечатанные записи, Noise-хендшейк
//! и мультиплексирование логических потоков поверх **любого дуплексного байтового
//! потока**. Носитель (TLS/HTTP-2, loopback-duplex в тестах) — сменный адаптер сверху;
//! сессионный протокол одинаков.
//!
//! Слои:
//! - [`record`] — кадры `[u16 len][body]` на потоке (хендшейк и transport-режим);
//! - [`session`] — [`Session`]: хендшейк + seal/open кадров с padding от sampler'а (§8.1);
//! - [`mux`] — логические потоки (streamId/адрес) поверх [`vlyness_core::frame`].
//!
//! Сборка стека: `vlyness-core` (Noise+кадры+адрес) × `vlyness-shaping` (длины) под
//! управлением носителя и [`vlyness_discipline`](../vlyness_discipline) сверху.

#![forbid(unsafe_code)]

pub mod mux;
pub mod record;
pub mod session;

pub use mux::{MuxEvent, MuxError};
pub use session::{Session, SessionReader, SessionWriter, MAX_STREAM_CHUNK};
