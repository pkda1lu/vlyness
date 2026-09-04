//! # vlyness-carrier
//!
//! Носители (carrier) для сессии VLYNESS. Носитель — сменный внешний слой, внутри
//! которого бежит [`vlyness_transport::Session`]:
//!
//! - [`tls`] — TLS 1.3 поверх реального TCP (rustls + ring). Внешний слой, видимый DPI.
//! - [`h2bridge`] — мост `AsyncRead/AsyncWrite` поверх одного HTTP/2-стрима.
//! - [`http`] — HTTP/2-носитель `stream-one`: AUTH в cookie → Noise-prologue, honest-fallback (§7).
//! - ECH co-tenancy — *следующий слой* (whitelist §2.1, док 05).
//!
//! Разделение соответствует дизайну: сессионный протокол один, носитель выбирается
//! профилем и может меняться (co-tenancy → сервис-канал → refraction) без переписывания
//! сессии.

#![forbid(unsafe_code)]

pub mod h2bridge;
pub mod http;
pub mod tls;

pub use h2bridge::H2Stream;
pub use http::{authorize, client_segments, client_stream_one, serve, ServerParams, SessionHandler};
