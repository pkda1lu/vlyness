//! # vlyness-core
//!
//! Ядро wire-примитивов VLYNESS (см. `docs/03-wire-spec.md`):
//!
//! - [`auth`] — ratchet-токен аутентификации (§3);
//! - [`frame`] — кадры E2E-слоя, plaintext-кодек (§5);
//! - [`address`] — адресный кадр, VLESS-совместимое ядро (§6);
//! - [`noise`] — E2E-хендшейк Noise_IK и transport-режим (§4);
//! - [`replay`] — анти-реплей кэш nonce по окну эпох (§3).
//!
//! Криптонабор фиксирован без переговоров (§1): X25519 / Noise_IK /
//! ChaCha20-Poly1305 / HKDF-BLAKE2s. Отсутствие ciphersuite-negotiation
//! умышленно — нечего перебирать зонду и нечего fingerprint'ить по набору.

#![forbid(unsafe_code)]

pub mod address;
pub mod auth;
pub mod frame;
pub mod noise;
pub mod replay;
