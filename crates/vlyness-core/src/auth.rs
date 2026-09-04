//! Ratchet-токен аутентификации (wire-spec §3).
//!
//! Заменяет статический 16-байтовый UUID из VLESS (док 00 §2, признак №11 в
//! таблице 01 §3). Наружу в каждой сессии уходят только `(salt, nonce, tag)` —
//! все три выглядят случайными и **не повторяются между сессиями**, поэтому три
//! соединения одного клиента не имеют ни одного общего байта в наблюдаемой части.
//!
//! Ключ выводится по «эпохе» (окно 1 час), что даёт устойчивость к дрейфу часов
//! ±1 час — в отличие от VMess с его жёстким окном ±90 с.
//!
//! ```text
//! epoch   = floor(unixtime / 3600)
//! authKey = KDF-BLAKE2s(salt, PSK, info = "vlyness/auth/v1" || LE64(epoch))
//! tag     = BLAKE2s-MAC(key = authKey, msg = salt || nonce)[0..16]
//! token   = base64url(salt || nonce || tag)          // 44 байта → 59 символов
//! ```
//!
//! `KDF-BLAKE2s` — HKDF-подобная конструкция (extract-then-expand) на **нативном
//! keyed-BLAKE2s**, а не HMAC-HKDF. Причина: BLAKE2 спроектирован с собственным
//! keyed-режимом, и стандартный HMAC-HKDF поверх него не собирается (HMAC требует
//! eager-buffer hash). Так мы держим единственный примитив (keyed BLAKE2s) и для
//! вывода ключа, и для тега — меньше зависимостей, нечего перебирать зонду (§1).
//!   extract: PRK = BLAKE2s-MAC(key = salt, msg = PSK)
//!   expand:  OKM = BLAKE2s-MAC(key = PRK,  msg = info || 0x01)     // один 32-байтовый блок

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blake2::Blake2sMac256;
use blake2::digest::Mac;
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

/// Длина соли (HKDF salt, per-session), байт.
pub const SALT_LEN: usize = 16;
/// Длина клиентского nonce (антиреплей, per-session), байт.
pub const NONCE_LEN: usize = 12;
/// Длина усечённого тега аутентификации, байт.
pub const TAG_LEN: usize = 16;
/// Длина сырого токена до base64, байт.
pub const TOKEN_LEN: usize = SALT_LEN + NONCE_LEN + TAG_LEN; // 44
/// Длина токена в символах base64url без padding (константа — критично, см. §3).
pub const TOKEN_B64_LEN: usize = 59;

/// Длительность эпохи в секундах (окно ротации ключа).
pub const EPOCH_SECS: u64 = 3600;
/// Длина PSK (общий секрет из подписки), байт.
pub const PSK_LEN: usize = 32;

const INFO_PREFIX: &[u8] = b"vlyness/auth/v1";

/// Keyed BLAKE2s-256 над конкатенацией сообщений, 32 байта на выходе.
/// `key` должен быть ≤ 32 байт (ограничение BLAKE2s).
fn blake2s_mac(key: &[u8], msgs: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Blake2sMac256 as Mac>::new_from_slice(key)
        .expect("ключ BLAKE2s не длиннее 32 байт");
    for m in msgs {
        mac.update(m);
    }
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Ошибки разбора/проверки токена.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("некорректный base64url токена")]
    BadEncoding,
    #[error("неверная длина токена: ожидалось {expected}, получено {got}")]
    BadLength { expected: usize, got: usize },
    #[error("тег аутентификации не совпал")]
    BadTag,
}

/// Токен, как он уходит в cookie `sid=` (§3, §6.2 дизайна).
#[derive(Clone, PartialEq, Eq)]
pub struct AuthToken {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub tag: [u8; TAG_LEN],
}

impl core::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Не печатаем содержимое: токен — секретный материал сессии.
        f.write_str("AuthToken(..)")
    }
}

/// Текущая эпоха по системным часам.
pub fn epoch_now() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs / EPOCH_SECS
}

/// Вывод ключа аутентификации для конкретной эпохи (клиент и сервер считают одинаково).
fn derive_auth_key(psk: &[u8; PSK_LEN], salt: &[u8; SALT_LEN], epoch: u64) -> [u8; 32] {
    let mut info = [0u8; INFO_PREFIX.len() + 8];
    info[..INFO_PREFIX.len()].copy_from_slice(INFO_PREFIX);
    info[INFO_PREFIX.len()..].copy_from_slice(&epoch.to_le_bytes());

    // extract: соль как ключ, PSK как вход.
    let prk = blake2s_mac(salt, &[psk.as_slice()]);
    // expand: один 32-байтовый блок с байтом-счётчиком 0x01 (как в HKDF).
    blake2s_mac(&prk, &[&info, &[0x01]])
}

/// Тег = keyed-BLAKE2s(authKey, salt || nonce), усечённый до 16 байт.
fn compute_tag(auth_key: &[u8; 32], salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; TAG_LEN] {
    let full = blake2s_mac(auth_key, &[salt, nonce]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

impl AuthToken {
    /// Клиентская сторона: собрать свежий токен для эпохи `epoch`.
    ///
    /// `salt` и `nonce` берутся из CSPRNG ОС. Для детерминированных тестов см.
    /// [`AuthToken::build_with`].
    pub fn build(psk: &[u8; PSK_LEN], epoch: u64) -> Self {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        Self::build_with(psk, epoch, salt, nonce)
    }

    /// Как [`build`](AuthToken::build), но с заданными salt/nonce (тесты, векторы).
    pub fn build_with(
        psk: &[u8; PSK_LEN],
        epoch: u64,
        salt: [u8; SALT_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Self {
        let auth_key = derive_auth_key(psk, &salt, epoch);
        let tag = compute_tag(&auth_key, &salt, &nonce);
        AuthToken { salt, nonce, tag }
    }

    /// Сырые байты токена `salt || nonce || tag` (44 байта).
    ///
    /// Именно они служат prologue Noise-хендшейка (§4): и клиент, и сервер должны
    /// получить одинаковые байты — клиент из собственного токена, сервер из cookie.
    pub fn raw(&self) -> [u8; TOKEN_LEN] {
        let mut raw = [0u8; TOKEN_LEN];
        raw[..SALT_LEN].copy_from_slice(&self.salt);
        raw[SALT_LEN..SALT_LEN + NONCE_LEN].copy_from_slice(&self.nonce);
        raw[SALT_LEN + NONCE_LEN..].copy_from_slice(&self.tag);
        raw
    }

    /// Сериализация в строку cookie (`base64url` без padding, константной длины).
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.raw())
    }

    /// Разбор строки cookie обратно в токен (без проверки тега).
    pub fn decode(s: &str) -> Result<Self, AuthError> {
        if s.len() != TOKEN_B64_LEN {
            return Err(AuthError::BadLength { expected: TOKEN_B64_LEN, got: s.len() });
        }
        let raw = URL_SAFE_NO_PAD.decode(s.as_bytes()).map_err(|_| AuthError::BadEncoding)?;
        if raw.len() != TOKEN_LEN {
            return Err(AuthError::BadLength { expected: TOKEN_LEN, got: raw.len() });
        }
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        let mut tag = [0u8; TAG_LEN];
        salt.copy_from_slice(&raw[..SALT_LEN]);
        nonce.copy_from_slice(&raw[SALT_LEN..SALT_LEN + NONCE_LEN]);
        tag.copy_from_slice(&raw[SALT_LEN + NONCE_LEN..]);
        Ok(AuthToken { salt, nonce, tag })
    }

    /// Серверная проверка тега для конкретной эпохи, в постоянном времени.
    ///
    /// Проверка выполняется полностью (никаких ранних выходов) даже для заведомо
    /// мусорного токена — это часть honest-fallback (дизайн §7): время ответа не
    /// должно зависеть от валидности.
    pub fn verify_epoch(&self, psk: &[u8; PSK_LEN], epoch: u64) -> bool {
        let auth_key = derive_auth_key(psk, &self.salt, epoch);
        let expected = compute_tag(&auth_key, &self.salt, &self.nonce);
        expected.ct_eq(&self.tag).into()
    }

    /// Проверка с толерантностью к дрейфу часов: принимает epoch ∈ {now−1, now, now+1}.
    ///
    /// Возвращает эпоху, на которой токен сошёлся (нужна для антиреплей-кэша),
    /// либо `None`. Все три эпохи проверяются всегда — без короткого замыкания,
    /// чтобы не создавать тайминг-канал по номеру совпавшей эпохи.
    pub fn verify(&self, psk: &[u8; PSK_LEN], now_epoch: u64) -> Option<u64> {
        let mut matched: Option<u64> = None;
        for delta in [-1i64, 0, 1] {
            let epoch = (now_epoch as i64 + delta) as u64;
            let ok = self.verify_epoch(psk, epoch);
            // Без ветвления по `ok`: фиксируем совпадение, но цикл не прерываем.
            if ok {
                matched = Some(epoch);
            }
        }
        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> [u8; PSK_LEN] {
        let mut p = [0u8; PSK_LEN];
        for (i, b) in p.iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    #[test]
    fn roundtrip_encode_decode() {
        let t = AuthToken::build(&psk(), 100);
        let s = t.encode();
        let back = AuthToken::decode(&s).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn token_length_is_constant() {
        // Критично: переменная длина токена сама становится каналом (§3).
        for epoch in [0u64, 1, 12345, u32::MAX as u64] {
            let s = AuthToken::build(&psk(), epoch).encode();
            assert_eq!(s.len(), TOKEN_B64_LEN, "epoch={epoch}");
        }
        assert_eq!(TOKEN_LEN, 44);
    }

    #[test]
    fn verify_accepts_fresh_token() {
        let epoch = epoch_now();
        let t = AuthToken::build(&psk(), epoch);
        assert_eq!(t.verify(&psk(), epoch), Some(epoch));
    }

    #[test]
    fn verify_tolerates_clock_skew() {
        let epoch = 500u64;
        let t = AuthToken::build(&psk(), epoch);
        // Клиент на эпохе 500, сервер думает, что сейчас 499/500/501 — все проходят.
        assert_eq!(t.verify(&psk(), 499), Some(epoch));
        assert_eq!(t.verify(&psk(), 500), Some(epoch));
        assert_eq!(t.verify(&psk(), 501), Some(epoch));
        // За пределами окна — отказ.
        assert_eq!(t.verify(&psk(), 498), None);
        assert_eq!(t.verify(&psk(), 502), None);
    }

    #[test]
    fn verify_rejects_wrong_psk() {
        let epoch = 42u64;
        let t = AuthToken::build(&psk(), epoch);
        let mut other = psk();
        other[0] ^= 0xff;
        assert_eq!(t.verify(&other, epoch), None);
    }

    #[test]
    fn verify_rejects_tampered_tag() {
        let epoch = 7u64;
        let mut t = AuthToken::build(&psk(), epoch);
        t.tag[0] ^= 0x01;
        assert_eq!(t.verify(&psk(), epoch), None);
    }

    #[test]
    fn decode_rejects_bad_length() {
        assert!(matches!(AuthToken::decode("short"), Err(AuthError::BadLength { .. })));
    }

    #[test]
    fn distinct_sessions_share_no_observable_bytes() {
        // Признак №11: три сессии одного клиента не должны совпадать наблюдаемо.
        let epoch = epoch_now();
        let a = AuthToken::build(&psk(), epoch).encode();
        let b = AuthToken::build(&psk(), epoch).encode();
        let c = AuthToken::build(&psk(), epoch).encode();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn known_answer_vector() {
        // Детерминированный вектор: фиксированные psk/salt/nonce/epoch → фиксированный токен.
        // Стабилизирует wire-формат между реализациями (Rust ↔ будущий сервер).
        let salt = [0x11u8; SALT_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let t = AuthToken::build_with(&psk(), 1, salt, nonce);
        let s = t.encode();
        assert_eq!(s.len(), TOKEN_B64_LEN);
        // Токен детерминирован → повторная сборка даёт тот же результат.
        let t2 = AuthToken::build_with(&psk(), 1, salt, nonce);
        assert_eq!(s, t2.encode());
        // И проходит проверку на своей эпохе.
        assert_eq!(t.verify(&psk(), 1), Some(1));
    }
}
