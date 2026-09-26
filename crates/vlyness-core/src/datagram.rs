//! Побочный datagram-канал: AEAD, устойчивый к потере и переупорядочиванию.
//!
//! Зачем отдельно от [`crate::noise::Transport`]: главный канал сессии — надёжный,
//! упорядоченный поток записей (Noise transport ведёт сквозной nonce-счётчик, любой
//! пропуск ломает распечатку). Нативные QUIC-датаграммы (RTC-форма, док 02 §2) —
//! **ненадёжные и неупорядоченные**: датаграмма может потеряться или прийти не по
//! порядку, и это нормально. Поэтому UDP-проброс (кадр `Datagram`) едет здесь, а не по
//! стриму, — тогда форма трафика становится datagram-доминантной, как у реального
//! видеозвонка, а не bulk-стримом.
//!
//! Конфиденциальность обязательна и здесь (§5.4 whitelist): носитель (CDN) терминирует
//! QUIC и видит нашу датаграмму. Поэтому каждая датаграмма запечатывается независимо:
//!
//! ```text
//! ключ    = KDF-BLAKE2s(handshake_hash, "vlyness/dgram/v1" || dir)   // dir ∈ {c2s,s2c}
//! nonce   = 0x00000000 || counter(8 BE)                              // 12 байт ChaCha20
//! wire    = counter(8 BE) || ChaCha20Poly1305_seal(ключ, nonce, plaintext)
//! ```
//!
//! Направления шифруются **разными ключами**, поэтому счётчики независимы и пара
//! (ключ, nonce) никогда не повторяется. Приём защищён скользящим окном анти-реплея
//! (как в DTLS/ESP): дубликат и слишком старый номер отвергаются, переупорядочивание в
//! пределах окна принимается. Ключ выведен из [`crate::noise::Transport::handshake_hash`],
//! поэтому наследует forward secrecy главного хендшейка.

use blake2::digest::Mac;
use blake2::Blake2sMac256;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

/// Длина ключа канала (ChaCha20-Poly1305), байт.
pub const DGRAM_KEY_LEN: usize = 32;
/// Длина префикса-счётчика на проводе, байт.
pub const COUNTER_LEN: usize = 8;
/// Оверхед AEAD-тега, байт.
pub const TAG_LEN: usize = 16;
/// Полный оверхед обёртки датаграммы (счётчик + тег) поверх plaintext.
pub const DGRAM_OVERHEAD: usize = COUNTER_LEN + TAG_LEN;
/// Ширина скользящего окна анти-реплея (номеров).
pub const REPLAY_WINDOW: u64 = 64;

const INFO: &[u8] = b"vlyness/dgram/v1";

/// Сторона канала — определяет, какой ключ используется для отправки, а какой для приёма.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Клиент: шлёт ключом c2s, принимает ключом s2c.
    Client,
    /// Сервер: шлёт ключом s2c, принимает ключом c2s.
    Server,
}

/// Keyed BLAKE2s-256 над конкатенацией сообщений (тот же примитив, что в `auth`).
fn blake2s_mac(key: &[u8], msgs: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <Blake2sMac256 as Mac>::new_from_slice(key).expect("ключ BLAKE2s не длиннее 32 байт");
    for m in msgs {
        mac.update(m);
    }
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Вывести ключ направления из хеша хендшейка.
fn derive_key(handshake_hash: &[u8], dir: &[u8]) -> [u8; DGRAM_KEY_LEN] {
    blake2s_mac(handshake_hash, &[INFO, dir])
}

fn cipher(key: &[u8; DGRAM_KEY_LEN]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

/// 12-байтовый nonce: 4 нулевых байта + счётчик (8 BE).
fn nonce_from(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&n)
}

/// Построить пару (запечатыватель, распечатыватель) для стороны `role` из хеша хендшейка.
pub fn channel(handshake_hash: &[u8], role: Role) -> (DatagramSealer, DatagramOpener) {
    let c2s = derive_key(handshake_hash, b"c2s");
    let s2c = derive_key(handshake_hash, b"s2c");
    let (seal_key, open_key) = match role {
        Role::Client => (c2s, s2c),
        Role::Server => (s2c, c2s),
    };
    (
        DatagramSealer { cipher: cipher(&seal_key), counter: 0 },
        DatagramOpener { cipher: cipher(&open_key), window: ReplayWindow::default() },
    )
}

/// Исходящая сторона: запечатывает датаграммы под монотонным счётчиком.
pub struct DatagramSealer {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl DatagramSealer {
    /// Запечатать одну датаграмму. Возвращает `counter(8 BE) || ciphertext` для отправки.
    /// Паникует только при исчерпании счётчика (2^64 датаграмм — недостижимо на сессию).
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ctr = self.counter;
        self.counter = self.counter.checked_add(1).expect("datagram counter не переполнится");
        let ct = self
            .cipher
            .encrypt(&nonce_from(ctr), plaintext)
            .expect("ChaCha20Poly1305 seal не падает на валидном входе");
        let mut out = Vec::with_capacity(COUNTER_LEN + ct.len());
        out.extend_from_slice(&ctr.to_be_bytes());
        out.extend_from_slice(&ct);
        out
    }
}

/// Входящая сторона: распечатывает и отсекает реплей/устаревшие датаграммы.
pub struct DatagramOpener {
    cipher: ChaCha20Poly1305,
    window: ReplayWindow,
}

impl DatagramOpener {
    /// Распечатать датаграмму `counter(8 BE) || ciphertext`. `None` — не прошла AEAD,
    /// либо реплей/слишком старая. Аутентификация идёт **до** обновления окна, поэтому
    /// подделка не сдвигает окно.
    pub fn open(&mut self, framed: &[u8]) -> Option<Vec<u8>> {
        if framed.len() < COUNTER_LEN + TAG_LEN {
            return None;
        }
        let ctr = u64::from_be_bytes(framed[..COUNTER_LEN].try_into().ok()?);
        let plaintext = self.cipher.decrypt(&nonce_from(ctr), &framed[COUNTER_LEN..]).ok()?;
        if !self.window.check_and_set(ctr) {
            return None; // валидная, но дубликат или вне окна — отбрасываем
        }
        Some(plaintext)
    }
}

/// Скользящее окно анти-реплея (битовая маска относительно наибольшего виденного номера).
#[derive(Debug, Default)]
struct ReplayWindow {
    seen_any: bool,
    highest: u64,
    /// Бит `i` = номер `highest - i` уже виден (бит 0 — сам `highest`).
    bitmap: u64,
}

impl ReplayWindow {
    /// Проверить номер и, если он новый, отметить. `false` — дубликат или слишком старый.
    fn check_and_set(&mut self, seq: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = seq;
            self.bitmap = 1;
            return true;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= REPLAY_WINDOW { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = seq;
            true
        } else {
            let diff = self.highest - seq;
            if diff >= REPLAY_WINDOW {
                return false; // за пределами окна — считаем реплеем
            }
            let mask = 1u64 << diff;
            if self.bitmap & mask != 0 {
                return false; // уже виден
            }
            self.bitmap |= mask;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (DatagramSealer, DatagramOpener, DatagramSealer, DatagramOpener) {
        let hash = [0x33u8; 32];
        let (cs, co) = channel(&hash, Role::Client);
        let (ss, so) = channel(&hash, Role::Server);
        (cs, co, ss, so)
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut cs, mut co, mut ss, mut so) = pair();
        // client -> server
        let w = cs.seal(b"hello udp");
        assert_eq!(so.open(&w).unwrap(), b"hello udp");
        // server -> client
        let w = ss.seal(b"reply udp");
        assert_eq!(co.open(&w).unwrap(), b"reply udp");
    }

    #[test]
    fn independent_direction_keys() {
        // Датаграмму c2s нельзя открыть распечатывателем c2s (клиент шлёт c2s, но и
        // клиентский opener — s2c): направления не путаются.
        let (mut cs, mut co, _ss, _so) = pair();
        let w = cs.seal(b"x");
        assert!(co.open(&w).is_none(), "клиент не должен открывать собственную c2s-датаграмму");
    }

    #[test]
    fn reorder_within_window_ok() {
        let (mut cs, _co, _ss, mut so) = pair();
        let a = cs.seal(b"a"); // ctr 0
        let b = cs.seal(b"b"); // ctr 1
        let c = cs.seal(b"c"); // ctr 2
        // Приходят вне порядка: c, a, b — все должны открыться ровно один раз.
        assert_eq!(so.open(&c).unwrap(), b"c");
        assert_eq!(so.open(&a).unwrap(), b"a");
        assert_eq!(so.open(&b).unwrap(), b"b");
    }

    #[test]
    fn duplicate_rejected() {
        let (mut cs, _co, _ss, mut so) = pair();
        let a = cs.seal(b"a");
        assert!(so.open(&a).is_some());
        assert!(so.open(&a).is_none(), "повтор той же датаграммы — реплей");
    }

    #[test]
    fn too_old_rejected() {
        let (mut cs, _co, _ss, mut so) = pair();
        let first = cs.seal(b"old"); // ctr 0
        // Продвигаем окно далеко вперёд.
        for _ in 0..(REPLAY_WINDOW + 5) {
            let w = cs.seal(b"x");
            so.open(&w).unwrap();
        }
        assert!(so.open(&first).is_none(), "номер за левым краем окна отвергается");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut cs, _co, _ss, mut so) = pair();
        let mut w = cs.seal(b"secret");
        let last = w.len() - 1;
        w[last] ^= 0x01;
        assert!(so.open(&w).is_none(), "битый тег не проходит AEAD");
        // И окно не сдвинулось: настоящая датаграмма с тем же ctr ещё пройдёт.
        let good = {
            let mut cs2 = super::channel(&[0x33u8; 32], Role::Client).0;
            cs2.seal(b"secret") // тот же ctr 0, что у битой
        };
        assert_eq!(so.open(&good).unwrap(), b"secret");
    }

    #[test]
    fn short_input_is_none() {
        let (_cs, _co, _ss, mut so) = pair();
        assert!(so.open(&[0u8; 4]).is_none());
        assert!(so.open(&[]).is_none());
    }
}
