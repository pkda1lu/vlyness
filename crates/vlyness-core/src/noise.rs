//! E2E-хендшейк и транспорт (wire-spec §4).
//!
//! Обёртка над `snow` для паттерна **Noise_IK_25519_ChaChaPoly_BLAKE2s**:
//! клиент (initiator) заранее знает статический ключ сервера `S_pub`, поэтому шлёт
//! полезные данные уже в первом сообщении (0-RTT).
//!
//! ```text
//! -> e, es, s, ss, [payload_0]     # msg1 (в теле первого HTTP-запроса)
//! <- e, ee, se, [payload_1]        # msg2 (в теле первого ответа)
//!                                  # далее transport-режим, две AEAD-цепочки
//! ```
//!
//! `prologue = AUTH` (§4): ключи хендшейка привязываются к токену аутентификации,
//! поэтому украденный AUTH нельзя переклеить к чужому хендшейку — стороны с разным
//! prologue не сойдутся.
//!
//! Зачем этот слой обязателен (дизайн §6.3, §5.4 whitelist): в режиме co-tenancy
//! носитель (CDN) терминирует внешний TLS и видит наш трафик. Без собственного E2E
//! разрешённый носитель читал бы всё, что мы через него гоним.

use snow::{Builder, HandshakeState, TransportState};

/// Строка параметров Noise. Фиксирована — никаких переговоров (§1).
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Жёсткий лимит длины сообщения Noise. Одна запечатанная запись обязана влезать.
pub const NOISE_MAX_MESSAGE: usize = 65535;
/// Оверхед AEAD-тега в transport-режиме.
pub const TAG_LEN: usize = 16;
/// Максимальная длина plaintext на одну запись transport-режима.
pub const MAX_PLAINTEXT: usize = NOISE_MAX_MESSAGE - TAG_LEN; // 65519

/// Ошибки хендшейка/транспорта.
#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("noise: {0}")]
    Snow(#[from] snow::Error),
    #[error("plaintext {0} байт превышает лимит записи {MAX_PLAINTEXT}")]
    PlaintextTooLarge(usize),
}

/// Статическая пара ключей X25519.
pub struct Keypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

/// Сгенерировать статическую пару ключей сервера (или клиента).
pub fn generate_keypair() -> Result<Keypair, NoiseError> {
    let kp = builder().generate_keypair()?;
    Ok(Keypair { private: kp.private, public: kp.public })
}

fn builder<'a>() -> Builder<'a> {
    // Параметры фиксированы и валидны, поэтому parse не может провалиться в рантайме.
    Builder::new(NOISE_PARAMS.parse().expect("валидная строка параметров Noise"))
}

/// Достаточный размер выходного буфера для сообщения хендшейка с данным payload.
fn hs_out_cap(payload_len: usize) -> usize {
    // Оверхед IK-сообщения: ephemeral(32) + шифр статики(32+16) + тег payload(16) ≈ 96.
    payload_len + 128
}

/// Клиентская сторона хендшейка (initiator).
pub struct Initiator {
    hs: HandshakeState,
}

impl Initiator {
    /// `server_pub` — статический публичный ключ сервера (из подписки);
    /// `client_priv` — статический приватный ключ клиента;
    /// `prologue` — сырые байты AUTH (salt||nonce||tag).
    pub fn new(server_pub: &[u8], client_priv: &[u8], prologue: &[u8]) -> Result<Self, NoiseError> {
        let hs = builder()
            .prologue(prologue)
            .local_private_key(client_priv)
            .remote_public_key(server_pub)
            .build_initiator()?;
        Ok(Initiator { hs })
    }

    /// Записать msg1 с 0-RTT payload. Возвращает байты для тела HTTP-запроса.
    pub fn write_msg1(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; hs_out_cap(payload.len())];
        let n = self.hs.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Прочитать msg2 и перейти в transport-режим. Возвращает (транспорт, payload_1).
    pub fn read_msg2(mut self, msg2: &[u8]) -> Result<(Transport, Vec<u8>), NoiseError> {
        let mut buf = vec![0u8; msg2.len()];
        let n = self.hs.read_message(msg2, &mut buf)?;
        buf.truncate(n);
        let ts = self.hs.into_transport_mode()?;
        Ok((Transport { ts }, buf))
    }
}

/// Серверная сторона хендшейка (responder).
pub struct Responder {
    hs: HandshakeState,
}

impl Responder {
    /// `server_priv` — статический приватный ключ сервера; `prologue` — байты AUTH,
    /// извлечённые сервером из cookie до начала хендшейка.
    pub fn new(server_priv: &[u8], prologue: &[u8]) -> Result<Self, NoiseError> {
        let hs = builder()
            .prologue(prologue)
            .local_private_key(server_priv)
            .build_responder()?;
        Ok(Responder { hs })
    }

    /// Прочитать msg1, вернуть 0-RTT payload_0.
    pub fn read_msg1(&mut self, msg1: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; msg1.len()];
        let n = self.hs.read_message(msg1, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Записать msg2 и перейти в transport-режим. Возвращает (транспорт, байты msg2).
    pub fn write_msg2(mut self, payload: &[u8]) -> Result<(Transport, Vec<u8>), NoiseError> {
        let mut buf = vec![0u8; hs_out_cap(payload.len())];
        let n = self.hs.write_message(payload, &mut buf)?;
        buf.truncate(n);
        let ts = self.hs.into_transport_mode()?;
        Ok((Transport { ts }, buf))
    }
}

/// Transport-режим: запечатывает/распечатывает записи после хендшейка.
///
/// Один [`Transport`] — одна сторона; nonce-счётчик ведёт `snow` внутри. Именно сюда
/// подаётся сериализованный [`crate::frame::Frame`], а на выходе — шифртекст, длину
/// которого затем оформляет sampler длин и record-префикс (см. [`crate::frame`]).
pub struct Transport {
    ts: TransportState,
}

impl Transport {
    /// Запечатать plaintext-запись → шифртекст (`plaintext.len() + 16`).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(NoiseError::PlaintextTooLarge(plaintext.len()));
        }
        let mut buf = vec![0u8; plaintext.len() + TAG_LEN];
        let n = self.ts.write_message(plaintext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Распечатать шифртекст → plaintext.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self.ts.read_message(ciphertext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Перевыработать **исходящий** ключ (после отправки управляющего кадра Rekey).
    /// Синхронизацию границы рекея между сторонами обеспечивает вызывающий (§4).
    pub fn rekey_outgoing(&mut self) {
        self.ts.rekey_outgoing();
    }

    /// Перевыработать **входящий** ключ (после приёма кадра Rekey).
    pub fn rekey_incoming(&mut self) {
        self.ts.rekey_incoming();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Addr, AddressFrame, Cmd};
    use crate::frame::{Frame, FrameType};
    use std::net::Ipv4Addr;

    /// Прогон полного хендшейка. Возвращает обе стороны transport-режима и оба payload.
    fn handshake() -> (Transport, Transport, Vec<u8>, Vec<u8>) {
        let server = generate_keypair().unwrap();
        let client = generate_keypair().unwrap();
        let auth = [0x5au8; 44]; // сырой AUTH как prologue

        let mut ini = Initiator::new(&server.public, &client.private, &auth).unwrap();
        let mut resp = Responder::new(&server.private, &auth).unwrap();

        let msg1 = ini.write_msg1(b"payload_0").unwrap();
        let p0 = resp.read_msg1(&msg1).unwrap();

        let (resp_t, msg2) = resp.write_msg2(b"payload_1").unwrap();
        let (ini_t, p1) = ini.read_msg2(&msg2).unwrap();

        (ini_t, resp_t, p0, p1)
    }

    #[test]
    fn zero_rtt_payloads_delivered() {
        let (_ic, _sc, p0, p1) = handshake();
        assert_eq!(p0, b"payload_0");
        assert_eq!(p1, b"payload_1");
    }

    #[test]
    fn transport_roundtrip_both_directions() {
        let (mut ini, mut resp, _, _) = handshake();

        // client -> server
        let ct = ini.seal(b"from client").unwrap();
        assert_eq!(ct.len(), "from client".len() + TAG_LEN);
        assert_eq!(resp.open(&ct).unwrap(), b"from client");

        // server -> client
        let ct = resp.seal(b"from server").unwrap();
        assert_eq!(ini.open(&ct).unwrap(), b"from server");
    }

    #[test]
    fn full_stack_carries_address_frame() {
        // Полный стек M1: AddressFrame -> Frame -> Noise transport -> и обратно.
        let (mut ini, mut resp, _, _) = handshake();

        let af = AddressFrame::new(1, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        let frame = Frame::new(FrameType::Address, af.encode().unwrap());
        let plaintext = frame.encode(37).unwrap(); // с padding, как задал бы sampler

        let sealed = ini.seal(&plaintext).unwrap();
        let opened = resp.open(&sealed).unwrap();

        let frame_back = Frame::decode(&opened).unwrap();
        assert_eq!(frame_back.ftype, FrameType::Address);
        let af_back = AddressFrame::decode(&frame_back.payload).unwrap();
        assert_eq!(af_back, af);
    }

    #[test]
    fn wrong_prologue_breaks_handshake() {
        // Разный prologue (AUTH) => стороны не сходятся: подмена токена ловится.
        let server = generate_keypair().unwrap();
        let client = generate_keypair().unwrap();

        let mut ini = Initiator::new(&server.public, &client.private, b"AUTH-A").unwrap();
        let mut resp = Responder::new(&server.private, b"AUTH-B").unwrap();

        let msg1 = ini.write_msg1(b"x").unwrap();
        assert!(resp.read_msg1(&msg1).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_open() {
        let (mut ini, mut resp, _, _) = handshake();
        let mut ct = ini.seal(b"secret").unwrap();
        ct[0] ^= 0x01;
        assert!(resp.open(&ct).is_err());
    }

    #[test]
    fn seal_rejects_oversize_plaintext() {
        let (mut ini, _, _, _) = handshake();
        let big = vec![0u8; MAX_PLAINTEXT + 1];
        assert!(matches!(ini.seal(&big), Err(NoiseError::PlaintextTooLarge(_))));
    }
}
