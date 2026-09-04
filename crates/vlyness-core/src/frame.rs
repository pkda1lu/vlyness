//! Кадр E2E-слоя (wire-spec §5) — plaintext-представление.
//!
//! Этот модуль отвечает только за **сериализацию/десериализацию открытого кадра**
//! и за padding. Запечатывание в AEAD выполняет транспорт поверх Noise (§4): готовый
//! plaintext-буфер отдаётся `snow`-у, который шифрует его ChaCha20-Poly1305 со своим
//! счётчиком nonce. Такое разделение слоёв не даёт дублировать крипто.
//!
//! ```text
//! Открытый буфер (до AEAD):
//! +--------+------------+----------+---------------+-------------+
//! |  1 B   |    2 B     |   2 B    |  payloadLen B |   padLen B  |
//! +--------+------------+----------+---------------+-------------+
//! |  type  | payloadLen |  padLen  |    payload    |   padding   |
//! +--------+------------+----------+---------------+-------------+
//! ```
//!
//! `payloadLen`/`padLen` находятся **внутри** будущего шифртекста, поэтому наблюдателю
//! недоступны: он видит лишь суммарную длину запечатанной записи, которую задаёт
//! sampler длин (дизайн §8.1). Padding содержимого не несёт (под AEAD неотличим).

/// Длина фиксированного заголовка кадра, байт: type(1) + payloadLen(2) + padLen(2).
pub const HEADER_LEN: usize = 5;
/// Оверхед AEAD-тега при запечатывании (ChaCha20-Poly1305 / AES-GCM), байт.
pub const AEAD_TAG_LEN: usize = 16;
/// Длина префикса длины записи на потоке (u16, вне AEAD), байт.
pub const RECORD_LEN_PREFIX: usize = 2;
/// Максимум для payload и padding по отдельности (оба — u16).
pub const MAX_FIELD: usize = u16::MAX as usize;

/// Тип кадра (первый байт заголовка).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Данные логического потока.
    StreamData = 0x01,
    /// Открытие нового логического потока (следом — адресный кадр, см. `address`).
    StreamOpen = 0x02,
    /// Закрытие логического потока.
    StreamClose = 0x03,
    /// Keepalive / idle-fill (несёт только padding).
    KeepAlive = 0x04,
    /// Сигнал перевыработки ключей.
    Rekey = 0x05,
    /// Адресный кадр (VLESS-совместимое ядро, §6).
    Address = 0x06,
}

impl FrameType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => FrameType::StreamData,
            0x02 => FrameType::StreamOpen,
            0x03 => FrameType::StreamClose,
            0x04 => FrameType::KeepAlive,
            0x05 => FrameType::Rekey,
            0x06 => FrameType::Address,
            _ => return None,
        })
    }
}

/// Ошибки разбора кадра.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("буфер короче заголовка: {0} < {HEADER_LEN}")]
    TooShort(usize),
    #[error("неизвестный тип кадра: {0:#04x}")]
    BadType(u8),
    #[error("длина буфера не совпадает с заголовком: заявлено {declared}, фактически {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("payload превышает максимум u16: {0}")]
    PayloadTooLarge(usize),
    #[error("padding превышает максимум u16: {0}")]
    PadTooLarge(usize),
}

/// Разобранный кадр. `payload` — полезные данные без padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ftype: FrameType,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Кадр с данными.
    pub fn new(ftype: FrameType, payload: Vec<u8>) -> Self {
        Frame { ftype, payload }
    }

    /// Keepalive/idle-fill: без полезных данных, только padding при сериализации.
    pub fn keepalive() -> Self {
        Frame { ftype: FrameType::KeepAlive, payload: Vec::new() }
    }

    /// Сериализация в открытый буфер с заданным числом байт padding.
    ///
    /// `pad_len` выбирает sampler длин (дизайн §8.1), чтобы итоговая длина записи
    /// была сэмплом из эмпирического распределения приложения-легенды. Padding
    /// заполняется нулями: под AEAD его содержимое неотличимо, а детерминизм
    /// удобен для тестов и векторов.
    pub fn encode(&self, pad_len: u16) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_FIELD {
            return Err(FrameError::PayloadTooLarge(self.payload.len()));
        }
        let payload_len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(HEADER_LEN + self.payload.len() + pad_len as usize);
        buf.push(self.ftype as u8);
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&pad_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf.resize(buf.len() + pad_len as usize, 0);
        Ok(buf)
    }

    /// Разбор открытого буфера (после AEAD-расшифровки) обратно в кадр.
    ///
    /// Длина буфера должна **точно** совпадать с `HEADER_LEN + payloadLen + padLen`
    /// — запечатанная запись самодостаточна, лишних/недостающих байт быть не может.
    pub fn decode(buf: &[u8]) -> Result<Frame, FrameError> {
        if buf.len() < HEADER_LEN {
            return Err(FrameError::TooShort(buf.len()));
        }
        let ftype = FrameType::from_u8(buf[0]).ok_or(FrameError::BadType(buf[0]))?;
        let payload_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let pad_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let declared = HEADER_LEN + payload_len + pad_len;
        if declared != buf.len() {
            return Err(FrameError::LengthMismatch { declared, actual: buf.len() });
        }
        let payload = buf[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
        Ok(Frame { ftype, payload })
    }

    /// Размер открытого буфера при данном payload и padding.
    pub fn plaintext_len(payload_len: usize, pad_len: usize) -> usize {
        HEADER_LEN + payload_len + pad_len
    }

    /// Размер записи **на проводе** после запечатывания: префикс длины + шифртекст + тег.
    /// Именно эту величину видит наблюдатель и формирует sampler длин.
    pub fn wire_len(payload_len: usize, pad_len: usize) -> usize {
        RECORD_LEN_PREFIX + Self::plaintext_len(payload_len, pad_len) + AEAD_TAG_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_no_padding() {
        let f = Frame::new(FrameType::StreamData, b"hello vlyness".to_vec());
        let buf = f.encode(0).unwrap();
        assert_eq!(buf.len(), HEADER_LEN + f.payload.len());
        assert_eq!(Frame::decode(&buf).unwrap(), f);
    }

    #[test]
    fn roundtrip_with_padding_strips_it() {
        let f = Frame::new(FrameType::StreamData, b"abc".to_vec());
        let buf = f.encode(200).unwrap();
        assert_eq!(buf.len(), HEADER_LEN + 3 + 200);
        // Padding не влияет на разобранный payload.
        assert_eq!(Frame::decode(&buf).unwrap(), f);
    }

    #[test]
    fn keepalive_is_pure_padding() {
        let f = Frame::keepalive();
        let buf = f.encode(512).unwrap();
        assert_eq!(buf.len(), HEADER_LEN + 512);
        let d = Frame::decode(&buf).unwrap();
        assert_eq!(d.ftype, FrameType::KeepAlive);
        assert!(d.payload.is_empty());
    }

    #[test]
    fn all_types_roundtrip() {
        for t in [
            FrameType::StreamData,
            FrameType::StreamOpen,
            FrameType::StreamClose,
            FrameType::KeepAlive,
            FrameType::Rekey,
            FrameType::Address,
        ] {
            let f = Frame::new(t, vec![1, 2, 3]);
            let buf = f.encode(7).unwrap();
            assert_eq!(Frame::decode(&buf).unwrap(), f);
        }
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert_eq!(Frame::decode(&[0x01, 0x00]), Err(FrameError::TooShort(2)));
    }

    #[test]
    fn decode_rejects_bad_type() {
        // type=0xff, payloadLen=0, padLen=0
        let buf = [0xff, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(Frame::decode(&buf), Err(FrameError::BadType(0xff)));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // Заявлено payloadLen=10, а данных нет.
        let buf = [0x01, 0x00, 0x0a, 0x00, 0x00];
        assert_eq!(
            Frame::decode(&buf),
            Err(FrameError::LengthMismatch { declared: HEADER_LEN + 10, actual: HEADER_LEN })
        );
    }

    #[test]
    fn max_payload_roundtrips() {
        let f = Frame::new(FrameType::StreamData, vec![0xAB; MAX_FIELD]);
        let buf = f.encode(0).unwrap();
        assert_eq!(Frame::decode(&buf).unwrap(), f);
    }

    #[test]
    fn wire_len_accounts_prefix_and_tag() {
        // 3 байта payload + 10 padding → 5+3+10 plaintext, +2 префикс +16 тег.
        assert_eq!(Frame::plaintext_len(3, 10), 18);
        assert_eq!(Frame::wire_len(3, 10), 18 + RECORD_LEN_PREFIX + AEAD_TAG_LEN);
    }
}
