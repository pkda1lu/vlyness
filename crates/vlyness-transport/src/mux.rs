//! Мультиплексирование логических потоков поверх одного сессионного канала.
//!
//! Из модели угроз (признак №5) всё гонится в **одном** TLS-соединении, поэтому
//! пользовательские потоки различаются `streamId`. Ядро [`vlyness_core::frame::Frame`]
//! несёт только тип и payload; этот модуль задаёт соглашение, как в payload кодируются
//! streamId и адрес:
//!
//! - `Open`  → кадр `Address`, payload = сериализованный [`AddressFrame`] (содержит streamId);
//! - `Data`  → кадр `StreamData`, payload = `streamId(2 BE) ++ данные`;
//! - `Close` → кадр `StreamClose`, payload = `streamId(2 BE)`;
//! - `KeepAlive` → кадр `KeepAlive` без полезных данных (только padding на уровне записи).

use vlyness_core::address::AddressFrame;
use vlyness_core::frame::{Frame, FrameType};

/// Логическое событие мультиплексора.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxEvent {
    /// Открыть поток к цели (адрес несёт streamId).
    Open(AddressFrame),
    /// Данные потока.
    Data { stream_id: u16, data: Vec<u8> },
    /// Закрыть поток.
    Close { stream_id: u16 },
    /// Keepalive/idle-fill.
    KeepAlive,
}

/// Ошибки декодирования события мультиплексора.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MuxError {
    #[error("кадр {0:?} не несёт streamId (нужно ≥2 байт)")]
    MissingStreamId(FrameType),
    #[error("не удалось разобрать адресный кадр: {0}")]
    BadAddress(#[from] vlyness_core::address::AddressError),
    #[error("тип кадра {0:?} не является событием мультиплексора")]
    UnexpectedType(FrameType),
}

/// Закодировать событие в кадр ядра.
pub fn encode(ev: &MuxEvent) -> Frame {
    match ev {
        MuxEvent::Open(af) => {
            // AddressFrame::encode может вернуть ошибку только при слишком длинном
            // домене (>255); такой AddressFrame не должен доходить сюда.
            let payload = af.encode().expect("домен ≤255 проверяется при создании AddressFrame");
            Frame::new(FrameType::Address, payload)
        }
        MuxEvent::Data { stream_id, data } => {
            let mut payload = Vec::with_capacity(2 + data.len());
            payload.extend_from_slice(&stream_id.to_be_bytes());
            payload.extend_from_slice(data);
            Frame::new(FrameType::StreamData, payload)
        }
        MuxEvent::Close { stream_id } => {
            Frame::new(FrameType::StreamClose, stream_id.to_be_bytes().to_vec())
        }
        MuxEvent::KeepAlive => Frame::keepalive(),
    }
}

/// Разобрать кадр ядра в событие мультиплексора.
pub fn decode(frame: &Frame) -> Result<MuxEvent, MuxError> {
    match frame.ftype {
        FrameType::Address => Ok(MuxEvent::Open(AddressFrame::decode(&frame.payload)?)),
        FrameType::StreamData => {
            let (id, data) = split_stream_id(frame.ftype, &frame.payload)?;
            Ok(MuxEvent::Data { stream_id: id, data: data.to_vec() })
        }
        FrameType::StreamClose => {
            let (id, _) = split_stream_id(frame.ftype, &frame.payload)?;
            Ok(MuxEvent::Close { stream_id: id })
        }
        FrameType::KeepAlive => Ok(MuxEvent::KeepAlive),
        other => Err(MuxError::UnexpectedType(other)),
    }
}

fn split_stream_id(ft: FrameType, payload: &[u8]) -> Result<(u16, &[u8]), MuxError> {
    if payload.len() < 2 {
        return Err(MuxError::MissingStreamId(ft));
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    Ok((id, &payload[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlyness_core::address::{Addr, Cmd};
    use std::net::Ipv4Addr;

    fn roundtrip(ev: MuxEvent) {
        let frame = encode(&ev);
        assert_eq!(decode(&frame).unwrap(), ev);
    }

    #[test]
    fn open_roundtrips() {
        let af = AddressFrame::new(3, Cmd::Tcp, 443, Addr::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        roundtrip(MuxEvent::Open(af));
    }

    #[test]
    fn data_roundtrips() {
        roundtrip(MuxEvent::Data { stream_id: 42, data: b"payload".to_vec() });
        roundtrip(MuxEvent::Data { stream_id: 0, data: vec![] });
    }

    #[test]
    fn close_and_keepalive_roundtrip() {
        roundtrip(MuxEvent::Close { stream_id: 7 });
        roundtrip(MuxEvent::KeepAlive);
    }

    #[test]
    fn data_frame_without_stream_id_is_error() {
        let frame = Frame::new(FrameType::StreamData, vec![0x01]); // 1 байт < 2
        assert_eq!(decode(&frame), Err(MuxError::MissingStreamId(FrameType::StreamData)));
    }
}
