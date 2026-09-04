//! Кадры на байтовом потоке: длина (u16 BE) + тело.
//!
//! Используется и для сообщений хендшейка (сырые байты Noise), и для transport-режима
//! (тело = запечатанный шифртекст кадра). Префикс длины — единственное, что видно
//! наблюдателю *внутри* несущей; его величину формирует sampler длин (§8.1), поэтому
//! на этом уровне мы просто честно пишем длину тела.
//!
//! Максимум тела — 65535 (u16). Запечатанный кадр как раз укладывается: plaintext ≤
//! `noise::MAX_PLAINTEXT` (65519) + тег 16 = 65535.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Максимальная длина тела одной записи.
pub const MAX_RECORD: usize = u16::MAX as usize;

/// Записать один кадр: `[u16 len][body]`.
pub async fn write_record<W>(w: &mut W, body: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = u16::try_from(body.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("тело записи {} байт превышает {MAX_RECORD}", body.len()),
        )
    })?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

/// Прочитать один кадр целиком. `UnexpectedEof`, если поток закрылся посреди записи.
pub async fn read_record<R>(r: &mut R) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_over_duplex() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payloads: Vec<Vec<u8>> =
            vec![b"".to_vec(), b"x".to_vec(), vec![0xAB; 1000], vec![0u8; MAX_RECORD]];
        let expect = payloads.clone();

        let writer = tokio::spawn(async move {
            for p in &payloads {
                write_record(&mut a, p).await.unwrap();
            }
        });

        for want in expect {
            let got = read_record(&mut b).await.unwrap();
            assert_eq!(got, want);
        }
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn oversize_body_is_rejected() {
        let (mut a, _b) = tokio::io::duplex(64);
        let big = vec![0u8; MAX_RECORD + 1];
        let err = write_record(&mut a, &big).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
