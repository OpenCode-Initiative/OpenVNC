//! Helpers de E/S assincrona sobre qualquer `AsyncRead`/`AsyncWrite`
//! (TCP, TLS ou um stream QUIC).

use openvnc_core::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{decode_payload, encode_with_limit, parse_header, Message, HEADER_LEN};

/// Le exatamente uma mensagem, validando o cabecalho antes de alocar.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R, max_payload: u32) -> Result<Message> {
    let mut hb = [0u8; HEADER_LEN];
    r.read_exact(&mut hb).await?;
    let h = parse_header(&hb, max_payload)?;
    let mut payload = vec![0u8; h.length as usize];
    r.read_exact(&mut payload).await?;
    decode_payload(h.ty, &payload)
}

/// Escreve uma mensagem e faz flush.
pub async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    m: &Message,
    max_payload: u32,
) -> Result<()> {
    let b = encode_with_limit(m, max_payload)?;
    w.write_all(&b).await?;
    w.flush().await?;
    Ok(())
}
