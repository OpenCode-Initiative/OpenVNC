//! Decodificadores de encodings RFB (RFC 6143 secao 7.7).
//!
//! Todos os decoders sao *retomaveis*: recebem o buffer acumulado e
//! retornam quantos bytes consumiram e se o retangulo terminou. Se faltam
//! dados, consomem o que for possivel (ou nada) e o chamador reenvia o
//! restante junto com bytes novos.

use flate2::{Decompress, FlushDecompress, Status};
use openvnc_core::{check_limit, Error, PixelFormat, Rect, Result};
use openvnc_framebuffer::Framebuffer;

pub mod encode;
mod tight;
#[cfg(feature = "h264")]
pub mod video;
pub use encode::EncoderState;
pub use tight::MAX_TIGHT_COMPRESSED;

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Codigos de encoding.
pub mod encoding {
    /// Raw.
    pub const RAW: i32 = 0;
    /// CopyRect.
    pub const COPY_RECT: i32 = 1;
    /// Hextile.
    pub const HEXTILE: i32 = 5;
    /// ZRLE.
    pub const ZRLE: i32 = 16;
    /// Tight.
    pub const TIGHT: i32 = 7;
    /// Pseudo-encoding Cursor.
    pub const CURSOR: i32 = -239;
    /// Qualidade JPEG do Tight, nivel 8 (de -32 = 0 a -23 = 9).
    pub const JPEG_QUALITY_8: i32 = -24;
    /// Pseudo-encoding DesktopSize.
    pub const DESKTOP_SIZE: i32 = -223;
    /// Pseudo-encoding ExtendedDesktopSize.
    pub const EXTENDED_DESKTOP_SIZE: i32 = -308;
}

/// Limite de bytes comprimidos por retangulo ZRLE.
pub const MAX_ZRLE_COMPRESSED: u64 = 64 * 1024 * 1024;

/// Resultado de uma chamada de decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Bytes consumidos da entrada.
    pub consumed: usize,
    /// Retangulo concluido.
    pub done: bool,
}

/// Estado persistente por conexao (o stream zlib do ZRLE e unico).
pub struct CodecState {
    zrle: Decompress,
    tight: tight::TightState,
}

impl Default for CodecState {
    fn default() -> Self {
        CodecState {
            zrle: Decompress::new(true),
            tight: tight::TightState::default(),
        }
    }
}

impl std::fmt::Debug for CodecState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodecState")
    }
}

/// Decoder de um retangulo em andamento.
#[derive(Debug)]
pub struct RectDecoder {
    rect: Rect,
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    Raw { row: u16 },
    CopyRect,
    Hextile(HextileState),
    Zrle,
    Tight,
}

#[derive(Debug, Default)]
struct HextileState {
    tile: u32,
    bg: [u8; 4],
    fg: [u8; 4],
}

impl RectDecoder {
    /// Cria um decoder para `encoding`; erro se nao suportado.
    pub fn new(rect: Rect, encoding: i32) -> Result<Self> {
        let kind = match encoding {
            encoding::RAW => Kind::Raw { row: 0 },
            encoding::COPY_RECT => Kind::CopyRect,
            encoding::HEXTILE => Kind::Hextile(HextileState::default()),
            encoding::ZRLE => Kind::Zrle,
            encoding::TIGHT => Kind::Tight,
            other => return Err(Error::Unsupported(format!("encoding {other}"))),
        };
        Ok(RectDecoder { rect, kind })
    }

    /// Decodifica o maximo possivel de `input`.
    pub fn decode(
        &mut self,
        input: &[u8],
        pf: &PixelFormat,
        fb: &mut Framebuffer,
        state: &mut CodecState,
    ) -> Result<Progress> {
        let r = self.rect;
        match &mut self.kind {
            Kind::Raw { row } => decode_raw(r, row, input, pf, fb),
            Kind::CopyRect => {
                if input.len() < 4 {
                    return Ok(Progress {
                        consumed: 0,
                        done: false,
                    });
                }
                let sx = u16::from_be_bytes([input[0], input[1]]);
                let sy = u16::from_be_bytes([input[2], input[3]]);
                fb.copy_rect(sx, sy, r);
                Ok(Progress {
                    consumed: 4,
                    done: true,
                })
            }
            Kind::Hextile(st) => decode_hextile(r, st, input, pf, fb),
            Kind::Zrle => decode_zrle(r, input, pf, fb, state),
            Kind::Tight => tight::decode_tight(r, input, pf, fb, &mut state.tight),
        }
    }
}

fn decode_raw(
    r: Rect,
    row: &mut u16,
    input: &[u8],
    pf: &PixelFormat,
    fb: &mut Framebuffer,
) -> Result<Progress> {
    let row_bytes = usize::from(r.width) * pf.bytes_per_pixel();
    let mut consumed = 0;
    if row_bytes == 0 {
        return Ok(Progress {
            consumed: 0,
            done: true,
        });
    }
    while *row < r.height && input.len() - consumed >= row_bytes {
        fb.put_row(
            r.x,
            r.y.saturating_add(*row),
            &input[consumed..consumed + row_bytes],
            pf,
        );
        consumed += row_bytes;
        *row += 1;
    }
    Ok(Progress {
        consumed,
        done: *row >= r.height,
    })
}

/// Tamanho de um tile hextile em bytes, ou None se faltam dados.
fn hextile_tile_len(input: &[u8], bpp: usize) -> Option<usize> {
    let flags = *input.first()?;
    if flags & 1 != 0 {
        return Some(1); // raw: tamanho final calculado pelo chamador
    }
    let mut n = 1;
    if flags & 2 != 0 {
        n += bpp;
    }
    if flags & 4 != 0 {
        n += bpp;
    }
    if flags & 8 != 0 {
        let count = usize::from(*input.get(n)?);
        n += 1;
        n += count * if flags & 16 != 0 { bpp + 2 } else { 2 };
    }
    Some(n)
}

fn decode_hextile(
    r: Rect,
    st: &mut HextileState,
    input: &[u8],
    pf: &PixelFormat,
    fb: &mut Framebuffer,
) -> Result<Progress> {
    let bpp = pf.bytes_per_pixel();
    let tiles_x = u32::from(r.width).div_ceil(16);
    let tiles_y = u32::from(r.height).div_ceil(16);
    let total = tiles_x * tiles_y;
    let mut consumed = 0;
    while st.tile < total {
        let tx = st.tile % tiles_x;
        let ty = st.tile / tiles_x;
        let x = r.x as u32 + tx * 16;
        let y = r.y as u32 + ty * 16;
        let w = (u32::from(r.width) - tx * 16).min(16) as u16;
        let h = (u32::from(r.height) - ty * 16).min(16) as u16;
        let (x, y) = (x.min(u16::MAX as u32) as u16, y.min(u16::MAX as u32) as u16);
        let data = &input[consumed..];
        let Some(mut len) = hextile_tile_len(data, bpp) else {
            break;
        };
        let flags = data[0];
        if flags & 1 != 0 {
            len = 1 + usize::from(w) * usize::from(h) * bpp;
        }
        if data.len() < len {
            break;
        }
        if flags & 1 != 0 {
            let row = usize::from(w) * bpp;
            for i in 0..h {
                let s = 1 + usize::from(i) * row;
                fb.put_row(x, y.saturating_add(i), &data[s..s + row], pf);
            }
        } else {
            let mut p = 1;
            if flags & 2 != 0 {
                st.bg = pf.to_rgba(pf.read_pixel(&data[p..p + bpp]));
                p += bpp;
            }
            fb.fill_rect(Rect::new(x, y, w, h), st.bg);
            if flags & 4 != 0 {
                st.fg = pf.to_rgba(pf.read_pixel(&data[p..p + bpp]));
                p += bpp;
            }
            if flags & 8 != 0 {
                let count = data[p];
                p += 1;
                for _ in 0..count {
                    let colour = if flags & 16 != 0 {
                        let c = pf.to_rgba(pf.read_pixel(&data[p..p + bpp]));
                        p += bpp;
                        c
                    } else {
                        st.fg
                    };
                    let xy = data[p];
                    let wh = data[p + 1];
                    p += 2;
                    let sx = u16::from(xy >> 4);
                    let sy = u16::from(xy & 15);
                    let sw = u16::from(wh >> 4) + 1;
                    let sh = u16::from(wh & 15) + 1;
                    if sx + sw > w || sy + sh > h {
                        return Err(Error::Protocol("hextile subrect fora do tile".into()));
                    }
                    fb.fill_rect(
                        Rect::new(x.saturating_add(sx), y.saturating_add(sy), sw, sh),
                        colour,
                    );
                }
            }
        }
        consumed += len;
        st.tile += 1;
    }
    Ok(Progress {
        consumed,
        done: st.tile >= total,
    })
}

fn decode_zrle(
    r: Rect,
    input: &[u8],
    pf: &PixelFormat,
    fb: &mut Framebuffer,
    state: &mut CodecState,
) -> Result<Progress> {
    if input.len() < 4 {
        return Ok(Progress {
            consumed: 0,
            done: false,
        });
    }
    let len = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    check_limit(
        "zrle compressed length",
        u64::from(len),
        MAX_ZRLE_COMPRESSED,
    )?;
    let len = len as usize;
    if input.len() < 4 + len {
        return Ok(Progress {
            consumed: 0,
            done: false,
        });
    }
    let cpx = pf.cpixel_len();
    let tiles = u64::from(r.width).div_ceil(64) * u64::from(r.height).div_ceil(64);
    // pior caso: subencoding + paleta + 1 byte de indice/run por pixel + cpixel por pixel
    let max_out = tiles * (1 + 128 * cpx as u64) + r.area() * (cpx as u64 + 1) + 1024;
    let data = inflate(&mut state.zrle, &input[4..4 + len], max_out)?;
    parse_zrle(r, &data, pf, cpx, fb)?;
    Ok(Progress {
        consumed: 4 + len,
        done: true,
    })
}

fn inflate(z: &mut Decompress, mut src: &[u8], max_out: u64) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(src.len().saturating_mul(4).min(1 << 20));
    loop {
        if out.len() == out.capacity() {
            out.reserve(64 * 1024);
        }
        let before_in = z.total_in();
        let before_out = z.total_out();
        let status = z
            .decompress_vec(src, &mut out, FlushDecompress::Sync)
            .map_err(|e| Error::Protocol(format!("zlib: {e}")))?;
        let used = (z.total_in() - before_in) as usize;
        src = &src[used..];
        check_limit("zrle decompressed", out.len() as u64, max_out)?;
        let produced = z.total_out() - before_out;
        match status {
            Status::StreamEnd => break,
            _ if src.is_empty() && out.len() < out.capacity() => break,
            _ if used == 0 && produced == 0 && out.len() < out.capacity() => {
                return Err(Error::Protocol("zlib sem progresso".into()))
            }
            _ => {}
        }
    }
    Ok(out)
}

struct Reader<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .p
            .checked_add(n)
            .filter(|&e| e <= self.d.len())
            .ok_or_else(|| Error::Protocol("zrle truncado".into()))?;
        let s = &self.d[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn run_len(&mut self) -> Result<usize> {
        let mut n = 1usize;
        loop {
            let b = self.u8()?;
            n += usize::from(b);
            if b != 255 {
                return Ok(n);
            }
        }
    }
}

fn parse_zrle(
    r: Rect,
    data: &[u8],
    pf: &PixelFormat,
    cpx: usize,
    fb: &mut Framebuffer,
) -> Result<()> {
    let mut rd = Reader { d: data, p: 0 };
    let mut buf: Vec<[u8; 4]> = Vec::with_capacity(64 * 64);
    let mut ty = 0u32;
    while ty < u32::from(r.height) {
        let th = (u32::from(r.height) - ty).min(64) as usize;
        let mut tx = 0u32;
        while tx < u32::from(r.width) {
            let tw = (u32::from(r.width) - tx).min(64) as usize;
            let n = tw * th;
            buf.clear();
            let sub = rd.u8()?;
            let cp = |rd: &mut Reader| -> Result<[u8; 4]> {
                Ok(pf.to_rgba(pf.read_cpixel(rd.take(cpx)?)))
            };
            match sub {
                0 => {
                    for _ in 0..n {
                        buf.push(cp(&mut rd)?);
                    }
                }
                1 => {
                    let c = cp(&mut rd)?;
                    buf.resize(n, c);
                }
                2..=16 => {
                    let size = usize::from(sub);
                    let mut pal = Vec::with_capacity(size);
                    for _ in 0..size {
                        pal.push(cp(&mut rd)?);
                    }
                    let bits = match size {
                        2 => 1,
                        3..=4 => 2,
                        _ => 4,
                    };
                    for _ in 0..th {
                        let mut byte = 0u8;
                        let mut left = 0;
                        for _ in 0..tw {
                            if left == 0 {
                                byte = rd.u8()?;
                                left = 8;
                            }
                            left -= bits;
                            let idx = usize::from((byte >> left) & ((1 << bits) - 1));
                            buf.push(
                                *pal.get(idx)
                                    .ok_or_else(|| Error::Protocol("indice de paleta".into()))?,
                            );
                        }
                    }
                }
                128 => {
                    while buf.len() < n {
                        let c = cp(&mut rd)?;
                        let len = rd.run_len()?;
                        if buf.len() + len > n {
                            return Err(Error::Protocol("zrle run excede tile".into()));
                        }
                        buf.resize(buf.len() + len, c);
                    }
                }
                130..=255 => {
                    let size = usize::from(sub - 128);
                    let mut pal = Vec::with_capacity(size);
                    for _ in 0..size {
                        pal.push(cp(&mut rd)?);
                    }
                    while buf.len() < n {
                        let b = rd.u8()?;
                        let c = *pal
                            .get(usize::from(b & 127))
                            .ok_or_else(|| Error::Protocol("indice de paleta".into()))?;
                        let len = if b & 128 != 0 { rd.run_len()? } else { 1 };
                        if buf.len() + len > n {
                            return Err(Error::Protocol("zrle run excede tile".into()));
                        }
                        buf.resize(buf.len() + len, c);
                    }
                }
                other => return Err(Error::Protocol(format!("zrle subencoding {other}"))),
            }
            let x0 = (u32::from(r.x) + tx).min(u32::from(u16::MAX)) as u16;
            let y0 = u32::from(r.y) + ty;
            for (i, row) in buf.chunks_exact(tw).enumerate() {
                let y = (y0 + i as u32).min(u32::from(u16::MAX)) as u16;
                fb.put_rgba_row(x0, y, row);
            }
            tx += 64;
        }
        ty += 64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use openvnc_framebuffer::DEFAULT_MAX_BYTES;
    use std::io::Write;

    const PF: PixelFormat = PixelFormat::RGBX8888;

    fn fb(w: u16, h: u16) -> Framebuffer {
        Framebuffer::new(w, h, DEFAULT_MAX_BYTES).unwrap()
    }

    /// Alimenta o decoder byte a byte, simulando rede fragmentada.
    fn feed_bytewise(dec: &mut RectDecoder, data: &[u8], f: &mut Framebuffer, st: &mut CodecState) {
        let mut buf = Vec::new();
        for &b in data {
            buf.push(b);
            let p = dec.decode(&buf, &PF, f, st).unwrap();
            buf.drain(..p.consumed);
            if p.done {
                assert!(buf.is_empty());
                return;
            }
        }
        panic!("decoder nao terminou");
    }

    #[test]
    fn raw_bytewise() {
        let mut f = fb(2, 2);
        let mut st = CodecState::default();
        let mut d = RectDecoder::new(Rect::new(0, 0, 2, 2), encoding::RAW).unwrap();
        let data: Vec<u8> = (0..4).flat_map(|i| [i * 10, 0, 0, 0]).collect();
        feed_bytewise(&mut d, &data, &mut f, &mut st);
        assert_eq!(f.pixel(1, 1), Some([30, 0, 0, 255]));
    }

    #[test]
    fn unknown_encoding() {
        assert!(RectDecoder::new(Rect::default(), 99).is_err());
    }

    #[test]
    fn hextile_bg_and_subrects() {
        let mut f = fb(20, 16);
        let mut st = CodecState::default();
        let mut d = RectDecoder::new(Rect::new(0, 0, 20, 16), encoding::HEXTILE).unwrap();
        let mut data = vec![2 | 4 | 8, 1, 1, 1, 0, 9, 9, 9, 0, 1, 0x11, 0x00];
        // tile 2 (4x16): reutiliza bg, sem subrects
        data.push(0);
        feed_bytewise(&mut d, &data, &mut f, &mut st);
        assert_eq!(f.pixel(0, 0), Some([1, 1, 1, 255]));
        assert_eq!(f.pixel(1, 1), Some([9, 9, 9, 255]));
        assert_eq!(f.pixel(19, 15), Some([1, 1, 1, 255]));
    }

    #[test]
    fn hextile_bad_subrect() {
        let mut f = fb(4, 4);
        let mut st = CodecState::default();
        let mut d = RectDecoder::new(Rect::new(0, 0, 4, 4), encoding::HEXTILE).unwrap();
        let data = [2 | 4 | 8, 1, 1, 1, 0, 9, 9, 9, 0, 1, 0x33, 0x33];
        assert!(d.decode(&data, &PF, &mut f, &mut st).is_err());
    }

    fn zlib(enc: &mut ZlibEncoder<Vec<u8>>, raw: &[u8]) -> Vec<u8> {
        let start = enc.get_ref().len();
        enc.write_all(raw).unwrap();
        enc.flush().unwrap();
        let out = enc.get_ref()[start..].to_vec();
        let mut v = (out.len() as u32).to_be_bytes().to_vec();
        v.extend(out);
        v
    }

    #[test]
    fn zrle_solid_and_rle_persistent_stream() {
        let mut f = fb(70, 2);
        let mut st = CodecState::default();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        // dois tiles: solido vermelho (64x2) e plain RLE (6x2) verde
        let raw = [1, 255, 0, 0, 128, 0, 255, 0, 11];
        let msg = zlib(&mut enc, &raw);
        let mut d = RectDecoder::new(Rect::new(0, 0, 70, 2), encoding::ZRLE).unwrap();
        feed_bytewise(&mut d, &msg, &mut f, &mut st);
        assert_eq!(f.pixel(63, 1), Some([255, 0, 0, 255]));
        assert_eq!(f.pixel(69, 1), Some([0, 255, 0, 255]));
        // segundo retangulo no mesmo stream: paleta 2 cores, 1 bit
        let raw2 = [2, 0, 0, 255, 255, 255, 255, 0b0100_0000, 0b1000_0000];
        let msg2 = zlib(&mut enc, &raw2);
        let mut d = RectDecoder::new(Rect::new(0, 0, 2, 2), encoding::ZRLE).unwrap();
        feed_bytewise(&mut d, &msg2, &mut f, &mut st);
        assert_eq!(f.pixel(0, 0), Some([0, 0, 255, 255]));
        assert_eq!(f.pixel(1, 0), Some([255, 255, 255, 255]));
        assert_eq!(f.pixel(0, 1), Some([255, 255, 255, 255]));
    }

    #[test]
    fn zrle_bomb_rejected() {
        let mut f = fb(1, 1);
        let mut st = CodecState::default();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        let msg = zlib(&mut enc, &vec![0u8; 1 << 20]);
        let mut d = RectDecoder::new(Rect::new(0, 0, 1, 1), encoding::ZRLE).unwrap();
        assert!(d.decode(&msg, &PF, &mut f, &mut st).is_err());
    }

    #[test]
    fn zrle_truncated_tile() {
        let mut f = fb(4, 4);
        let mut st = CodecState::default();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        let msg = zlib(&mut enc, &[0, 1, 2]);
        let mut d = RectDecoder::new(Rect::new(0, 0, 4, 4), encoding::ZRLE).unwrap();
        assert!(d.decode(&msg, &PF, &mut f, &mut st).is_err());
    }

    #[test]
    fn copyrect() {
        let mut f = fb(4, 1);
        let mut st = CodecState::default();
        f.fill_rect(Rect::new(0, 0, 1, 1), [5, 5, 5, 255]);
        let mut d = RectDecoder::new(Rect::new(3, 0, 1, 1), encoding::COPY_RECT).unwrap();
        feed_bytewise(&mut d, &[0, 0, 0, 0], &mut f, &mut st);
        assert_eq!(f.pixel(3, 0), Some([5, 5, 5, 255]));
    }
}
