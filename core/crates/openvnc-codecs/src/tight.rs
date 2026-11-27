//! Decoder Tight (encoding 7), com JPEG.
//!
//! O subtipo JPEG e decodificado com `jpeg-decoder` (Rust puro), com
//! limite de tamanho comprimido e checagem das dimensoes contra o retangulo.
//! Suporta fill, basic (filtros copy, palette e gradient) e os 4 streams
//! zlib com reset pelo byte de controle.

use flate2::Decompress;
use openvnc_core::{check_limit, Error, PixelFormat, Rect, Result};
use openvnc_framebuffer::Framebuffer;

use crate::{inflate, Progress};

/// Limite de bytes comprimidos por retangulo Tight.
pub const MAX_TIGHT_COMPRESSED: u64 = 64 * 1024 * 1024;

/// Os 4 streams zlib persistentes do Tight.
pub struct TightState {
    z: [Decompress; 4],
}

impl Default for TightState {
    fn default() -> Self {
        TightState {
            z: std::array::from_fn(|_| Decompress::new(true)),
        }
    }
}

fn wait() -> Result<Progress> {
    Ok(Progress {
        consumed: 0,
        done: false,
    })
}

/// Comprimento compacto (1 a 3 bytes); `None` se faltam bytes.
fn compact_len(b: &[u8]) -> Option<(usize, usize)> {
    let mut n = 0usize;
    for i in 0..3 {
        let v = *b.get(i)?;
        if i == 2 {
            n |= usize::from(v) << 14;
            return Some((n, 3));
        }
        n |= usize::from(v & 0x7f) << (7 * i);
        if v & 0x80 == 0 {
            return Some((n, i + 1));
        }
    }
    unreachable!()
}

/// Maior bloco JPEG aceito.
const MAX_JPEG: usize = 16 * 1024 * 1024;

fn decode_jpeg(r: Rect, data: &[u8], fb: &mut Framebuffer) -> Result<()> {
    let mut d = jpeg_decoder::Decoder::new(data);
    d.read_info()
        .map_err(|e| Error::Protocol(format!("tight jpeg: {e}")))?;
    let info = d
        .info()
        .ok_or_else(|| Error::Protocol("tight jpeg: sem info".into()))?;
    if info.width != r.width || info.height != r.height {
        return Err(Error::Protocol(
            "tight jpeg: dimensoes divergem do retangulo".into(),
        ));
    }
    let pix = d
        .decode()
        .map_err(|e| Error::Protocol(format!("tight jpeg: {e}")))?;
    let w = usize::from(r.width);
    let rgba: Vec<[u8; 4]> = match info.pixel_format {
        jpeg_decoder::PixelFormat::RGB24 => pix
            .chunks_exact(3)
            .map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        jpeg_decoder::PixelFormat::L8 => pix.iter().map(|&v| [v, v, v, 255]).collect(),
        _ => {
            return Err(Error::Protocol(
                "tight jpeg: formato de pixel nao suportado".into(),
            ))
        }
    };
    if rgba.len() != w * usize::from(r.height) {
        return Err(Error::Protocol("tight jpeg: tamanho incorreto".into()));
    }
    for (i, row) in rgba.chunks_exact(w.max(1)).enumerate() {
        fb.put_rgba_row(r.x, r.y.saturating_add(i as u16), row);
    }
    Ok(())
}

/// Decodifica um retangulo Tight inteiro (espera ate ter todos os bytes).
pub(crate) fn decode_tight(
    r: Rect,
    input: &[u8],
    pf: &PixelFormat,
    fb: &mut Framebuffer,
    st: &mut TightState,
) -> Result<Progress> {
    let Some(&ctl) = input.first() else {
        return wait();
    };
    let cpx = pf.cpixel_len();
    let px = |b: &[u8]| pf.to_rgba(pf.read_cpixel(b));
    let kind = ctl >> 4;
    if kind == 0x8 {
        // fill
        if input.len() < 1 + cpx {
            return wait();
        }
        reset(st, ctl);
        fb.fill_rect(r, px(&input[1..1 + cpx]));
        return Ok(Progress {
            consumed: 1 + cpx,
            done: true,
        });
    }
    if kind == 0x9 {
        let Some((n, l)) = compact_len(&input[1..]) else {
            return wait();
        };
        openvnc_core::check_limit("tight jpeg", n as u64, MAX_JPEG as u64)?;
        if input.len() < 1 + l + n {
            return wait();
        }
        reset(st, ctl);
        decode_jpeg(r, &input[1 + l..1 + l + n], fb)?;
        return Ok(Progress {
            consumed: 1 + l + n,
            done: true,
        });
    }
    if kind > 0x9 {
        return Err(Error::Protocol(format!(
            "tight: controle invalido {ctl:#x}"
        )));
    }
    let stream = usize::from(kind & 3);
    let mut p = 1;
    let filter = if kind & 4 != 0 {
        let Some(&f) = input.get(p) else {
            return wait();
        };
        p += 1;
        f
    } else {
        0
    };
    let mut palette: Vec<[u8; 4]> = Vec::new();
    let (w, h) = (usize::from(r.width), usize::from(r.height));
    let raw_len = match filter {
        0 | 2 => w * h * cpx,
        1 => {
            let Some(&n) = input.get(p) else {
                return wait();
            };
            let n = usize::from(n) + 1;
            p += 1;
            if n < 2 {
                return Err(Error::Protocol("tight: paleta com 1 cor".into()));
            }
            if input.len() < p + n * cpx {
                return wait();
            }
            palette.extend(input[p..p + n * cpx].chunks_exact(cpx).map(px));
            p += n * cpx;
            if n == 2 {
                w.div_ceil(8) * h
            } else {
                w * h
            }
        }
        f => return Err(Error::Protocol(format!("tight: filtro desconhecido {f}"))),
    };
    if filter == 2 && cpx != 3 && pf.bits_per_pixel != 16 {
        return Err(Error::Protocol(
            "tight: gradient so com pixel de 16 ou 24 bits".into(),
        ));
    }
    let data: std::borrow::Cow<[u8]> = if raw_len < 12 {
        if input.len() < p + raw_len {
            return wait();
        }
        let d = &input[p..p + raw_len];
        p += raw_len;
        d.into()
    } else {
        let Some((len, n)) = compact_len(&input[p..]) else {
            return wait();
        };
        check_limit("tight compressed length", len as u64, MAX_TIGHT_COMPRESSED)?;
        if input.len() < p + n + len {
            return wait();
        }
        reset(st, ctl);
        let src = &input[p + n..p + n + len];
        p += n + len;
        let out = inflate(&mut st.z[stream], src, raw_len as u64)?;
        if out.len() != raw_len {
            return Err(Error::Protocol(format!(
                "tight: esperava {raw_len} bytes, veio {}",
                out.len()
            )));
        }
        out.into()
    };
    if raw_len < 12 {
        reset(st, ctl);
    }
    if w == 0 || h == 0 {
        // Retangulo vazio: os bytes ja foram consumidos, nada a desenhar
        // (evita `chunks_exact(0)`, que entra em panico).
        return Ok(Progress {
            consumed: p,
            done: true,
        });
    }
    let mut row: Vec<[u8; 4]> = Vec::with_capacity(w);
    match filter {
        0 => {
            for (y, line) in data.chunks_exact(w * cpx).enumerate() {
                row.clear();
                row.extend(line.chunks_exact(cpx).map(px));
                fb.put_rgba_row(r.x, r.y.saturating_add(y as u16), &row);
            }
        }
        1 => {
            let get = |i: u8| {
                palette
                    .get(usize::from(i))
                    .copied()
                    .ok_or_else(|| Error::Protocol("tight: indice fora da paleta".into()))
            };
            if palette.len() == 2 {
                for (y, line) in data.chunks_exact(w.div_ceil(8)).enumerate() {
                    row.clear();
                    for x in 0..w {
                        row.push(get((line[x / 8] >> (7 - x % 8)) & 1)?);
                    }
                    fb.put_rgba_row(r.x, r.y.saturating_add(y as u16), &row);
                }
            } else {
                for (y, line) in data.chunks_exact(w).enumerate() {
                    row.clear();
                    for &i in line {
                        row.push(get(i)?);
                    }
                    fb.put_rgba_row(r.x, r.y.saturating_add(y as u16), &row);
                }
            }
        }
        _ => gradient(r, &data, pf, cpx, fb),
    }
    Ok(Progress {
        consumed: p,
        done: true,
    })
}

fn reset(st: &mut TightState, ctl: u8) {
    for (i, z) in st.z.iter_mut().enumerate() {
        if ctl & (1 << i) != 0 {
            z.reset(true);
        }
    }
}

/// Filtro gradient: cada canal e previsto por `esq + cima - diagonal`
/// (limitado a `[0, max]`) e o dado e somado modulo `max + 1`.
fn gradient(r: Rect, data: &[u8], pf: &PixelFormat, cpx: usize, fb: &mut Framebuffer) {
    let (w, h) = (usize::from(r.width), usize::from(r.height));
    let max = [pf.red_max, pf.green_max, pf.blue_max].map(i32::from);
    let shift = [pf.red_shift, pf.green_shift, pf.blue_shift];
    let mut prev = vec![[0i32; 3]; w];
    let mut cur = vec![[0i32; 3]; w];
    let mut row: Vec<[u8; 4]> = Vec::with_capacity(w);
    for y in 0..h {
        row.clear();
        for x in 0..w {
            let raw = pf.read_cpixel(&data[(y * w + x) * cpx..]);
            let mut c = [0i32; 3];
            for k in 0..3 {
                let left = if x > 0 { cur[x - 1][k] } else { 0 };
                let up = prev[x][k];
                let diag = if x > 0 { prev[x - 1][k] } else { 0 };
                let pred = (left + up - diag).clamp(0, max[k]);
                let d = ((raw >> shift[k]) as i32) & max[k];
                c[k] = (pred + d) & max[k];
            }
            cur[x] = c;
            let p =
                (c[0] as u32) << shift[0] | (c[1] as u32) << shift[1] | (c[2] as u32) << shift[2];
            row.push(pf.to_rgba(p));
        }
        fb.put_rgba_row(r.x, r.y.saturating_add(y as u16), &row);
        std::mem::swap(&mut prev, &mut cur);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encoding, CodecState, RectDecoder};
    use flate2::{Compress, Compression, FlushCompress};
    use openvnc_framebuffer::DEFAULT_MAX_BYTES;

    const PF: PixelFormat = PixelFormat::RGBX8888;

    fn fb() -> Framebuffer {
        Framebuffer::new(32, 32, DEFAULT_MAX_BYTES).unwrap()
    }

    fn zlib(z: &mut Compress, d: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(d.len() + 64);
        z.compress_vec(d, &mut out, FlushCompress::Sync).unwrap();
        out
    }

    fn compact(n: usize, out: &mut Vec<u8>) {
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x4000 {
            out.extend([(n & 0x7f) as u8 | 0x80, (n >> 7) as u8]);
        } else {
            out.extend([
                (n & 0x7f) as u8 | 0x80,
                ((n >> 7) & 0x7f) as u8 | 0x80,
                (n >> 14) as u8,
            ]);
        }
    }

    fn run(r: Rect, bytes: &[u8], f: &mut Framebuffer, st: &mut CodecState) {
        let mut d = RectDecoder::new(r, encoding::TIGHT).unwrap();
        // incompleto: nao consome
        if bytes.len() > 1 {
            let p = d.decode(&bytes[..bytes.len() - 1], &PF, f, st).unwrap();
            assert!(!p.done);
        }
        let p = d.decode(bytes, &PF, f, st).unwrap();
        assert_eq!(
            p,
            Progress {
                consumed: bytes.len(),
                done: true
            }
        );
    }

    #[test]
    fn compact_lengths() {
        for n in [0, 5, 127, 128, 300, 16383, 16384, 4_000_000] {
            let mut v = Vec::new();
            compact(n, &mut v);
            assert_eq!(compact_len(&v), Some((n, v.len())), "{n}");
        }
        assert_eq!(compact_len(&[0x80]), None);
    }

    #[test]
    fn retangulo_vazio_nao_entra_em_panico() {
        // copy (0x00), paleta de 2 cores e paleta de 3 cores (0x40, filtro 1)
        for (r, bytes) in [
            (Rect::new(0, 0, 0, 5), vec![0x00]),
            (Rect::new(0, 0, 5, 0), vec![0x00]),
            (Rect::new(0, 0, 0, 5), vec![0x40, 1, 1, 1, 1, 1, 2, 2, 2]),
            (
                Rect::new(0, 0, 0, 5),
                vec![0x40, 1, 2, 1, 1, 1, 2, 2, 2, 3, 3, 3],
            ),
        ] {
            let mut f = fb();
            let mut st = CodecState::default();
            let mut d = RectDecoder::new(r, encoding::TIGHT).unwrap();
            let p = d.decode(&bytes, &PF, &mut f, &mut st).unwrap();
            assert!(p.done, "{r:?}");
            assert_eq!(p.consumed, bytes.len(), "{r:?}");
        }
    }

    #[test]
    fn fill() {
        let mut f = fb();
        let mut st = CodecState::default();
        run(Rect::new(2, 3, 10, 5), &[0x80, 10, 20, 30], &mut f, &mut st);
        assert_eq!(f.pixel(2, 3), Some([10, 20, 30, 255]));
        assert_eq!(f.pixel(11, 7), Some([10, 20, 30, 255]));
        assert_eq!(f.pixel(12, 7), Some([0, 0, 0, 255]));
    }

    #[test]
    fn basic_copy_small_and_zlib_two_rects() {
        let mut f = fb();
        let mut st = CodecState::default();
        // 3 pixels = 9 bytes < 12: sem zlib
        run(
            Rect::new(0, 0, 3, 1),
            &[0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            &mut f,
            &mut st,
        );
        assert_eq!(f.pixel(2, 0), Some([7, 8, 9, 255]));
        // 2 retangulos no mesmo stream 1 (o segundo depende do dicionario)
        let mut z = Compress::new(Compression::default(), true);
        let px: Vec<u8> = (0..16 * 16 * 3).map(|i| (i % 251) as u8).collect();
        for (k, y) in [(0, 0u16), (1, 16)] {
            let c = zlib(&mut z, &px);
            let mut m = vec![0x10 | if k == 0 { 0x02 } else { 0 }];
            compact(c.len(), &mut m);
            m.extend(c);
            run(Rect::new(8, y, 16, 16), &m[..], &mut f, &mut st);
        }
        let want = |i: usize| [px[i * 3], px[i * 3 + 1], px[i * 3 + 2], 255];
        assert_eq!(f.pixel(8, 16), Some(want(0)));
        assert_eq!(f.pixel(23, 31), Some(want(15 * 16 + 15)));
    }

    #[test]
    fn palette_mono_and_multi() {
        let mut f = fb();
        let mut st = CodecState::default();
        // 2 cores, 10x2 -> 2 bytes por linha = 4 bytes (< 12)
        let mut m = vec![0x40, 1, 1, 255, 0, 0, 0, 0, 255];
        m.extend([0b1010_0000, 0b0100_0000, 0b0000_0000, 0b1100_0000]);
        run(Rect::new(0, 0, 10, 2), &m, &mut f, &mut st);
        assert_eq!(f.pixel(0, 0), Some([0, 0, 255, 255]));
        assert_eq!(f.pixel(1, 0), Some([255, 0, 0, 255]));
        assert_eq!(f.pixel(9, 0), Some([0, 0, 255, 255]));
        assert_eq!(f.pixel(8, 1), Some([0, 0, 255, 255]));
        assert_eq!(f.pixel(9, 1), Some([0, 0, 255, 255]));
        assert_eq!(f.pixel(0, 1), Some([255, 0, 0, 255]));
        // 3 cores, 4x4 = 16 bytes: zlib no stream 2
        let mut z = Compress::new(Compression::default(), true);
        let idx: Vec<u8> = (0..16).map(|i| i % 3).collect();
        let c = zlib(&mut z, &idx);
        let mut m = vec![0x60, 1, 2, 10, 10, 10, 20, 20, 20, 30, 30, 30];
        compact(c.len(), &mut m);
        m.extend(c);
        run(Rect::new(16, 16, 4, 4), &m, &mut f, &mut st);
        assert_eq!(f.pixel(16, 16), Some([10, 10, 10, 255]));
        assert_eq!(f.pixel(18, 16), Some([30, 30, 30, 255]));
        assert_eq!(f.pixel(19, 19), Some([10, 10, 10, 255])); // 15 % 3 == 0
    }

    #[test]
    fn gradient_filter() {
        // imagem alvo e o residuo calculado como o encoder faria
        let (w, h) = (6usize, 5usize);
        let img: Vec<[i32; 3]> = (0..w * h)
            .map(|i| [(i * 7 % 256) as i32, (i * 13 % 256) as i32, 200])
            .collect();
        let at = |x: isize, y: isize| {
            if x < 0 || y < 0 {
                [0; 3]
            } else {
                img[y as usize * w + x as usize]
            }
        };
        let mut res = Vec::new();
        for y in 0..h as isize {
            for x in 0..w as isize {
                for k in 0..3 {
                    let pred =
                        (at(x - 1, y)[k] + at(x, y - 1)[k] - at(x - 1, y - 1)[k]).clamp(0, 255);
                    res.push(((at(x, y)[k] - pred) & 255) as u8);
                }
            }
        }
        let mut z = Compress::new(Compression::default(), true);
        let c = zlib(&mut z, &res);
        let mut m = vec![0x40, 2];
        compact(c.len(), &mut m);
        m.extend(c);
        let mut f = fb();
        let mut st = CodecState::default();
        run(Rect::new(1, 1, w as u16, h as u16), &m, &mut f, &mut st);
        for y in 0..h {
            for x in 0..w {
                let p = img[y * w + x];
                assert_eq!(
                    f.pixel(1 + x as u16, 1 + y as u16),
                    Some([p[0] as u8, p[1] as u8, p[2] as u8, 255])
                );
            }
        }
    }

    #[test]
    fn jpeg_and_garbage_rejected() {
        let mut f = fb();
        let mut st = CodecState::default();
        for ctl in [0xa0u8, 0xff] {
            let mut d = RectDecoder::new(Rect::new(0, 0, 4, 4), encoding::TIGHT).unwrap();
            assert!(d.decode(&[ctl, 0, 0, 0, 0], &PF, &mut f, &mut st).is_err());
        }
        // JPEG corrompido
        let mut d = RectDecoder::new(Rect::new(0, 0, 4, 4), encoding::TIGHT).unwrap();
        assert!(d
            .decode(&[0x90, 4, 1, 2, 3, 4], &PF, &mut f, &mut st)
            .is_err());
        // filtro desconhecido
        let mut d = RectDecoder::new(Rect::new(0, 0, 4, 4), encoding::TIGHT).unwrap();
        assert!(d.decode(&[0x40, 7, 0, 0], &PF, &mut f, &mut st).is_err());
        // indice fora da paleta (3 cores, indice 5)
        let mut d = RectDecoder::new(Rect::new(0, 0, 2, 1), encoding::TIGHT).unwrap();
        let m = [0x40, 1, 2, 1, 1, 1, 2, 2, 2, 3, 3, 3, 0, 5];
        assert!(d.decode(&m, &PF, &mut f, &mut st).is_err());
    }
}
