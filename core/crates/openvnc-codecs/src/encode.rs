//! Encoders RFB para o lado servidor: Raw, CopyRect, Hextile e ZRLE.
//!
//! O framebuffer de origem e sempre RGBA8 ([`Framebuffer`]); os pixels
//! sao convertidos para o [`PixelFormat`] pedido pelo cliente.

use flate2::{Compress, Compression, FlushCompress};
use openvnc_core::{Error, PixelFormat, Rect, Result};
use openvnc_framebuffer::Framebuffer;

use crate::encoding;

/// Estado de codificacao por conexao (o stream zlib do ZRLE e unico).
pub struct EncoderState {
    zrle: Compress,
    scratch: Vec<u8>,
}

impl Default for EncoderState {
    fn default() -> Self {
        EncoderState {
            zrle: Compress::new(Compression::fast(), true),
            scratch: Vec::new(),
        }
    }
}

impl std::fmt::Debug for EncoderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncoderState")
    }
}

/// Escreve o cabecalho de retangulo (x, y, w, h, encoding).
pub fn write_rect_header(r: Rect, enc: i32, out: &mut Vec<u8>) {
    for v in [r.x, r.y, r.width, r.height] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&enc.to_be_bytes());
}

/// Retangulo CopyRect completo (cabecalho + origem).
pub fn encode_copy_rect(dst: Rect, src_x: u16, src_y: u16, out: &mut Vec<u8>) {
    write_rect_header(dst, encoding::COPY_RECT, out);
    out.extend_from_slice(&src_x.to_be_bytes());
    out.extend_from_slice(&src_y.to_be_bytes());
}

fn px(fb: &Framebuffer, x: u16, y: u16) -> [u8; 4] {
    let i = usize::from(y) * fb.stride() + usize::from(x) * 4;
    let d = fb.data();
    [d[i], d[i + 1], d[i + 2], 255]
}

/// Pixels RGBA de uma area (que deve estar dentro do framebuffer).
fn area(fb: &Framebuffer, r: Rect, buf: &mut Vec<[u8; 4]>) {
    buf.clear();
    for y in r.y..r.y + r.height {
        for x in r.x..r.x + r.width {
            buf.push(px(fb, x, y));
        }
    }
}

impl EncoderState {
    /// Codifica `r` (cabecalho incluido) com `enc` no formato `pf`.
    /// `r` precisa estar dentro do framebuffer.
    pub fn encode_rect(
        &mut self,
        fb: &Framebuffer,
        r: Rect,
        enc: i32,
        pf: &PixelFormat,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if r.clip_to(fb.width(), fb.height()) != r {
            return Err(Error::Protocol("retangulo fora do framebuffer".into()));
        }
        write_rect_header(r, enc, out);
        match enc {
            encoding::RAW => encode_raw(fb, r, pf, out),
            encoding::HEXTILE => encode_hextile(fb, r, pf, out),
            encoding::ZRLE => self.encode_zrle(fb, r, pf, out)?,
            other => return Err(Error::Unsupported(format!("encoder {other}"))),
        }
        Ok(())
    }

    fn encode_zrle(
        &mut self,
        fb: &Framebuffer,
        r: Rect,
        pf: &PixelFormat,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let raw = &mut self.scratch;
        raw.clear();
        let mut tile: Vec<[u8; 4]> = Vec::with_capacity(64 * 64);
        let mut pal: Vec<[u8; 4]> = Vec::with_capacity(16);
        let mut ty = 0u32;
        while ty < u32::from(r.height) {
            let th = (u32::from(r.height) - ty).min(64) as u16;
            let mut tx = 0u32;
            while tx < u32::from(r.width) {
                let tw = (u32::from(r.width) - tx).min(64) as u16;
                let t = Rect::new(r.x + tx as u16, r.y + ty as u16, tw, th);
                area(fb, t, &mut tile);
                zrle_tile(&tile, tw, pf, &mut pal, raw);
                tx += 64;
            }
            ty += 64;
        }
        let start = out.len();
        out.extend_from_slice(&[0; 4]);
        let mut input: &[u8] = raw;
        loop {
            out.reserve(input.len() / 2 + 1024);
            let before = self.zrle.total_in();
            self.zrle
                .compress_vec(input, out, FlushCompress::Sync)
                .map_err(|e| Error::Protocol(format!("zlib: {e}")))?;
            let used = (self.zrle.total_in() - before) as usize;
            input = &input[used..];
            // terminado quando consumiu tudo e o flush coube no buffer
            if input.is_empty() && out.len() < out.capacity() {
                break;
            }
        }
        let len = (out.len() - start - 4) as u32;
        out[start..start + 4].copy_from_slice(&len.to_be_bytes());
        Ok(())
    }
}

fn encode_raw(fb: &Framebuffer, r: Rect, pf: &PixelFormat, out: &mut Vec<u8>) {
    out.reserve(r.area() as usize * pf.bytes_per_pixel());
    for y in r.y..r.y + r.height {
        for x in r.x..r.x + r.width {
            pf.write_pixel(pf.from_rgba(px(fb, x, y)), out);
        }
    }
}

/// Paleta de ate `max` cores; `false` se houver mais.
fn palette(pixels: &[[u8; 4]], max: usize, pal: &mut Vec<[u8; 4]>) -> bool {
    pal.clear();
    let mut last = None;
    for p in pixels {
        if last == Some(*p) {
            continue;
        }
        last = Some(*p);
        if !pal.contains(p) {
            if pal.len() == max {
                return false;
            }
            pal.push(*p);
        }
    }
    true
}

fn zrle_tile(
    tile: &[[u8; 4]],
    tw: u16,
    pf: &PixelFormat,
    pal: &mut Vec<[u8; 4]>,
    out: &mut Vec<u8>,
) {
    let cp = |c: [u8; 4], out: &mut Vec<u8>| pf.write_cpixel(pf.from_rgba(c), out);
    if palette(tile, 16, pal) {
        if pal.len() == 1 {
            out.push(1);
            cp(pal[0], out);
            return;
        }
        out.push(pal.len() as u8);
        for c in pal.iter() {
            cp(*c, out);
        }
        let bits = match pal.len() {
            2 => 1,
            3..=4 => 2,
            _ => 4,
        };
        for row in tile.chunks_exact(usize::from(tw)) {
            let mut byte = 0u8;
            let mut used = 0;
            for p in row {
                let idx = pal.iter().position(|c| c == p).unwrap_or(0) as u8;
                byte = (byte << bits) | idx;
                used += bits;
                if used == 8 {
                    out.push(byte);
                    byte = 0;
                    used = 0;
                }
            }
            if used > 0 {
                out.push(byte << (8 - used));
            }
        }
        return;
    }
    // plain RLE quando compensa (muitas sequencias repetidas), senao raw
    let runs = 1 + tile.windows(2).filter(|w| w[0] != w[1]).count();
    if runs * 2 < tile.len() {
        out.push(128);
        let mut i = 0;
        while i < tile.len() {
            let c = tile[i];
            let mut n = 1;
            while i + n < tile.len() && tile[i + n] == c {
                n += 1;
            }
            cp(c, out);
            let mut rest = n - 1;
            while rest >= 255 {
                out.push(255);
                rest -= 255;
            }
            out.push(rest as u8);
            i += n;
        }
    } else {
        out.push(0);
        for c in tile {
            cp(*c, out);
        }
    }
}

mod hextile_flags {
    pub const RAW: u8 = 1;
    pub const BG: u8 = 2;
    pub const FG: u8 = 4;
    pub const ANY_SUBRECTS: u8 = 8;
    pub const COLOURED: u8 = 16;
}

/// Sub-retangulos (x, y, w, h, cor) cobrindo os pixels != `bg`.
/// Junta sequencias horizontais e as estende para baixo quando iguais.
fn subrects(tile: &[[u8; 4]], tw: usize, th: usize, bg: [u8; 4]) -> Vec<(u8, u8, u8, u8, [u8; 4])> {
    let mut done = vec![false; tile.len()];
    let mut v = Vec::new();
    for y in 0..th {
        let mut x = 0;
        while x < tw {
            let i = y * tw + x;
            let c = tile[i];
            if c == bg || done[i] {
                x += 1;
                continue;
            }
            let mut w = 1;
            while x + w < tw && tile[i + w] == c && !done[i + w] {
                w += 1;
            }
            let mut h = 1;
            'down: while y + h < th {
                for k in 0..w {
                    let j = (y + h) * tw + x + k;
                    if tile[j] != c || done[j] {
                        break 'down;
                    }
                }
                h += 1;
            }
            for dy in 0..h {
                for dx in 0..w {
                    done[(y + dy) * tw + x + dx] = true;
                }
            }
            v.push((x as u8, y as u8, w as u8, h as u8, c));
            x += w;
        }
    }
    v
}

fn encode_hextile(fb: &Framebuffer, r: Rect, pf: &PixelFormat, out: &mut Vec<u8>) {
    use hextile_flags::*;
    let bpp = pf.bytes_per_pixel();
    let mut tile: Vec<[u8; 4]> = Vec::with_capacity(256);
    let mut pal = Vec::with_capacity(2);
    let mut last_bg: Option<[u8; 4]> = None;
    let mut last_fg: Option<[u8; 4]> = None;
    let mut ty = 0u32;
    while ty < u32::from(r.height) {
        let th = (u32::from(r.height) - ty).min(16) as u16;
        let mut tx = 0u32;
        while tx < u32::from(r.width) {
            let tw = (u32::from(r.width) - tx).min(16) as u16;
            let t = Rect::new(r.x + tx as u16, r.y + ty as u16, tw, th);
            area(fb, t, &mut tile);
            let (tw_, th_) = (usize::from(tw), usize::from(th));
            let raw_len = 1 + tile.len() * bpp;
            let mono = palette(&tile, 2, &mut pal);
            // bg = cor mais frequente
            let bg = if mono && pal.len() == 2 {
                let n0 = tile.iter().filter(|c| **c == pal[0]).count();
                if n0 * 2 >= tile.len() {
                    pal[0]
                } else {
                    pal[1]
                }
            } else if mono {
                pal[0]
            } else {
                most_common(&tile)
            };
            let subs = subrects(&tile, tw_, th_, bg);
            let mut flags = 0u8;
            let mut body = Vec::new();
            if last_bg != Some(bg) {
                flags |= BG;
                pf.write_pixel(pf.from_rgba(bg), &mut body);
            }
            let mut fg_set = None;
            if !subs.is_empty() {
                flags |= ANY_SUBRECTS;
                let single_fg = subs.iter().all(|s| s.4 == subs[0].4);
                if single_fg {
                    let fg = subs[0].4;
                    if last_fg != Some(fg) {
                        flags |= FG;
                        pf.write_pixel(pf.from_rgba(fg), &mut body);
                    }
                    fg_set = Some(fg);
                } else {
                    flags |= COLOURED;
                }
            }
            let fits = subs.len() <= 255;
            let sub_len = subs.len() * if flags & COLOURED != 0 { bpp + 2 } else { 2 };
            if !fits || 1 + body.len() + 1 + sub_len >= raw_len {
                out.push(RAW);
                for c in &tile {
                    pf.write_pixel(pf.from_rgba(*c), out);
                }
                // bg/fg ficam indefinidos apos um tile raw
                last_bg = None;
                last_fg = None;
            } else {
                out.push(flags);
                out.extend_from_slice(&body);
                if flags & ANY_SUBRECTS != 0 {
                    out.push(subs.len() as u8);
                    for (x, y, w, h, c) in &subs {
                        if flags & COLOURED != 0 {
                            pf.write_pixel(pf.from_rgba(*c), out);
                        }
                        out.push((x << 4) | y);
                        out.push(((w - 1) << 4) | (h - 1));
                    }
                }
                last_bg = Some(bg);
                if let Some(fg) = fg_set {
                    last_fg = Some(fg);
                } else if flags & COLOURED != 0 {
                    // subrects coloridos tornam o fg indefinido
                    last_fg = None;
                }
            }
            tx += 16;
        }
        ty += 16;
    }
}

fn most_common(tile: &[[u8; 4]]) -> [u8; 4] {
    let mut counts: Vec<([u8; 4], usize)> = Vec::new();
    for c in tile {
        if let Some(e) = counts.iter_mut().find(|(k, _)| k == c) {
            e.1 += 1;
        } else if counts.len() < 32 {
            counts.push((*c, 1));
        }
    }
    counts
        .iter()
        .max_by_key(|(_, n)| *n)
        .map(|(c, _)| *c)
        .unwrap_or([0, 0, 0, 255])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CodecState, RectDecoder};
    use openvnc_framebuffer::DEFAULT_MAX_BYTES;

    fn pattern(w: u16, h: u16) -> Framebuffer {
        let mut fb = Framebuffer::new(w, h, DEFAULT_MAX_BYTES).unwrap();
        fb.fill_rect(Rect::new(0, 0, w, h), [10, 20, 30, 255]);
        fb.fill_rect(Rect::new(3, 3, 20, 5), [200, 0, 0, 255]);
        fb.fill_rect(Rect::new(40, 10, 7, 30), [0, 200, 0, 255]);
        for x in 0..w {
            let y = (x * 7) % h;
            fb.fill_rect(Rect::new(x, y, 1, 1), [x as u8, (x * 3) as u8, 99, 255]);
        }
        fb.take_damage();
        fb
    }

    fn roundtrip(enc: i32, pf: PixelFormat) {
        let src = pattern(77, 50);
        let r = Rect::new(0, 0, 77, 50);
        let mut st = EncoderState::default();
        let mut wire = Vec::new();
        st.encode_rect(&src, r, enc, &pf, &mut wire).unwrap();
        // segundo retangulo no mesmo stream (zlib persistente)
        let r2 = Rect::new(5, 5, 30, 30);
        st.encode_rect(&src, r2, enc, &pf, &mut wire).unwrap();
        let mut dst = Framebuffer::new(77, 50, DEFAULT_MAX_BYTES).unwrap();
        let mut cs = CodecState::default();
        let mut p = 0;
        for _ in 0..2 {
            let hdr = &wire[p..p + 12];
            let rr = Rect::new(
                u16::from_be_bytes([hdr[0], hdr[1]]),
                u16::from_be_bytes([hdr[2], hdr[3]]),
                u16::from_be_bytes([hdr[4], hdr[5]]),
                u16::from_be_bytes([hdr[6], hdr[7]]),
            );
            p += 12;
            let mut d = RectDecoder::new(rr, enc).unwrap();
            let pr = d.decode(&wire[p..], &pf, &mut dst, &mut cs).unwrap();
            assert!(pr.done);
            p += pr.consumed;
        }
        assert_eq!(p, wire.len());
        assert_eq!(src.data(), dst.data(), "encoding {enc}");
    }

    const RGB565: PixelFormat = PixelFormat {
        bits_per_pixel: 16,
        depth: 16,
        big_endian: false,
        true_colour: true,
        red_max: 31,
        green_max: 63,
        blue_max: 31,
        red_shift: 11,
        green_shift: 5,
        blue_shift: 0,
    };

    #[test]
    fn raw_hextile_zrle_roundtrip() {
        for enc in [encoding::RAW, encoding::HEXTILE, encoding::ZRLE] {
            roundtrip(enc, PixelFormat::RGBX8888);
        }
    }

    #[test]
    fn rgb565_roundtrip_is_lossy_but_decodes() {
        let src = pattern(20, 20);
        let mut st = EncoderState::default();
        for enc in [encoding::RAW, encoding::HEXTILE, encoding::ZRLE] {
            let mut wire = Vec::new();
            st.encode_rect(&src, Rect::new(0, 0, 20, 20), enc, &RGB565, &mut wire)
                .unwrap();
            let mut dst = Framebuffer::new(20, 20, DEFAULT_MAX_BYTES).unwrap();
            let mut cs = CodecState::default();
            let mut d = RectDecoder::new(Rect::new(0, 0, 20, 20), enc).unwrap();
            if enc == encoding::ZRLE {
                // o stream zlib do encoder e reiniciado por teste
                st = EncoderState::default();
                wire.clear();
                st.encode_rect(&src, Rect::new(0, 0, 20, 20), enc, &RGB565, &mut wire)
                    .unwrap();
            }
            let pr = d.decode(&wire[12..], &RGB565, &mut dst, &mut cs).unwrap();
            assert!(pr.done);
            for (x, y) in [(0, 0), (5, 5), (10, 4), (19, 19)] {
                let (a, b) = (src.pixel(x, y).unwrap(), dst.pixel(x, y).unwrap());
                for k in 0..3 {
                    assert!(
                        a[k].abs_diff(b[k]) <= 8,
                        "enc {enc} ({x},{y}): {a:?} vs {b:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn solid_hextile_is_tiny() {
        let mut fb = Framebuffer::new(64, 64, DEFAULT_MAX_BYTES).unwrap();
        fb.fill_rect(Rect::new(0, 0, 64, 64), [1, 2, 3, 255]);
        let mut st = EncoderState::default();
        let mut wire = Vec::new();
        st.encode_rect(
            &fb,
            Rect::new(0, 0, 64, 64),
            encoding::HEXTILE,
            &PixelFormat::RGBX8888,
            &mut wire,
        )
        .unwrap();
        // cabecalho + 1 tile com bg + 15 tiles com flags 0
        assert_eq!(wire.len(), 12 + 5 + 15);
    }

    #[test]
    fn out_of_bounds_rejected() {
        let fb = Framebuffer::new(4, 4, DEFAULT_MAX_BYTES).unwrap();
        let mut st = EncoderState::default();
        let mut w = Vec::new();
        assert!(st
            .encode_rect(
                &fb,
                Rect::new(2, 2, 4, 4),
                encoding::RAW,
                &PixelFormat::RGBX8888,
                &mut w
            )
            .is_err());
    }
}
