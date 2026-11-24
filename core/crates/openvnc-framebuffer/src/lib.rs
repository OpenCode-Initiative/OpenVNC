//! Framebuffer RGBA8 com rastreamento de regioes alteradas (dirty regions).
//!
//! Todas as operacoes recortam (clip) as coordenadas ao tamanho do
//! framebuffer: dados remotos fora dos limites nunca causam panic.

use openvnc_core::{check_limit, PixelFormat, Rect, Result};

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximo de retangulos sujos antes de colapsar no bounding box.
const MAX_DAMAGE_RECTS: usize = 64;

/// Limite padrao de memoria do framebuffer (bytes).
pub const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Framebuffer RGBA8, linhas contiguas, alfa sempre 255.
#[derive(Clone)]
pub struct Framebuffer {
    width: u16,
    height: u16,
    data: Vec<u8>,
    damage: Vec<Rect>,
}

impl std::fmt::Debug for Framebuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framebuffer")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("damage", &self.damage.len())
            .finish()
    }
}

impl Framebuffer {
    /// Cria um framebuffer preto, validando `max_bytes`.
    pub fn new(width: u16, height: u16, max_bytes: u64) -> Result<Self> {
        let bytes = u64::from(width) * u64::from(height) * 4;
        check_limit("framebuffer bytes", bytes, max_bytes)?;
        let mut data = vec![0u8; bytes as usize];
        for px in data.chunks_exact_mut(4) {
            px[3] = 255;
        }
        Ok(Framebuffer {
            width,
            height,
            data,
            damage: Vec::new(),
        })
    }

    /// Largura.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Altura.
    pub fn height(&self) -> u16 {
        self.height
    }

    /// Pixels RGBA8.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Bytes por linha.
    pub fn stride(&self) -> usize {
        usize::from(self.width) * 4
    }

    /// Pixel RGBA em (x, y), se dentro dos limites.
    pub fn pixel(&self, x: u16, y: u16) -> Option<[u8; 4]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let i = usize::from(y) * self.stride() + usize::from(x) * 4;
        Some([
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            self.data[i + 3],
        ])
    }

    fn mark(&mut self, r: Rect) {
        if r.is_empty() {
            return;
        }
        self.damage.push(r);
        if self.damage.len() > MAX_DAMAGE_RECTS {
            let bb = self
                .damage
                .iter()
                .fold(Rect::default(), |acc, d| acc.union(d));
            self.damage.clear();
            self.damage.push(bb);
        }
    }

    /// Marca uma regiao como alterada.
    pub fn mark_damage(&mut self, r: Rect) {
        let r = r.clip_to(self.width, self.height);
        self.mark(r);
    }

    /// Retira e retorna as regioes alteradas desde a ultima chamada.
    pub fn take_damage(&mut self) -> Vec<Rect> {
        std::mem::take(&mut self.damage)
    }

    /// Preenche um retangulo com uma cor RGBA.
    pub fn fill_rect(&mut self, r: Rect, rgba: [u8; 4]) {
        let r = r.clip_to(self.width, self.height);
        if r.is_empty() {
            return;
        }
        let stride = self.stride();
        for y in r.y..r.y + r.height {
            let start = usize::from(y) * stride + usize::from(r.x) * 4;
            let row = &mut self.data[start..start + usize::from(r.width) * 4];
            for px in row.chunks_exact_mut(4) {
                px.copy_from_slice(&rgba);
            }
        }
        self.mark(r);
    }

    /// Escreve uma linha de pixels no formato `pf` a partir de (x, y).
    /// `pixels` contem pixels inteiros; o excesso fora do framebuffer e ignorado.
    pub fn put_row(&mut self, x: u16, y: u16, pixels: &[u8], pf: &PixelFormat) {
        let bpp = pf.bytes_per_pixel();
        let n = pixels.len() / bpp;
        let r = Rect::new(x, y, n.min(usize::from(u16::MAX)) as u16, 1)
            .clip_to(self.width, self.height);
        if r.is_empty() {
            return;
        }
        let start = usize::from(r.y) * self.stride() + usize::from(r.x) * 4;
        let dst = &mut self.data[start..start + usize::from(r.width) * 4];
        if *pf == PixelFormat::RGBX8888 {
            for (d, s) in dst.chunks_exact_mut(4).zip(pixels.chunks_exact(4)) {
                d[0] = s[0];
                d[1] = s[1];
                d[2] = s[2];
                d[3] = 255;
            }
        } else {
            for (d, s) in dst.chunks_exact_mut(4).zip(pixels.chunks_exact(bpp)) {
                d.copy_from_slice(&pf.to_rgba(pf.read_pixel(s)));
            }
        }
        self.mark(r);
    }

    /// Escreve uma linha de cores RGBA ja convertidas.
    pub fn put_rgba_row(&mut self, x: u16, y: u16, rgba: &[[u8; 4]]) {
        let r = Rect::new(x, y, rgba.len().min(usize::from(u16::MAX)) as u16, 1)
            .clip_to(self.width, self.height);
        if r.is_empty() {
            return;
        }
        let start = usize::from(r.y) * self.stride() + usize::from(r.x) * 4;
        let dst = &mut self.data[start..start + usize::from(r.width) * 4];
        for (d, s) in dst.chunks_exact_mut(4).zip(rgba) {
            d.copy_from_slice(s);
        }
        self.mark(r);
    }

    /// Copia a regiao `r` de outro framebuffer de mesmas dimensoes.
    pub fn copy_from(&mut self, src: &Framebuffer, r: Rect) {
        if src.width != self.width || src.height != self.height {
            return;
        }
        let r = r.clip_to(self.width, self.height);
        if r.is_empty() {
            return;
        }
        let stride = self.stride();
        let row = usize::from(r.width) * 4;
        for y in r.y..r.y + r.height {
            let o = usize::from(y) * stride + usize::from(r.x) * 4;
            self.data[o..o + row].copy_from_slice(&src.data[o..o + row]);
        }
        self.mark(r);
    }

    /// CopyRect: copia a regiao com origem (src_x, src_y) para `dst`.
    /// Regioes de origem fora dos limites sao recortadas.
    pub fn copy_rect(&mut self, src_x: u16, src_y: u16, dst: Rect) {
        let d = dst.clip_to(self.width, self.height);
        let s = Rect::new(src_x, src_y, d.width, d.height).clip_to(self.width, self.height);
        let w = d.width.min(s.width);
        let h = d.height.min(s.height);
        if w == 0 || h == 0 || (d.x != dst.x || d.y != dst.y) {
            return;
        }
        let stride = self.stride();
        let row_bytes = usize::from(w) * 4;
        let rows: Box<dyn Iterator<Item = u16>> = if src_y < d.y {
            Box::new((0..h).rev())
        } else {
            Box::new(0..h)
        };
        for i in rows {
            let so = usize::from(src_y + i) * stride + usize::from(src_x) * 4;
            let doff = usize::from(d.y + i) * stride + usize::from(d.x) * 4;
            self.data.copy_within(so..so + row_bytes, doff);
        }
        self.mark(Rect::new(d.x, d.y, w, h));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_enforced() {
        assert!(Framebuffer::new(1000, 1000, 100).is_err());
    }

    #[test]
    fn fill_and_clip() {
        let mut fb = Framebuffer::new(4, 4, DEFAULT_MAX_BYTES).unwrap();
        fb.fill_rect(Rect::new(2, 2, 100, 100), [1, 2, 3, 255]);
        assert_eq!(fb.pixel(3, 3), Some([1, 2, 3, 255]));
        assert_eq!(fb.pixel(1, 1), Some([0, 0, 0, 255]));
        assert_eq!(fb.take_damage(), vec![Rect::new(2, 2, 2, 2)]);
        assert!(fb.take_damage().is_empty());
    }

    #[test]
    fn put_row_out_of_bounds_is_safe() {
        let mut fb = Framebuffer::new(2, 2, DEFAULT_MAX_BYTES).unwrap();
        fb.put_row(1, 1, &[9, 9, 9, 0, 8, 8, 8, 0], &PixelFormat::RGBX8888);
        fb.put_row(5, 5, &[1, 1, 1, 0], &PixelFormat::RGBX8888);
        assert_eq!(fb.pixel(1, 1), Some([9, 9, 9, 255]));
    }

    #[test]
    fn copy_rect_overlapping() {
        let mut fb = Framebuffer::new(4, 4, DEFAULT_MAX_BYTES).unwrap();
        for y in 0..4u16 {
            fb.fill_rect(Rect::new(0, y, 4, 1), [y as u8, 0, 0, 255]);
        }
        fb.copy_rect(0, 0, Rect::new(0, 1, 4, 3));
        let rows: Vec<u8> = (0..4).map(|y| fb.pixel(0, y).unwrap()[0]).collect();
        assert_eq!(rows, vec![0, 0, 1, 2]);
    }

    #[test]
    fn damage_collapses() {
        let mut fb = Framebuffer::new(200, 200, DEFAULT_MAX_BYTES).unwrap();
        for i in 0..100 {
            fb.mark_damage(Rect::new(i, i, 1, 1));
        }
        assert!(fb.take_damage().len() <= MAX_DAMAGE_RECTS);
    }
}
