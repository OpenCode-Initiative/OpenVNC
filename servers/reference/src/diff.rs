//! Deteccao de regioes alteradas entre dois quadros.

use openvnc_core::Rect;
use openvnc_framebuffer::Framebuffer;

/// Lado do tile de comparacao.
pub const TILE: u16 = 64;

fn rows_equal(a: &Framebuffer, b: &Framebuffer, r: Rect) -> bool {
    let (sa, sb) = (a.stride(), b.stride());
    let x0 = usize::from(r.x) * 4;
    let x1 = x0 + usize::from(r.width) * 4;
    (r.y..r.y + r.height).all(|y| {
        let y = usize::from(y);
        a.data()[y * sa + x0..y * sa + x1] == b.data()[y * sb + x0..y * sb + x1]
    })
}

/// Tiles diferentes entre `old` e `new` (mesmo tamanho), com tiles
/// vizinhos na mesma linha unidos num retangulo so.
pub fn dirty_tiles(old: &Framebuffer, new: &Framebuffer) -> Vec<Rect> {
    let (w, h) = (new.width(), new.height());
    let mut out = Vec::new();
    let mut ty = 0u16;
    while ty < h {
        let th = TILE.min(h - ty);
        let mut run: Option<Rect> = None;
        let mut tx = 0u16;
        while tx < w {
            let tw = TILE.min(w - tx);
            let t = Rect::new(tx, ty, tw, th);
            if !rows_equal(old, new, t) {
                run = Some(match run {
                    Some(r) => Rect::new(r.x, r.y, r.width + tw, th),
                    None => t,
                });
            } else if let Some(r) = run.take() {
                out.push(r);
            }
            tx = tx.saturating_add(TILE);
            if tx == u16::MAX {
                break;
            }
        }
        out.extend(run);
        ty = ty.saturating_add(TILE);
        if ty == u16::MAX {
            break;
        }
    }
    // une faixas verticais identicas (mesmo x/largura, linhas contiguas)
    let mut merged: Vec<Rect> = Vec::with_capacity(out.len());
    for r in out {
        if let Some(m) = merged
            .iter_mut()
            .find(|m| m.x == r.x && m.width == r.width && m.y + m.height == r.y)
        {
            m.height += r.height;
        } else {
            merged.push(r);
        }
    }
    merged
}

/// Area contida de `rects` (bounding box).
pub fn bounds(rects: &[Rect]) -> Option<Rect> {
    let mut it = rects.iter();
    let first = *it.next()?;
    Some(it.fold(first, |a, r| a.union(r)))
}

fn area_row(fb: &Framebuffer, area: Rect, y: u16) -> &[u8] {
    let s = usize::from(y) * fb.stride() + usize::from(area.x) * 4;
    &fb.data()[s..s + usize::from(area.width) * 4]
}

/// Detecta rolagem vertical dentro de `area`: procura `dy` tal que
/// `new[y] == old[y - dy]` para toda a regiao sobreposta. Retorna
/// `(destino, src_y)` para um CopyRect, ou `None`.
pub fn detect_vertical_scroll(
    old: &Framebuffer,
    new: &Framebuffer,
    area: Rect,
    max_dy: u16,
) -> Option<(Rect, u16)> {
    if area.height < 32 || area.width < 32 {
        return None;
    }
    let row = |fb, y| area_row(fb, area, y);
    // linha de amostra: meio da area
    let probe = area.y + area.height / 2;
    for d in 1..=max_dy.min(area.height / 2) {
        for dy in [i32::from(d), -i32::from(d)] {
            let src = i32::from(probe) - dy;
            if src < i32::from(area.y) || src >= i32::from(area.y + area.height) {
                continue;
            }
            if row(new, probe) != row(old, src as u16) {
                continue;
            }
            // regiao sobreposta
            let (dst_y, src_y, h) = if dy > 0 {
                (area.y + d, area.y, area.height - d)
            } else {
                (area.y, area.y + d, area.height - d)
            };
            if (0..h).all(|i| row(new, dst_y + i) == row(old, src_y + i)) {
                // compensa so se a linha nao for trivialmente uniforme
                if row(new, probe)
                    .chunks_exact(4)
                    .all(|p| p == &row(new, probe)[..4])
                {
                    return None;
                }
                return Some((Rect::new(area.x, dst_y, area.width, h), src_y));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvnc_framebuffer::DEFAULT_MAX_BYTES;

    fn fb(w: u16, h: u16) -> Framebuffer {
        Framebuffer::new(w, h, DEFAULT_MAX_BYTES).unwrap()
    }

    #[test]
    fn identical_is_clean() {
        let a = fb(200, 100);
        assert!(dirty_tiles(&a, &a.clone()).is_empty());
    }

    #[test]
    fn one_pixel_marks_its_tile() {
        let a = fb(200, 150);
        let mut b = a.clone();
        b.fill_rect(Rect::new(130, 70, 1, 1), [9, 9, 9, 255]);
        assert_eq!(dirty_tiles(&a, &b), vec![Rect::new(128, 64, 64, 64)]);
        // tiles da borda sao recortados
        b.fill_rect(Rect::new(199, 149, 1, 1), [9, 9, 9, 255]);
        let d = dirty_tiles(&a, &b);
        assert!(d.contains(&Rect::new(192, 128, 8, 22)), "{d:?}");
    }

    #[test]
    fn neighbours_merge() {
        let a = fb(256, 128);
        let mut b = a.clone();
        b.fill_rect(Rect::new(10, 10, 150, 100), [1, 1, 1, 255]);
        assert_eq!(dirty_tiles(&a, &b), vec![Rect::new(0, 0, 192, 128)]);
    }

    #[test]
    fn scroll_detected() {
        let mut a = fb(100, 100);
        for y in 0..100u16 {
            a.fill_rect(Rect::new(0, y, 100, 1), [y as u8, (y * 3) as u8, 7, 255]);
            a.fill_rect(Rect::new(y, y, 1, 1), [255, 255, 255, 255]);
        }
        let mut b = a.clone();
        b.copy_from(&a, Rect::new(0, 0, 100, 100));
        b.copy_rect(0, 10, Rect::new(0, 0, 100, 90)); // rolou 10 linhas para cima
        let area = Rect::new(0, 0, 100, 100);
        assert_eq!(
            detect_vertical_scroll(&a, &b, area, 64),
            Some((Rect::new(0, 0, 100, 90), 10))
        );
        assert_eq!(detect_vertical_scroll(&a, &a.clone(), area, 64), None);
    }
}
