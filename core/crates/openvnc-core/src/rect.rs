//! Retangulos de framebuffer.

/// Retangulo em coordenadas de framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Rect {
    /// X do canto superior esquerdo.
    pub x: u16,
    /// Y do canto superior esquerdo.
    pub y: u16,
    /// Largura.
    pub width: u16,
    /// Altura.
    pub height: u16,
}

impl Rect {
    /// Cria um retangulo.
    pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    /// Numero de pixels (sem overflow).
    pub fn area(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }

    /// Verdadeiro se nao tem area.
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// Intersecao com uma area `w x h` com origem em (0,0).
    pub fn clip_to(&self, w: u16, h: u16) -> Rect {
        let x0 = u32::from(self.x).min(u32::from(w));
        let y0 = u32::from(self.y).min(u32::from(h));
        let x1 = (u32::from(self.x) + u32::from(self.width)).min(u32::from(w));
        let y1 = (u32::from(self.y) + u32::from(self.height)).min(u32::from(h));
        Rect::new(x0 as u16, y0 as u16, (x1 - x0) as u16, (y1 - y0) as u16)
    }

    /// Menor retangulo contendo ambos.
    pub fn union(&self, o: &Rect) -> Rect {
        if self.is_empty() {
            return *o;
        }
        if o.is_empty() {
            return *self;
        }
        let x0 = self.x.min(o.x);
        let y0 = self.y.min(o.y);
        let x1 = (u32::from(self.x) + u32::from(self.width))
            .max(u32::from(o.x) + u32::from(o.width))
            .min(u32::from(u16::MAX));
        let y1 = (u32::from(self.y) + u32::from(self.height))
            .max(u32::from(o.y) + u32::from(o.height))
            .min(u32::from(u16::MAX));
        Rect::new(
            x0,
            y0,
            (x1 - u32::from(x0)) as u16,
            (y1 - u32::from(y0)) as u16,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip() {
        assert_eq!(
            Rect::new(5, 5, 10, 10).clip_to(8, 100),
            Rect::new(5, 5, 3, 10)
        );
        assert!(Rect::new(65535, 0, 65535, 1).clip_to(10, 10).is_empty());
    }

    #[test]
    fn union() {
        assert_eq!(
            Rect::new(0, 0, 2, 2).union(&Rect::new(5, 5, 1, 1)),
            Rect::new(0, 0, 6, 6)
        );
    }
}
