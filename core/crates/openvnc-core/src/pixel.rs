//! Formato de pixel RFB (RFC 6143, secao 7.4).

use crate::{Error, Result};

/// Formato de pixel RFB (`PIXEL_FORMAT`, 16 bytes na rede).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    /// Bits por pixel: 8, 16 ou 32.
    pub bits_per_pixel: u8,
    /// Bits uteis de cor.
    pub depth: u8,
    /// Pixels multi-byte em big-endian.
    pub big_endian: bool,
    /// True colour (caso contrario, mapa de cores).
    pub true_colour: bool,
    /// Valor maximo do vermelho.
    pub red_max: u16,
    /// Valor maximo do verde.
    pub green_max: u16,
    /// Valor maximo do azul.
    pub blue_max: u16,
    /// Deslocamento do vermelho.
    pub red_shift: u8,
    /// Deslocamento do verde.
    pub green_shift: u8,
    /// Deslocamento do azul.
    pub blue_shift: u8,
}

impl PixelFormat {
    /// Tamanho na rede.
    pub const WIRE_LEN: usize = 16;

    /// 32 bpp, little-endian, bytes em memoria R, G, B, X.
    /// E o formato que o cliente OpenVNC solicita por padrao.
    pub const RGBX8888: PixelFormat = PixelFormat {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 0,
        green_shift: 8,
        blue_shift: 16,
    };

    /// Bytes por pixel.
    pub fn bytes_per_pixel(&self) -> usize {
        usize::from(self.bits_per_pixel / 8)
    }

    /// Decodifica 16 bytes e valida.
    pub fn parse(b: &[u8; 16]) -> Result<Self> {
        let pf = PixelFormat {
            bits_per_pixel: b[0],
            depth: b[1],
            big_endian: b[2] != 0,
            true_colour: b[3] != 0,
            red_max: u16::from_be_bytes([b[4], b[5]]),
            green_max: u16::from_be_bytes([b[6], b[7]]),
            blue_max: u16::from_be_bytes([b[8], b[9]]),
            red_shift: b[10],
            green_shift: b[11],
            blue_shift: b[12],
        };
        pf.validate()?;
        Ok(pf)
    }

    /// Codifica em 16 bytes (3 de padding).
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = self.bits_per_pixel;
        b[1] = self.depth;
        b[2] = u8::from(self.big_endian);
        b[3] = u8::from(self.true_colour);
        b[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        b[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        b[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        b[10] = self.red_shift;
        b[11] = self.green_shift;
        b[12] = self.blue_shift;
        b
    }

    /// Valida bpp e shifts.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.bits_per_pixel, 8 | 16 | 32) {
            return Err(Error::Protocol(format!(
                "invalid bits-per-pixel {}",
                self.bits_per_pixel
            )));
        }
        if self.true_colour {
            for s in [self.red_shift, self.green_shift, self.blue_shift] {
                if s >= 32 {
                    return Err(Error::Protocol(format!("invalid colour shift {s}")));
                }
            }
        }
        Ok(())
    }

    /// Le um pixel (`bytes_per_pixel` bytes) como inteiro.
    /// `b` deve ter pelo menos `bytes_per_pixel` bytes.
    #[inline]
    pub fn read_pixel(&self, b: &[u8]) -> u32 {
        match (self.bits_per_pixel, self.big_endian) {
            (8, _) => u32::from(b[0]),
            (16, false) => u32::from(u16::from_le_bytes([b[0], b[1]])),
            (16, true) => u32::from(u16::from_be_bytes([b[0], b[1]])),
            (_, false) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            (_, true) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }

    /// Converte um pixel true-colour em RGBA8 (alfa 255).
    #[inline]
    pub fn to_rgba(&self, p: u32) -> [u8; 4] {
        #[inline]
        fn comp(p: u32, shift: u8, max: u16) -> u8 {
            if max == 0 {
                return 0;
            }
            let v = (p >> shift) & u32::from(max);
            if max == 255 {
                v as u8
            } else {
                ((v * 255 + u32::from(max) / 2) / u32::from(max)) as u8
            }
        }
        [
            comp(p, self.red_shift, self.red_max),
            comp(p, self.green_shift, self.green_max),
            comp(p, self.blue_shift, self.blue_max),
            255,
        ]
    }

    /// Tamanho do CPIXEL do ZRLE/Tight (RFC 6143, 7.7.6): 3 bytes quando
    /// 32 bpp, true colour, depth <= 24 e as cores cabem em 3 bytes.
    pub fn cpixel_len(&self) -> usize {
        if self.bits_per_pixel == 32 && self.true_colour && self.depth <= 24 {
            let mask = (u32::from(self.red_max) << self.red_shift)
                | (u32::from(self.green_max) << self.green_shift)
                | (u32::from(self.blue_max) << self.blue_shift);
            if mask & 0xFF00_0000 == 0 || mask & 0x0000_00FF == 0 {
                return 3;
            }
        }
        self.bytes_per_pixel()
    }

    /// Le um CPIXEL e retorna o pixel inteiro.
    #[inline]
    pub fn read_cpixel(&self, b: &[u8]) -> u32 {
        if self.cpixel_len() != 3 {
            return self.read_pixel(b);
        }
        let mask = (u32::from(self.red_max) << self.red_shift)
            | (u32::from(self.green_max) << self.green_shift)
            | (u32::from(self.blue_max) << self.blue_shift);
        let low = mask & 0xFF00_0000 == 0;
        let v = if self.big_endian {
            u32::from_be_bytes([0, b[0], b[1], b[2]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], 0])
        };
        if low {
            v
        } else {
            v << 8
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let b = PixelFormat::RGBX8888.to_bytes();
        assert_eq!(PixelFormat::parse(&b).unwrap(), PixelFormat::RGBX8888);
    }

    #[test]
    fn rejects_bad_bpp() {
        let mut b = PixelFormat::RGBX8888.to_bytes();
        b[0] = 24;
        assert!(PixelFormat::parse(&b).is_err());
    }

    #[test]
    fn rgba_conversion() {
        let pf = PixelFormat::RGBX8888;
        assert_eq!(pf.to_rgba(pf.read_pixel(&[1, 2, 3, 0])), [1, 2, 3, 255]);
        let rgb565 = PixelFormat {
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
        assert_eq!(rgb565.to_rgba(0xFFFF), [255, 255, 255, 255]);
        assert_eq!(rgb565.to_rgba(0xF800), [255, 0, 0, 255]);
    }

    #[test]
    fn cpixel() {
        let pf = PixelFormat::RGBX8888;
        assert_eq!(pf.cpixel_len(), 3);
        assert_eq!(pf.to_rgba(pf.read_cpixel(&[9, 8, 7])), [9, 8, 7, 255]);
    }
}
