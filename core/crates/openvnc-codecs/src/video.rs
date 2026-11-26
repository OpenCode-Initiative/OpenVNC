//! Video H.264 para o protocolo nativo (feature `h264`).
//!
//! Cada quadro cobre a tela inteira e faz parte de um fluxo continuo: o
//! encoder do servidor e o decoder do cliente guardam estado (quadros de
//! referencia). As dimensoes precisam ser pares (subamostragem 4:2:0).

use openh264::decoder::Decoder;
use openh264::encoder::{Encoder, EncoderConfig, FrameType};
use openh264::formats::{RgbaSliceU8, YUVBuffer, YUVSource};
use openh264::OpenH264API;
use openvnc_core::{Error, Result};

fn verr(e: impl std::fmt::Display) -> Error {
    Error::Protocol(format!("h264: {e}"))
}

/// Indica se a tela pode ser codificada (dimensoes pares e nao nulas).
pub fn supported(w: u16, h: u16) -> bool {
    w >= 16 && h >= 16 && w % 2 == 0 && h % 2 == 0
}

/// Encoder com estado. Recriar quando a resolucao mudar.
pub struct H264Encoder {
    inner: Encoder,
    size: (u16, u16),
    yuv: YUVBuffer,
}

impl std::fmt::Debug for H264Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H264Encoder")
            .field("size", &self.size)
            .finish()
    }
}

impl H264Encoder {
    /// Cria para `w`x`h` com taxa alvo em bit/s.
    pub fn new(w: u16, h: u16, bitrate: u32) -> Result<Self> {
        if !supported(w, h) {
            return Err(verr("dimensoes precisam ser pares e >= 16"));
        }
        let cfg = EncoderConfig::new()
            .bitrate(openh264::encoder::BitRate::from_bps(bitrate))
            .max_frame_rate(openh264::encoder::FrameRate::from_hz(60.0))
            .usage_type(openh264::encoder::UsageType::ScreenContentRealTime)
            .skip_frames(false);
        let inner = Encoder::with_api_config(OpenH264API::from_source(), cfg).map_err(verr)?;
        Ok(H264Encoder {
            inner,
            size: (w, h),
            yuv: YUVBuffer::new(usize::from(w), usize::from(h)),
        })
    }

    /// Resolucao do fluxo.
    pub fn size(&self) -> (u16, u16) {
        self.size
    }

    /// Forca o proximo quadro a ser IDR (decodificavel sozinho).
    pub fn force_keyframe(&mut self) {
        self.inner.force_intra_frame();
    }

    /// Codifica um quadro RGBA8 (`w*h*4` bytes). Retorna o bitstream Annex B
    /// e se o quadro e IDR.
    pub fn encode(&mut self, rgba: &[u8]) -> Result<(Vec<u8>, bool)> {
        let (w, h) = (usize::from(self.size.0), usize::from(self.size.1));
        if rgba.len() != w * h * 4 {
            return Err(verr("tamanho do quadro incorreto"));
        }
        self.yuv.read_rgb(RgbaSliceU8::new(rgba, (w, h)));
        let bs = self.inner.encode(&self.yuv).map_err(verr)?;
        let key = matches!(bs.frame_type(), FrameType::IDR | FrameType::I);
        Ok((bs.to_vec(), key))
    }
}

/// Decoder com estado.
pub struct H264Decoder {
    inner: Decoder,
}

impl std::fmt::Debug for H264Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("H264Decoder")
    }
}

impl H264Decoder {
    /// Cria um decoder.
    pub fn new() -> Result<Self> {
        Ok(H264Decoder {
            inner: Decoder::new().map_err(verr)?,
        })
    }

    /// Decodifica um quadro e escreve RGBA8 em `out` (`w*h*4`). Retorna
    /// `false` se o bitstream nao produziu imagem (ex.: so parametros).
    pub fn decode(&mut self, data: &[u8], w: u16, h: u16, out: &mut [u8]) -> Result<bool> {
        let Some(img) = self.inner.decode(data).map_err(verr)? else {
            return Ok(false);
        };
        if img.dimensions() != (usize::from(w), usize::from(h)) {
            return Err(verr("dimensoes do quadro divergem do retangulo"));
        }
        if out.len() != usize::from(w) * usize::from(h) * 4 {
            return Err(verr("buffer de saida com tamanho incorreto"));
        }
        img.write_rgba8(out);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_aproximado() {
        let (w, h) = (64u16, 48u16);
        let mut e = H264Encoder::new(w, h, 2_000_000).unwrap();
        let mut d = H264Decoder::new().unwrap();
        let mut out = vec![0u8; 64 * 48 * 4];
        for f in 0..5u8 {
            let rgba: Vec<u8> = (0..64 * 48)
                .flat_map(|i| [((i % 64) * 4) as u8, f.wrapping_mul(40), 128, 255])
                .collect();
            let (bs, key) = e.encode(&rgba).unwrap();
            if f == 0 {
                assert!(key, "o primeiro quadro precisa ser IDR");
            }
            assert!(d.decode(&bs, w, h, &mut out).unwrap());
            // com perdas: erro medio pequeno
            let err: u64 = rgba
                .iter()
                .zip(&out)
                .map(|(a, b)| u64::from(a.abs_diff(*b)))
                .sum();
            assert!(err / rgba.len() as u64 <= 6, "erro medio alto: {err}");
        }
        assert!(H264Encoder::new(63, 48, 1).is_err());
    }

    /// Mede banda H.264 contra zlib numa cena com movimento (rode com
    /// `cargo test -p openvnc-codecs --features h264 -- --ignored --nocapture`).
    #[test]
    #[ignore = "medicao, nao verificacao"]
    fn medir_banda() {
        use std::io::Write as _;
        let (w, h) = (640u16, 480u16);
        let mut e = H264Encoder::new(w, h, 8_000_000).unwrap();
        let (mut hb, mut zb) = (0usize, 0usize);
        let t = std::time::Instant::now();
        for f in 0..60u32 {
            let rgba: Vec<u8> = (0..u32::from(w) * u32::from(h))
                .flat_map(|i| {
                    let (x, y) = (i % 640 + f * 4, i / 640 + f * 2);
                    [(x ^ y) as u8, (x * 3) as u8, (y * 5 + x) as u8, 255]
                })
                .collect();
            hb += e.encode(&rgba).unwrap().0.len();
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            z.write_all(&rgba).unwrap();
            zb += z.finish().unwrap().len();
        }
        println!(
            "60 quadros 640x480: h264 {} KiB, zlib {} KiB, razao {:.1}x, {:.1} ms/quadro (gerar + h264 + zlib)",
            hb / 1024,
            zb / 1024,
            zb as f64 / hb as f64,
            t.elapsed().as_secs_f64() * 1000.0 / 60.0
        );
    }
}
