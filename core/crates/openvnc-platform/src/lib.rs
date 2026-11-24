//! Captura de tela e injecao de entrada, isoladas atras de traits.
//!
//! Backends:
//!
//! | SO | Captura | Entrada |
//! |---|---|---|
//! | Qualquer | [`TestPattern`] (sintetico, para CI e benchmarks) | [`NullInjector`] |
//! | Windows | GDI `BitBlt` ([`windows::GdiCapture`]) | `SendInput` ([`windows::SendInputInjector`]) |
//! | Linux X11 | `GetImage` ([`x11::X11Capture`]) | XTest ([`x11::XTestInjector`]) |
//! | Wayland | nao suportado ainda (PipeWire/portal) | nao suportado |
//! | macOS | nao suportado ainda (ScreenCaptureKit) | nao suportado |
//!
//! O DXGI Desktop Duplication (Windows) e o MIT-SHM/Damage (X11) ficam
//! para depois; os backends atuais copiam o quadro inteiro e o servidor
//! descobre as regioes alteradas comparando tiles.

use openvnc_core::{Error, KeyEvent, PointerEvent, Rect, Result};
use openvnc_framebuffer::Framebuffer;

#[cfg(windows)]
pub mod windows;

#[cfg(all(unix, not(target_os = "macos")))]
pub mod x11;

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Fonte de quadros da tela.
pub trait ScreenCapture: Send {
    /// Tamanho atual da tela.
    fn size(&self) -> (u16, u16);
    /// Copia o quadro atual para `fb` (mesmo tamanho de [`size`](Self::size)).
    /// Se o tamanho da tela mudou, retorna `Ok(false)` sem copiar; o
    /// chamador recria o framebuffer.
    fn capture(&mut self, fb: &mut Framebuffer) -> Result<bool>;
    /// Nome do backend (para logs).
    fn name(&self) -> &'static str;
}

/// Destino de eventos de entrada.
pub trait InputInjector: Send {
    /// Tecla (keysym X11).
    fn key(&mut self, ev: KeyEvent) -> Result<()>;
    /// Ponteiro em coordenadas da tela.
    fn pointer(&mut self, ev: PointerEvent) -> Result<()>;
}

/// Injetor que descarta tudo (modo somente-visualizacao, testes).
#[derive(Debug, Default)]
pub struct NullInjector;

impl InputInjector for NullInjector {
    fn key(&mut self, _ev: KeyEvent) -> Result<()> {
        Ok(())
    }
    fn pointer(&mut self, _ev: PointerEvent) -> Result<()> {
        Ok(())
    }
}

/// Tela sintetica animada: fundo fixo, um quadrado que se move a cada
/// quadro e uma faixa que acompanha o ponteiro recebido. Deterministica.
#[derive(Debug)]
pub struct TestPattern {
    width: u16,
    height: u16,
    frame: u64,
    /// Quadros por passo da animacao (0 = parada).
    pub speed: u32,
}

impl TestPattern {
    /// Nova tela sintetica.
    pub fn new(width: u16, height: u16) -> Self {
        TestPattern {
            width,
            height,
            frame: 0,
            speed: 1,
        }
    }

    /// Posicao do quadrado no quadro `n`.
    fn square(&self, n: u64) -> Rect {
        let s = 48u16.min(self.width).min(self.height);
        let span_x = u64::from(self.width - s).max(1);
        let span_y = u64::from(self.height - s).max(1);
        let bounce = |v: u64, span: u64| {
            let p = v % (2 * span);
            (if p < span { p } else { 2 * span - p }) as u16
        };
        Rect::new(bounce(n * 4, span_x), bounce(n * 3, span_y), s, s)
    }

    fn background(fb: &mut Framebuffer) {
        let (w, h) = (fb.width(), fb.height());
        let mut row = vec![[0u8; 4]; usize::from(w)];
        for y in 0..h {
            for (x, p) in row.iter_mut().enumerate() {
                let checker = ((x / 32) + usize::from(y / 32)) % 2 == 0;
                let g = if checker { 40 } else { 56 };
                *p = [g, g, (g + 30), 255];
            }
            fb.put_rgba_row(0, y, &row);
        }
    }
}

impl ScreenCapture for TestPattern {
    fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    fn capture(&mut self, fb: &mut Framebuffer) -> Result<bool> {
        if (fb.width(), fb.height()) != (self.width, self.height) {
            return Ok(false);
        }
        Self::background(fb);
        let n = self.frame / u64::from(self.speed.max(1));
        let sq = self.square(n);
        let c = (n % 256) as u8;
        fb.fill_rect(sq, [230, c, 255 - c, 255]);
        if self.speed > 0 {
            self.frame += 1;
        }
        Ok(true)
    }

    fn name(&self) -> &'static str {
        "test-pattern"
    }
}

/// Captura nativa do SO atual, se houver.
pub fn native_capture() -> Result<Box<dyn ScreenCapture>> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows::GdiCapture::new()?))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return Err(Error::Unsupported(
                "captura Wayland (PipeWire/portal) ainda nao implementada".into(),
            ));
        }
        Ok(Box::new(x11::X11Capture::new()?))
    }
    #[cfg(target_os = "macos")]
    {
        Err(Error::Unsupported(
            "captura macOS (ScreenCaptureKit) ainda nao implementada".into(),
        ))
    }
    #[cfg(not(any(windows, unix)))]
    {
        Err(Error::Unsupported("SO sem backend de captura".into()))
    }
}

/// Injetor nativo do SO atual, se houver.
pub fn native_injector() -> Result<Box<dyn InputInjector>> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows::SendInputInjector::new()))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok(Box::new(x11::XTestInjector::new()?))
    }
    #[cfg(not(any(windows, all(unix, not(target_os = "macos")))))]
    {
        Err(Error::Unsupported("SO sem backend de entrada".into()))
    }
}

/// Converte a mascara RFB em transicoes (botao, pressionado) desde `prev`.
/// Botoes RFB: 0 esquerdo, 1 meio, 2 direito, 3/4 roda.
pub fn button_changes(prev: u8, now: u8) -> impl Iterator<Item = (u8, bool)> {
    (0..8u8).filter_map(move |b| {
        let (was, is) = (prev >> b & 1 == 1, now >> b & 1 == 1);
        (was != is).then_some((b, is))
    })
}

#[allow(dead_code)]
fn unsupported<T>(what: &str) -> Result<T> {
    Err(Error::Unsupported(what.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvnc_framebuffer::DEFAULT_MAX_BYTES;

    #[test]
    fn test_pattern_moves() {
        let mut tp = TestPattern::new(320, 200);
        let mut a = Framebuffer::new(320, 200, DEFAULT_MAX_BYTES).unwrap();
        let mut b = a.clone();
        assert!(tp.capture(&mut a).unwrap());
        assert!(tp.capture(&mut b).unwrap());
        assert_ne!(a.data(), b.data());
        let mut small = Framebuffer::new(10, 10, DEFAULT_MAX_BYTES).unwrap();
        assert!(!tp.capture(&mut small).unwrap());
    }

    #[test]
    fn test_pattern_static_when_speed_zero() {
        let mut tp = TestPattern::new(64, 64);
        tp.speed = 0;
        let mut a = Framebuffer::new(64, 64, DEFAULT_MAX_BYTES).unwrap();
        let mut b = a.clone();
        tp.capture(&mut a).unwrap();
        tp.capture(&mut b).unwrap();
        assert_eq!(a.data(), b.data());
    }

    #[test]
    fn buttons() {
        let v: Vec<_> = button_changes(0b001, 0b100).collect();
        assert_eq!(v, vec![(0, false), (2, true)]);
    }
}
