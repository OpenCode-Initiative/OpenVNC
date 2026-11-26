//! Backend macOS: captura por CoreGraphics (`CGDisplayCreateImage`) e
//! entrada por `CGEvent`. FFI direta, sem SDK no build.
//!
//! **So compilado (cross-check para aarch64-apple-darwin); nunca rodou num
//! Mac.** Exige as permissoes "Gravacao de Tela" e "Acessibilidade" para o
//! binario. `CGDisplayCreateImage` esta obsoleto no macOS 15; o alvo e
//! migrar para ScreenCaptureKit (ver PLANO.md).
#![allow(unsafe_code)]

use std::ffi::c_void;

use openvnc_core::{Error, KeyEvent, PointerEvent, Result};
use openvnc_framebuffer::Framebuffer;

use crate::{button_changes, InputInjector, ScreenCapture};

type CFTypeRef = *const c_void;
type CGEventRef = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct CGPoint {
    x: f64,
    y: f64,
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn CFDataGetBytePtr(d: CFTypeRef) -> *const u8;
    fn CFDataGetLength(d: CFTypeRef) -> isize;
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    // permissao de Acessibilidade (necessaria para CGEventPost)
    fn AXIsProcessTrusted() -> bool;
}

/// Situacao das permissoes TCC que o servidor precisa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    /// Gravacao de Tela concedida.
    pub screen_recording: bool,
    /// Acessibilidade concedida (injecao de entrada).
    pub accessibility: bool,
}

/// Consulta as permissoes sem abrir dialogo.
pub fn permissions() -> Permissions {
    // SAFETY: funcoes sem argumentos, apenas consultam o TCC.
    unsafe {
        Permissions {
            screen_recording: CGPreflightScreenCaptureAccess(),
            accessibility: AXIsProcessTrusted(),
        }
    }
}

const SCREEN_HELP: &str = "permissao de Gravacao de Tela ausente: conceda em Ajustes do Sistema > Privacidade e Seguranca > Gravacao de Tela e reinicie o servidor";
const AX_HELP: &str = "permissao de Acessibilidade ausente: conceda em Ajustes do Sistema > Privacidade e Seguranca > Acessibilidade e reinicie o servidor";

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGMainDisplayID() -> u32;
    fn CGDisplayPixelsWide(d: u32) -> usize;
    fn CGDisplayPixelsHigh(d: u32) -> usize;
    fn CGDisplayCreateImage(d: u32) -> CFTypeRef;
    fn CGImageGetWidth(i: CFTypeRef) -> usize;
    fn CGImageGetHeight(i: CFTypeRef) -> usize;
    fn CGImageGetBytesPerRow(i: CFTypeRef) -> usize;
    fn CGImageGetBitsPerPixel(i: CFTypeRef) -> usize;
    fn CGImageGetBitmapInfo(i: CFTypeRef) -> u32;
    fn CGImageGetDataProvider(i: CFTypeRef) -> CFTypeRef;
    fn CGDataProviderCopyData(p: CFTypeRef) -> CFTypeRef;
    fn CGEventCreateMouseEvent(s: CFTypeRef, t: u32, p: CGPoint, b: u32) -> CGEventRef;
    fn CGEventCreateKeyboardEvent(s: CFTypeRef, key: u16, down: bool) -> CGEventRef;
    fn CGEventKeyboardSetUnicodeString(e: CGEventRef, len: usize, s: *const u16);
    fn CGEventCreateScrollWheelEvent(
        s: CFTypeRef,
        units: u32,
        count: u32,
        w1: i32,
        ...
    ) -> CGEventRef;
    fn CGEventPost(tap: u32, e: CGEventRef);
    // macOS 10.15+: permissao de Gravacao de Tela (TCC)
    fn CGPreflightScreenCaptureAccess() -> bool;
    fn CGRequestScreenCaptureAccess() -> bool;
}

// CGEventType
const LEFT_DOWN: u32 = 1;
const LEFT_UP: u32 = 2;
const RIGHT_DOWN: u32 = 3;
const RIGHT_UP: u32 = 4;
const MOVED: u32 = 5;
const LEFT_DRAGGED: u32 = 6;
const RIGHT_DRAGGED: u32 = 7;
const OTHER_DOWN: u32 = 25;
const OTHER_UP: u32 = 26;
const OTHER_DRAGGED: u32 = 27;
const HID_EVENT_TAP: u32 = 0;
const SCROLL_UNIT_LINE: u32 = 1;
// kCGBitmapByteOrder32Little
const BYTE_ORDER_32_LITTLE: u32 = 2 << 12;

fn err(m: &str) -> Error {
    Error::Unsupported(format!("macOS: {m}"))
}

/// Captura do monitor principal.
pub struct CgCapture {
    display: u32,
    row: Vec<[u8; 4]>,
}

// SAFETY: so guarda o id do display (inteiro).
unsafe impl Send for CgCapture {}

impl CgCapture {
    /// Abre o monitor principal.
    pub fn new() -> Result<Self> {
        if !permissions().screen_recording {
            // pede uma vez (abre o dialogo do sistema) e falha com orientacao;
            // sem a permissao o macOS entrega so o papel de parede.
            // SAFETY: funcao sem argumentos.
            unsafe { CGRequestScreenCaptureAccess() };
            return Err(err(SCREEN_HELP));
        }
        // SAFETY: funcoes sem argumentos ponteiro.
        let display = unsafe { CGMainDisplayID() };
        let c = CgCapture {
            display,
            row: Vec::new(),
        };
        if c.size() == (0, 0) {
            return Err(err("sem monitor"));
        }
        Ok(c)
    }
}

impl ScreenCapture for CgCapture {
    fn size(&self) -> (u16, u16) {
        // SAFETY: id de display valido ou nao; a API so retorna 0.
        let (w, h) = unsafe {
            (
                CGDisplayPixelsWide(self.display),
                CGDisplayPixelsHigh(self.display),
            )
        };
        (
            u16::try_from(w).unwrap_or(u16::MAX),
            u16::try_from(h).unwrap_or(u16::MAX),
        )
    }

    fn capture(&mut self, fb: &mut Framebuffer) -> Result<bool> {
        // SAFETY: cada objeto Create/Copy e liberado com CFRelease uma vez;
        // os bytes so sao lidos dentro de [ptr, ptr+len) enquanto `data` vive.
        unsafe {
            let img = CGDisplayCreateImage(self.display);
            if img.is_null() {
                return Err(err(
                    "CGDisplayCreateImage falhou (permissao de Gravacao de Tela?)",
                ));
            }
            let (w, h) = (CGImageGetWidth(img), CGImageGetHeight(img));
            // HiDPI: a imagem vem em pixels, o tamanho logico em pontos
            if (usize::from(fb.width()), usize::from(fb.height())) != (w, h) {
                CFRelease(img);
                return Ok(false);
            }
            let bpr = CGImageGetBytesPerRow(img);
            let little = CGImageGetBitmapInfo(img) & (7 << 12) == BYTE_ORDER_32_LITTLE;
            if CGImageGetBitsPerPixel(img) != 32 {
                CFRelease(img);
                return Err(err("formato de pixel inesperado"));
            }
            let data = CGDataProviderCopyData(CGImageGetDataProvider(img));
            CFRelease(img);
            if data.is_null() {
                return Err(err("sem dados da imagem"));
            }
            let len = CFDataGetLength(data).max(0) as usize;
            let bytes = std::slice::from_raw_parts(CFDataGetBytePtr(data), len);
            self.row.resize(w, [0; 4]);
            for y in 0..h {
                let Some(src) = bytes.get(y * bpr..y * bpr + w * 4) else {
                    break;
                };
                for (p, s) in self.row.iter_mut().zip(src.chunks_exact(4)) {
                    // little-endian ARGB32 = BGRA na memoria; senao ARGB
                    *p = if little {
                        [s[2], s[1], s[0], 255]
                    } else {
                        [s[1], s[2], s[3], 255]
                    };
                }
                fb.put_rgba_row(0, y as u16, &self.row);
            }
            CFRelease(data);
        }
        Ok(true)
    }

    fn name(&self) -> &'static str {
        "coregraphics"
    }
}

/// Entrada por `CGEventPost`.
#[derive(Default)]
pub struct CgEventInjector {
    buttons: u8,
    pos: (f64, f64),
}

impl CgEventInjector {
    /// Cria o injetor.
    pub fn new() -> Self {
        Self::default()
    }
}

fn post(e: CGEventRef) -> Result<()> {
    if !permissions().accessibility {
        if !e.is_null() {
            // SAFETY: evento criado pelo chamador, liberado uma vez.
            unsafe { CFRelease(e) };
        }
        return Err(err(AX_HELP));
    }
    if e.is_null() {
        return Err(err("CGEvent nulo"));
    }
    // SAFETY: `e` e um CGEvent valido criado acima; liberado uma vez.
    unsafe {
        CGEventPost(HID_EVENT_TAP, e);
        CFRelease(e);
    }
    Ok(())
}

/// Keysym X11 -> virtual keycode do macOS (teclas sem texto).
fn keysym_to_keycode(ks: u32) -> Option<u16> {
    Some(match ks {
        0xff08 => 0x33,          // BackSpace
        0xff09 => 0x30,          // Tab
        0xff0d => 0x24,          // Return
        0xff1b => 0x35,          // Escape
        0xffff => 0x75,          // Delete
        0xff50 => 0x73,          // Home
        0xff57 => 0x77,          // End
        0xff55 => 0x74,          // Prior
        0xff56 => 0x79,          // Next
        0xff51 => 0x7b,          // Left
        0xff53 => 0x7c,          // Right
        0xff52 => 0x7e,          // Up
        0xff54 => 0x7d,          // Down
        0xffe1 => 0x38,          // Shift_L
        0xffe2 => 0x3c,          // Shift_R
        0xffe3 => 0x3b,          // Control_L
        0xffe4 => 0x3e,          // Control_R
        0xffe9 | 0xff7e => 0x3a, // Alt_L -> Option
        0xffea | 0xfe03 => 0x3d, // Alt_R -> Option direito
        0xffeb | 0xffe7 => 0x37, // Super_L/Meta_L -> Command
        0xffec | 0xffe8 => 0x36, // Super_R/Meta_R
        0xffe5 => 0x39,          // Caps_Lock
        0xffbe => 0x7a,          // F1
        0xffbf => 0x78,
        0xffc0 => 0x63,
        0xffc1 => 0x76,
        0xffc2 => 0x60,
        0xffc3 => 0x61,
        0xffc4 => 0x62,
        0xffc5 => 0x64,
        0xffc6 => 0x65,
        0xffc7 => 0x6d,
        0xffc8 => 0x67,
        0xffc9 => 0x6f, // F12
        0x20 => 0x31,   // espaco
        _ => return None,
    })
}

/// Keysym imprimivel -> caractere Unicode.
fn keysym_to_char(ks: u32) -> Option<char> {
    match ks {
        0x21..=0x7e | 0xa0..=0xff => char::from_u32(ks),
        k if k & 0xff00_0000 == 0x0100_0000 => char::from_u32(k & 0x00ff_ffff),
        _ => None,
    }
}

impl InputInjector for CgEventInjector {
    fn key(&mut self, ev: KeyEvent) -> Result<()> {
        // SAFETY: fonte nula = evento sintetico; o buffer UTF-16 vive ate a chamada.
        unsafe {
            if let Some(code) = keysym_to_keycode(ev.keysym) {
                return post(CGEventCreateKeyboardEvent(std::ptr::null(), code, ev.down));
            }
            let Some(c) = keysym_to_char(ev.keysym) else {
                return Ok(());
            };
            let e = CGEventCreateKeyboardEvent(std::ptr::null(), 0, ev.down);
            if !e.is_null() {
                let mut buf = [0u16; 2];
                let s = c.encode_utf16(&mut buf);
                CGEventKeyboardSetUnicodeString(e, s.len(), s.as_ptr());
            }
            post(e)
        }
    }

    fn pointer(&mut self, ev: PointerEvent) -> Result<()> {
        let p = CGPoint {
            x: f64::from(ev.x),
            y: f64::from(ev.y),
        };
        let held = self.buttons;
        // SAFETY: fonte nula = evento sintetico.
        unsafe {
            if (p.x, p.y) != self.pos {
                let t = if held & 1 != 0 {
                    LEFT_DRAGGED
                } else if held & 4 != 0 {
                    RIGHT_DRAGGED
                } else if held & 2 != 0 {
                    OTHER_DRAGGED
                } else {
                    MOVED
                };
                post(CGEventCreateMouseEvent(std::ptr::null(), t, p, 0))?;
                self.pos = (p.x, p.y);
            }
            for (b, down) in button_changes(self.buttons, ev.buttons) {
                let (t, n) = match (b, down) {
                    (0, true) => (LEFT_DOWN, 0),
                    (0, false) => (LEFT_UP, 0),
                    (1, true) => (OTHER_DOWN, 2),
                    (1, false) => (OTHER_UP, 2),
                    (2, true) => (RIGHT_DOWN, 1),
                    (2, false) => (RIGHT_UP, 1),
                    (3, true) => {
                        post(CGEventCreateScrollWheelEvent(
                            std::ptr::null(),
                            SCROLL_UNIT_LINE,
                            1,
                            1,
                        ))?;
                        continue;
                    }
                    (4, true) => {
                        post(CGEventCreateScrollWheelEvent(
                            std::ptr::null(),
                            SCROLL_UNIT_LINE,
                            1,
                            -1,
                        ))?;
                        continue;
                    }
                    _ => continue,
                };
                post(CGEventCreateMouseEvent(std::ptr::null(), t, p, n))?;
            }
        }
        self.buttons = ev.buttons;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keysym_tables() {
        assert_eq!(keysym_to_keycode(0xff0d), Some(0x24));
        assert_eq!(keysym_to_char(u32::from(b'a')), Some('a'));
        assert_eq!(keysym_to_char(0x0100_20ac), Some('€'));
        assert_eq!(keysym_to_char(0xff0d), None);
    }
}
