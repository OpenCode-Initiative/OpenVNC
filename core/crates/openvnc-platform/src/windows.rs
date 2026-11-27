//! Backend Windows: captura por GDI `BitBlt` e entrada por `SendInput`.
//!
//! `unsafe` e liberado so neste modulo: sao chamadas FFI Win32. Cada
//! bloco tem um comentario `SAFETY` com a invariante usada.
#![allow(unsafe_code)]

use std::ptr;

use openvnc_core::{Error, KeyEvent, PointerEvent, Result};
use openvnc_framebuffer::Framebuffer;
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC,
    SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS, HBITMAP, HDC,
    HGDIOBJ, SRCCOPY,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    MapVirtualKeyW, SendInput, VkKeyScanW, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, MAPVK_VK_TO_VSC,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEINPUT, VIRTUAL_KEY,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

use crate::{button_changes, InputInjector, ScreenCapture};

/// Retangulo (na area virtual) do monitor capturado, quando a captura e de
/// um monitor so (DXGI). `None`: a imagem e a area virtual inteira (GDI).
static VIEW: std::sync::Mutex<Option<(i32, i32)>> = std::sync::Mutex::new(None);

/// Informa a origem (canto superior esquerdo, coordenadas da area
/// virtual) do monitor que a captura esta mostrando.
pub fn set_view(origin: Option<(i32, i32)>) {
    if let Ok(mut v) = VIEW.lock() {
        *v = origin;
    }
}

fn virtual_screen() -> (i32, i32, i32, i32) {
    // SAFETY: GetSystemMetrics nao tem pre-condicoes.
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    }
}

/// Captura da area de trabalho virtual inteira por GDI.
pub struct GdiCapture {
    screen: HDC,
    mem: HDC,
    bmp: HBITMAP,
    old: HGDIOBJ,
    bits: *mut u8,
    x: i32,
    y: i32,
    w: u16,
    h: u16,
    row: Vec<[u8; 4]>,
}

// SAFETY: os handles GDI e o ponteiro do DIB pertencem so a esta struct e
// sao usados por uma thread de cada vez (&mut self).
unsafe impl Send for GdiCapture {}

impl GdiCapture {
    /// Abre a captura no tamanho atual da tela.
    pub fn new() -> Result<Self> {
        let (x, y, w, h) = virtual_screen();
        set_view(None);
        let (w16, h16) = (
            u16::try_from(w).map_err(|_| Error::Unsupported("tela larga demais".into()))?,
            u16::try_from(h).map_err(|_| Error::Unsupported("tela alta demais".into()))?,
        );
        if w16 == 0 || h16 == 0 {
            return Err(Error::Unsupported("sem desktop interativo".into()));
        }
        // SAFETY: GetDC(null) devolve o DC da tela; os retornos sao checados
        // e liberados em Drop. BITMAPINFO e inicializado por completo.
        unsafe {
            let screen = GetDC(ptr::null_mut());
            if screen.is_null() {
                return Err(Error::Unsupported("GetDC falhou".into()));
            }
            let mem = CreateCompatibleDC(screen);
            let mut bi: BITMAPINFO = std::mem::zeroed();
            bi.bmiHeader = BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..std::mem::zeroed()
            };
            let mut bits: *mut core::ffi::c_void = ptr::null_mut();
            let bmp = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &mut bits, ptr::null_mut(), 0);
            if mem.is_null() || bmp.is_null() || bits.is_null() {
                if !bmp.is_null() {
                    DeleteObject(bmp);
                }
                if !mem.is_null() {
                    DeleteDC(mem);
                }
                ReleaseDC(ptr::null_mut(), screen);
                return Err(Error::Unsupported("CreateDIBSection falhou".into()));
            }
            let old = SelectObject(mem, bmp);
            Ok(GdiCapture {
                screen,
                mem,
                bmp,
                old,
                bits: bits.cast(),
                x,
                y,
                w: w16,
                h: h16,
                row: vec![[0; 4]; usize::from(w16)],
            })
        }
    }
}

impl Drop for GdiCapture {
    fn drop(&mut self) {
        // SAFETY: handles criados em `new` e ainda validos.
        unsafe {
            SelectObject(self.mem, self.old);
            DeleteObject(self.bmp);
            DeleteDC(self.mem);
            ReleaseDC(ptr::null_mut(), self.screen);
        }
    }
}

impl ScreenCapture for GdiCapture {
    fn size(&self) -> (u16, u16) {
        (self.w, self.h)
    }

    fn capture(&mut self, fb: &mut Framebuffer) -> Result<bool> {
        let (_, _, w, h) = virtual_screen();
        if (w, h) != (i32::from(self.w), i32::from(self.h)) {
            *self = GdiCapture::new()?;
            return Ok(false);
        }
        if (fb.width(), fb.height()) != (self.w, self.h) {
            return Ok(false);
        }
        let (wi, hi) = (i32::from(self.w), i32::from(self.h));
        // SAFETY: mem tem o DIB de w x h selecionado; screen e o DC da tela.
        let ok = unsafe {
            BitBlt(
                self.mem,
                0,
                0,
                wi,
                hi,
                self.screen,
                self.x,
                self.y,
                SRCCOPY | CAPTUREBLT,
            )
        };
        if ok == 0 {
            // ex.: tela bloqueada / UAC (desktop seguro)
            return Err(Error::Unsupported("BitBlt falhou".into()));
        }
        let stride = usize::from(self.w) * 4;
        // SAFETY: o DIB tem exatamente stride*h bytes e vive enquanto self.
        let data = unsafe { std::slice::from_raw_parts(self.bits, stride * usize::from(self.h)) };
        for (y, src) in data.chunks_exact(stride).enumerate() {
            for (p, s) in self.row.iter_mut().zip(src.chunks_exact(4)) {
                *p = [s[2], s[1], s[0], 255];
            }
            fb.put_rgba_row(0, y as u16, &self.row);
        }
        Ok(true)
    }

    fn name(&self) -> &'static str {
        "gdi"
    }
}

/// Injecao de teclado e mouse com `SendInput`.
#[derive(Debug, Default)]
pub struct SendInputInjector {
    buttons: u8,
}

impl SendInputInjector {
    /// Novo injetor.
    pub fn new() -> Self {
        Self::default()
    }
}

fn send(inputs: &[INPUT]) -> Result<()> {
    // SAFETY: slice valido de INPUTs inicializados.
    let n = unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
    if n as usize != inputs.len() {
        return Err(Error::Unsupported("SendInput bloqueado (UIPI?)".into()));
    }
    Ok(())
}

fn key_input(vk: VIRTUAL_KEY, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn mouse_input(dx: i32, dy: i32, data: i32, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data as u32,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Keysym X11 -> (virtual key, estendida).
fn keysym_to_vk(ks: u32) -> Option<(u16, bool)> {
    Some(match ks {
        0xff08 => (0x08, false),                                   // BackSpace
        0xff09 => (0x09, false),                                   // Tab
        0xff0d => (0x0d, false),                                   // Return
        0xff1b => (0x1b, false),                                   // Escape
        0xff50 => (0x24, true),                                    // Home
        0xff51 => (0x25, true),                                    // Left
        0xff52 => (0x26, true),                                    // Up
        0xff53 => (0x27, true),                                    // Right
        0xff54 => (0x28, true),                                    // Down
        0xff55 => (0x21, true),                                    // Prior
        0xff56 => (0x22, true),                                    // Next
        0xff57 => (0x23, true),                                    // End
        0xff63 => (0x2d, true),                                    // Insert
        0xffff => (0x2e, true),                                    // Delete
        0xffe1 => (0xa0, false),                                   // Shift_L
        0xffe2 => (0xa1, false),                                   // Shift_R
        0xffe3 => (0xa2, false),                                   // Control_L
        0xffe4 => (0xa3, true),                                    // Control_R
        0xffe9 | 0xff7e => (0xa4, false),                          // Alt_L
        0xffea | 0xfe03 => (0xa5, true),                           // Alt_R / AltGr
        0xffeb => (0x5b, true),                                    // Super_L
        0xffec => (0x5c, true),                                    // Super_R
        0xff67 => (0x5d, true),                                    // Menu
        0xffe5 => (0x14, false),                                   // Caps_Lock
        0xff61 => (0x2c, true),                                    // Print
        0xff13 => (0x13, false),                                   // Pause
        0xffbe..=0xffc9 => ((0x70 + (ks - 0xffbe)) as u16, false), // F1..F12
        0x20 => (0x20, false),
        _ => return None,
    })
}

impl InputInjector for SendInputInjector {
    fn key(&mut self, ev: KeyEvent) -> Result<()> {
        let up = if ev.down { 0 } else { KEYEVENTF_KEYUP };
        if let Some((vk, ext)) = keysym_to_vk(ev.keysym) {
            // SAFETY: MapVirtualKeyW sem pre-condicoes.
            let scan = unsafe { MapVirtualKeyW(u32::from(vk), MAPVK_VK_TO_VSC) } as u16;
            let flags = up | if ext { KEYEVENTF_EXTENDEDKEY } else { 0 };
            return send(&[key_input(vk, scan, flags)]);
        }
        // Latin-1 direto ou keysym Unicode (0x01000000 + cp)
        let cp = match ev.keysym {
            k @ 0x20..=0xff => k,
            k if k & 0xff00_0000 == 0x0100_0000 => k & 0x00ff_ffff,
            _ => return Ok(()), // keysym desconhecido: ignora
        };
        let Some(c) = char::from_u32(cp) else {
            return Ok(());
        };
        let mut units = [0u16; 2];
        let units = c.encode_utf16(&mut units);
        if units.len() == 1 {
            // tecla real do layout atual quando existir (atalhos com Ctrl funcionam)
            // SAFETY: VkKeyScanW sem pre-condicoes.
            let r = unsafe { VkKeyScanW(units[0]) };
            if r != -1 && (r >> 8) & 0x6 == 0 {
                let vk = (r & 0xff) as u16;
                // SAFETY: idem.
                let scan = unsafe { MapVirtualKeyW(u32::from(vk), MAPVK_VK_TO_VSC) } as u16;
                return send(&[key_input(vk, scan, up)]);
            }
        }
        let v: Vec<INPUT> = units
            .iter()
            .map(|u| key_input(0, *u, KEYEVENTF_UNICODE | up))
            .collect();
        send(&v)
    }

    fn pointer(&mut self, ev: PointerEvent) -> Result<()> {
        // coordenadas RFB sao relativas a area virtual capturada, que e
        // exatamente o espaco 0..65535 de MOUSEEVENTF_VIRTUALDESK
        // Com um monitor so, desloca para a posicao dele na area virtual
        let (vx, vy, vw, vh) = virtual_screen();
        let (ox, oy) = VIEW
            .lock()
            .ok()
            .and_then(|v| *v)
            .map_or((0, 0), |(x, y)| (x - vx, y - vy));
        let norm =
            |v: i32, span: i32| ((i64::from(v) * 65535) / i64::from((span - 1).max(1))) as i32;
        let mut v = vec![mouse_input(
            norm(i32::from(ev.x) + ox, vw),
            norm(i32::from(ev.y) + oy, vh),
            0,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
        )];
        for (b, down) in button_changes(self.buttons, ev.buttons) {
            let f = match (b, down) {
                (0, true) => MOUSEEVENTF_LEFTDOWN,
                (0, false) => MOUSEEVENTF_LEFTUP,
                (1, true) => MOUSEEVENTF_MIDDLEDOWN,
                (1, false) => MOUSEEVENTF_MIDDLEUP,
                (2, true) => MOUSEEVENTF_RIGHTDOWN,
                (2, false) => MOUSEEVENTF_RIGHTUP,
                (3, true) => {
                    v.push(mouse_input(0, 0, 120, MOUSEEVENTF_WHEEL));
                    continue;
                }
                (4, true) => {
                    v.push(mouse_input(0, 0, -120, MOUSEEVENTF_WHEEL));
                    continue;
                }
                _ => continue,
            };
            v.push(mouse_input(0, 0, 0, f));
        }
        self.buttons = ev.buttons;
        send(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keysym_table() {
        assert_eq!(keysym_to_vk(0xff0d), Some((0x0d, false)));
        assert_eq!(keysym_to_vk(0xffc9), Some((0x7b, false))); // F12
        assert_eq!(keysym_to_vk(0x61), None);
    }
}
