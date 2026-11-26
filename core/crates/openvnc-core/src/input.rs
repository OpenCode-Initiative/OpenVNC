//! Eventos de entrada do cliente.

/// Evento de teclado (keysym X11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// Tecla pressionada (true) ou solta.
    pub down: bool,
    /// Keysym X11.
    pub keysym: u32,
}

/// Evento de ponteiro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerEvent {
    /// Mascara de botoes: bit0 esquerdo, bit1 meio, bit2 direito,
    /// bit3/bit4 roda para cima/baixo.
    pub buttons: u8,
    /// X.
    pub x: u16,
    /// Y.
    pub y: u16,
}

/// Keysyms X11 usados pelo cliente.
pub mod keysym {
    #![allow(missing_docs)]
    pub const BACKSPACE: u32 = 0xff08;
    pub const TAB: u32 = 0xff09;
    pub const RETURN: u32 = 0xff0d;
    pub const ESCAPE: u32 = 0xff1b;
    pub const HOME: u32 = 0xff50;
    pub const LEFT: u32 = 0xff51;
    pub const UP: u32 = 0xff52;
    pub const RIGHT: u32 = 0xff53;
    pub const DOWN: u32 = 0xff54;
    pub const PAGE_UP: u32 = 0xff55;
    pub const PAGE_DOWN: u32 = 0xff56;
    pub const END: u32 = 0xff57;
    pub const INSERT: u32 = 0xff63;
    pub const DELETE: u32 = 0xffff;
    pub const F1: u32 = 0xffbe;
    pub const SHIFT_L: u32 = 0xffe1;
    pub const CONTROL_L: u32 = 0xffe3;
    pub const ALT_L: u32 = 0xffe9;
    pub const SUPER_L: u32 = 0xffeb;

    /// Keysym de um caractere Unicode (Latin-1 direto; demais 0x0100_0000 + U).
    pub fn from_char(c: char) -> u32 {
        let u = c as u32;
        match u {
            0x20..=0x7e | 0xa0..=0xff => u,
            _ => 0x0100_0000 + u,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn keysym_from_char() {
        assert_eq!(super::keysym::from_char('a'), 0x61);
        assert_eq!(super::keysym::from_char('é'), 0xe9);
        assert_eq!(super::keysym::from_char('€'), 0x0100_20ac);
    }
}
