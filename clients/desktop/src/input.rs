//! Traducao de eventos de teclado do egui para keysyms X11.

use eframe::egui::{self, Key, Modifiers};
use openvnc_core::input::keysym;
use openvnc_core::KeyEvent;

/// Estado de modificadores ja enviados ao servidor.
#[derive(Default)]
pub struct KeyState {
    shift: bool,
    ctrl: bool,
    alt: bool,
}

fn named(key: Key) -> Option<u32> {
    use keysym::*;
    Some(match key {
        Key::Backspace => BACKSPACE,
        Key::Tab => TAB,
        Key::Enter => RETURN,
        Key::Escape => ESCAPE,
        Key::Home => HOME,
        Key::End => END,
        Key::PageUp => PAGE_UP,
        Key::PageDown => PAGE_DOWN,
        Key::Insert => INSERT,
        Key::Delete => DELETE,
        Key::ArrowLeft => LEFT,
        Key::ArrowUp => UP,
        Key::ArrowRight => RIGHT,
        Key::ArrowDown => DOWN,
        Key::F1 => F1,
        Key::F2 => F1 + 1,
        Key::F3 => F1 + 2,
        Key::F4 => F1 + 3,
        Key::F5 => F1 + 4,
        Key::F6 => F1 + 5,
        Key::F7 => F1 + 6,
        Key::F8 => F1 + 7,
        Key::F9 => F1 + 8,
        Key::F10 => F1 + 9,
        Key::F11 => F1 + 10,
        Key::F12 => F1 + 11,
        _ => return None,
    })
}

/// Tecla alfanumerica como keysym (usada quando Ctrl/Alt suprimem `Text`).
fn plain(key: Key) -> Option<u32> {
    let name = key.name();
    let mut chars = name.chars();
    let c = chars.next()?;
    if chars.next().is_some() || !c.is_ascii_alphanumeric() {
        return None;
    }
    Some(u32::from(c.to_ascii_lowercase()))
}

impl KeyState {
    /// Converte os eventos de um quadro em KeyEvents RFB.
    pub fn translate(&mut self, events: &[egui::Event], mods: Modifiers) -> Vec<KeyEvent> {
        let mut out = Vec::new();
        self.sync_mods(mods, &mut out);
        for ev in events {
            match ev {
                egui::Event::Text(t) => {
                    for c in t.chars() {
                        let ks = keysym::from_char(c);
                        out.push(KeyEvent {
                            down: true,
                            keysym: ks,
                        });
                        out.push(KeyEvent {
                            down: false,
                            keysym: ks,
                        });
                    }
                }
                egui::Event::Key {
                    key,
                    pressed,
                    modifiers,
                    ..
                } => {
                    if let Some(ks) = named(*key) {
                        out.push(KeyEvent {
                            down: *pressed,
                            keysym: ks,
                        });
                    } else if modifiers.ctrl
                        || modifiers.alt
                        || modifiers.command && !modifiers.mac_cmd
                    {
                        if let Some(ks) = plain(*key) {
                            out.push(KeyEvent {
                                down: *pressed,
                                keysym: ks,
                            });
                        }
                    }
                }
                egui::Event::Copy => {
                    // Ctrl+C e consumido pelo egui como Copy
                    self.ctrl_combo(u32::from(b'c'), &mut out);
                }
                egui::Event::Cut => self.ctrl_combo(u32::from(b'x'), &mut out),
                egui::Event::Paste(t) => {
                    for c in t.chars() {
                        let ks = keysym::from_char(c);
                        out.push(KeyEvent {
                            down: true,
                            keysym: ks,
                        });
                        out.push(KeyEvent {
                            down: false,
                            keysym: ks,
                        });
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn ctrl_combo(&mut self, ks: u32, out: &mut Vec<KeyEvent>) {
        out.push(KeyEvent {
            down: true,
            keysym: ks,
        });
        out.push(KeyEvent {
            down: false,
            keysym: ks,
        });
    }

    fn sync_mods(&mut self, m: Modifiers, out: &mut Vec<KeyEvent>) {
        for (cur, want, ks) in [
            (&mut self.shift, m.shift, keysym::SHIFT_L),
            (&mut self.ctrl, m.ctrl, keysym::CONTROL_L),
            (&mut self.alt, m.alt, keysym::ALT_L),
        ] {
            if *cur != want {
                *cur = want;
                out.push(KeyEvent {
                    down: want,
                    keysym: ks,
                });
            }
        }
    }

    /// Solta modificadores pressionados (ao perder foco).
    pub fn release_all(&mut self) -> Vec<KeyEvent> {
        let mut out = Vec::new();
        self.sync_mods(Modifiers::NONE, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(k: Key, pressed: bool, modifiers: Modifiers) -> egui::Event {
        egui::Event::Key {
            key: k,
            physical_key: None,
            pressed,
            repeat: false,
            modifiers,
        }
    }

    fn ev(down: bool, keysym: u32) -> KeyEvent {
        KeyEvent { down, keysym }
    }

    #[test]
    fn texto_vira_down_up_por_caractere() {
        let mut st = KeyState::default();
        let out = st.translate(&[egui::Event::Text("aÉ!".into())], Modifiers::NONE);
        assert_eq!(
            out,
            vec![
                ev(true, 'a' as u32),
                ev(false, 'a' as u32),
                ev(true, 0xc9),
                ev(false, 0xc9),
                ev(true, '!' as u32),
                ev(false, '!' as u32),
            ]
        );
    }

    #[test]
    fn teclas_especiais_respeitam_pressed() {
        let mut st = KeyState::default();
        let out = st.translate(
            &[
                key(Key::Enter, true, Modifiers::NONE),
                key(Key::Enter, false, Modifiers::NONE),
                key(Key::ArrowLeft, true, Modifiers::NONE),
                key(Key::Backspace, true, Modifiers::NONE),
            ],
            Modifiers::NONE,
        );
        assert_eq!(
            out,
            vec![
                ev(true, keysym::RETURN),
                ev(false, keysym::RETURN),
                ev(true, keysym::LEFT),
                ev(true, keysym::BACKSPACE),
            ]
        );
    }

    #[test]
    fn letra_sem_modificador_nao_duplica_text() {
        // sem Ctrl/Alt a letra chega via Event::Text; o Key e ignorado
        let mut st = KeyState::default();
        let out = st.translate(&[key(Key::A, true, Modifiers::NONE)], Modifiers::NONE);
        assert!(out.is_empty());
    }

    #[test]
    fn ctrl_letra_envia_modificador_e_minuscula() {
        let mut st = KeyState::default();
        let out = st.translate(
            &[
                key(Key::A, true, Modifiers::CTRL),
                key(Key::A, false, Modifiers::CTRL),
            ],
            Modifiers::CTRL,
        );
        assert_eq!(
            out,
            vec![
                ev(true, keysym::CONTROL_L),
                ev(true, 'a' as u32),
                ev(false, 'a' as u32),
            ]
        );
        // soltar Ctrl no quadro seguinte
        let out = st.translate(&[], Modifiers::NONE);
        assert_eq!(out, vec![ev(false, keysym::CONTROL_L)]);
    }

    #[test]
    fn copy_do_egui_vira_ctrl_c() {
        let mut st = KeyState::default();
        let out = st.translate(&[egui::Event::Copy], Modifiers::CTRL);
        assert_eq!(
            out,
            vec![
                ev(true, keysym::CONTROL_L),
                ev(true, 'c' as u32),
                ev(false, 'c' as u32),
            ]
        );
    }

    #[test]
    fn modificadores_nao_repetem_e_soltam_ao_perder_foco() {
        let mut st = KeyState::default();
        let m = Modifiers {
            shift: true,
            alt: true,
            ..Modifiers::NONE
        };
        let first = st.translate(&[], m);
        assert_eq!(
            first,
            vec![ev(true, keysym::SHIFT_L), ev(true, keysym::ALT_L)]
        );
        assert!(st.translate(&[], m).is_empty());
        let rel = st.release_all();
        assert_eq!(
            rel,
            vec![ev(false, keysym::SHIFT_L), ev(false, keysym::ALT_L)]
        );
        assert!(st.release_all().is_empty());
    }
}
