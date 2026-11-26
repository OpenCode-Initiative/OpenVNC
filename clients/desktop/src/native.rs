//! Renderer nativo (`OPENVNC_RENDERER=native`): janela winit e blit em
//! software com softbuffer (GDI no Windows, X11/Wayland SHM no Linux),
//! sem contexto OpenGL. Ver `docs/renderer-proprio.md`.
//!
//! So desenha quando ha damage; com a tela remota parada a CPU fica em ~0%.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::Arc;

use openvnc_client::{Command, ConnectOptions, Session, SessionEvent};
use openvnc_core::input::keysym;
use openvnc_core::{KeyEvent, PointerEvent, Rect};
use openvnc_framebuffer::Framebuffer;
use winit::application::ApplicationHandler;
use winit::dpi::PhysicalPosition;
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy};
use winit::keyboard::{Key, NamedKey, PhysicalKey};
use winit::window::{CustomCursor, Window, WindowId};

/// Destino de apresentacao do framebuffer remoto.
pub trait Presenter {
    /// A janela mudou de tamanho (pixels fisicos).
    fn resize(&mut self, w: u32, h: u32);
    /// Desenha `damage` (coordenadas remotas); `full` redesenha tudo.
    fn present(&mut self, fb: &Framebuffer, damage: &[Rect], full: bool) -> anyhow::Result<()>;
    /// Converte uma posicao da janela em coordenadas remotas.
    fn to_remote(&self, x: f64, y: f64, fb_w: u16, fb_h: u16) -> Option<(u16, u16)>;
}

/// Escala "Fit" com barras pretas: `dst = off + src * k`.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Fit {
    k: f64,
    ox: f64,
    oy: f64,
}

fn fit(win: (u32, u32), fb: (u16, u16)) -> Fit {
    let (fw, fh) = (f64::from(fb.0.max(1)), f64::from(fb.1.max(1)));
    let (ww, wh) = (f64::from(win.0), f64::from(win.1));
    let mut k = (ww / fw).min(wh / fh);
    // 1:1 quando cabe: evita reamostrar (e mantem o texto nitido)
    if k >= 1.0 {
        k = 1.0;
    }
    Fit {
        k,
        ox: ((ww - fw * k) / 2.0).floor(),
        oy: ((wh - fh * k) / 2.0).floor(),
    }
}

/// Presenter em software via softbuffer.
pub struct SoftPresenter {
    surface: softbuffer::Surface<Rc<Window>, Rc<Window>>,
    size: (u32, u32),
}

impl SoftPresenter {
    fn new(window: Rc<Window>) -> anyhow::Result<Self> {
        let ctx = softbuffer::Context::new(window.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let surface =
            softbuffer::Surface::new(&ctx, window.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let s = window.inner_size();
        let mut p = SoftPresenter {
            surface,
            size: (0, 0),
        };
        p.resize(s.width, s.height);
        Ok(p)
    }
}

impl Presenter for SoftPresenter {
    fn resize(&mut self, w: u32, h: u32) {
        if let (Some(nw), Some(nh)) = (NonZeroU32::new(w), NonZeroU32::new(h)) {
            if self.surface.resize(nw, nh).is_ok() {
                self.size = (w, h);
            }
        }
    }

    fn present(&mut self, fb: &Framebuffer, damage: &[Rect], full: bool) -> anyhow::Result<()> {
        let (ww, wh) = self.size;
        if ww == 0 || wh == 0 {
            return Ok(());
        }
        let f = fit(self.size, (fb.width(), fb.height()));
        let mut buf = self
            .surface
            .buffer_mut()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        // age 0 = conteudo anterior perdido
        let full = full || buf.age() == 0;
        let all = [Rect::new(0, 0, fb.width(), fb.height())];
        let src_rects: &[Rect] = if full { &all } else { damage };
        if full {
            buf.fill(0);
        }
        let mut out = Vec::with_capacity(src_rects.len());
        for r in src_rects {
            let r = r.clip_to(fb.width(), fb.height());
            if r.is_empty() {
                continue;
            }
            // retangulo destino (arredondado para fora)
            let x0 = (f.ox + f64::from(r.x) * f.k).floor().max(0.0) as u32;
            let y0 = (f.oy + f64::from(r.y) * f.k).floor().max(0.0) as u32;
            let x1 = ((f.ox + f64::from(r.x + r.width) * f.k).ceil() as u32).min(ww);
            let y1 = ((f.oy + f64::from(r.y + r.height) * f.k).ceil() as u32).min(wh);
            if x1 <= x0 || y1 <= y0 {
                continue;
            }
            blit(fb, &f, &mut buf, ww, (x0, y0, x1, y1));
            out.push(softbuffer::Rect {
                x: x0,
                y: y0,
                width: NonZeroU32::new(x1 - x0).expect(">0"),
                height: NonZeroU32::new(y1 - y0).expect(">0"),
            });
        }
        if full {
            buf.present().map_err(|e| anyhow::anyhow!("{e}"))
        } else if out.is_empty() {
            Ok(())
        } else {
            buf.present_with_damage(&out)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
    }

    fn to_remote(&self, x: f64, y: f64, fb_w: u16, fb_h: u16) -> Option<(u16, u16)> {
        let f = fit(self.size, (fb_w, fb_h));
        let rx = (x - f.ox) / f.k;
        let ry = (y - f.oy) / f.k;
        if rx < 0.0 || ry < 0.0 || rx >= f64::from(fb_w) || ry >= f64::from(fb_h) {
            return None;
        }
        Some((rx as u16, ry as u16))
    }
}

/// Copia (vizinho mais proximo) a regiao destino `(x0, y0, x1, y1)`.
fn blit(fb: &Framebuffer, f: &Fit, buf: &mut [u32], stride: u32, d: (u32, u32, u32, u32)) {
    let (x0, y0, x1, y1) = d;
    let data = fb.data();
    let (fw, fh) = (usize::from(fb.width()), usize::from(fb.height()));
    // coluna de origem para cada coluna destino
    let cols: Vec<Option<usize>> = (x0..x1)
        .map(|x| {
            let sx = (f64::from(x) + 0.5 - f.ox) / f.k;
            (sx >= 0.0 && (sx as usize) < fw).then_some(sx as usize * 4)
        })
        .collect();
    for y in y0..y1 {
        let sy = (f64::from(y) + 0.5 - f.oy) / f.k;
        if sy < 0.0 || sy as usize >= fh {
            continue;
        }
        let src = &data[sy as usize * fb.stride()..];
        let row = &mut buf[(y * stride) as usize..];
        for (x, c) in (x0..x1).zip(&cols) {
            if let Some(o) = *c {
                let p = &src[o..o + 3];
                row[x as usize] = u32::from(p[0]) << 16 | u32::from(p[1]) << 8 | u32::from(p[2]);
            }
        }
    }
}

/// Keysym para uma tecla do winit (None = ignorar).
fn key_to_keysym(key: &Key) -> Option<u32> {
    use keysym::*;
    Some(match key {
        Key::Named(n) => match n {
            NamedKey::Backspace => BACKSPACE,
            NamedKey::Tab => TAB,
            NamedKey::Enter => RETURN,
            NamedKey::Escape => ESCAPE,
            NamedKey::Home => HOME,
            NamedKey::End => END,
            NamedKey::PageUp => PAGE_UP,
            NamedKey::PageDown => PAGE_DOWN,
            NamedKey::Insert => INSERT,
            NamedKey::Delete => DELETE,
            NamedKey::ArrowLeft => LEFT,
            NamedKey::ArrowUp => UP,
            NamedKey::ArrowRight => RIGHT,
            NamedKey::ArrowDown => DOWN,
            NamedKey::Shift => SHIFT_L,
            NamedKey::Control => CONTROL_L,
            NamedKey::Alt => ALT_L,
            NamedKey::Super => SUPER_L,
            NamedKey::Space => 0x20,
            NamedKey::F1 => F1,
            NamedKey::F2 => F1 + 1,
            NamedKey::F3 => F1 + 2,
            NamedKey::F4 => F1 + 3,
            NamedKey::F5 => F1 + 4,
            NamedKey::F6 => F1 + 5,
            NamedKey::F7 => F1 + 6,
            NamedKey::F8 => F1 + 7,
            NamedKey::F9 => F1 + 8,
            NamedKey::F10 => F1 + 9,
            NamedKey::F11 => F1 + 10,
            NamedKey::F12 => F1 + 11,
            _ => return None,
        },
        Key::Character(s) => {
            let mut it = s.chars();
            let c = it.next()?;
            if it.next().is_some() {
                return None;
            }
            let cp = u32::from(c);
            match cp {
                // Ctrl+letra pode chegar como caractere de controle
                0x01..=0x1a => cp + 0x60,
                0x00..=0x1f | 0x7f => return None,
                0x20..=0xff => cp,
                _ => 0x0100_0000 | cp,
            }
        }
        _ => return None,
    })
}

enum UserEvent {
    Wake,
}

struct App {
    rt: tokio::runtime::Runtime,
    opts: Option<ConnectOptions>,
    proxy: EventLoopProxy<UserEvent>,
    window: Option<Rc<Window>>,
    presenter: Option<SoftPresenter>,
    session: Option<Session>,
    generation: u64,
    damage: Vec<Rect>,
    full: bool,
    pressed: HashMap<PhysicalKey, u32>,
    buttons: u8,
    pos: (u16, u16),
    title: String,
    error: Option<String>,
}

impl App {
    fn send_ptr(&self, buttons: u8) {
        if let Some(s) = &self.session {
            let (x, y) = self.pos;
            s.send(Command::Pointer(PointerEvent { buttons, x, y }));
        }
    }

    fn release_all(&mut self) {
        let Some(s) = &self.session else { return };
        for (_, ks) in self.pressed.drain() {
            s.send(Command::Key(KeyEvent {
                down: false,
                keysym: ks,
            }));
        }
    }

    fn fb_size(&self) -> Option<(u16, u16)> {
        let s = self.session.as_ref()?;
        let f = s.frame().lock().expect("mutex");
        f.fb.as_ref().map(|fb| (fb.width(), fb.height()))
    }

    fn pump(&mut self, el: &ActiveEventLoop) {
        let Some(s) = &self.session else { return };
        let window = self.window.clone().expect("janela");
        while let Some(e) = s.try_event() {
            match e {
                SessionEvent::Connected {
                    name,
                    width,
                    height,
                    ..
                } => {
                    self.title = format!("OpenVNC — {name} ({width}x{height})");
                    window.set_title(&self.title);
                    self.full = true;
                }
                SessionEvent::Resized { width, height } => {
                    tracing::info!(width, height, "redimensionado");
                    self.full = true;
                }
                SessionEvent::Cursor {
                    hot_x,
                    hot_y,
                    width,
                    height,
                    rgba,
                } => {
                    if width == 0 || height == 0 {
                        continue;
                    }
                    match CustomCursor::from_rgba(rgba, width, height, hot_x, hot_y) {
                        Ok(src) => window.set_cursor(el.create_custom_cursor(src)),
                        Err(e) => tracing::debug!(%e, "cursor recusado"),
                    }
                }
                SessionEvent::Disconnected { reason, retrying } => {
                    window.set_title(&format!("OpenVNC — {reason}"));
                    if !retrying {
                        self.error = Some(reason);
                        el.exit();
                    }
                }
                SessionEvent::Updated | SessionEvent::Bell | SessionEvent::CutText(_) => {}
            }
        }
        // junta o damage pendente
        let mut f = s.frame().lock().expect("mutex");
        if f.generation != self.generation {
            self.generation = f.generation;
            self.full = true;
        }
        self.damage.append(&mut f.damage);
        drop(f);
        if self.full || !self.damage.is_empty() {
            window.request_redraw();
        }
    }

    fn redraw(&mut self) {
        let (Some(s), Some(p)) = (&self.session, self.presenter.as_mut()) else {
            return;
        };
        let f = s.frame().lock().expect("mutex");
        let Some(fb) = f.fb.as_ref() else { return };
        if let Err(e) = p.present(fb, &self.damage, self.full) {
            tracing::warn!(%e, "falha ao apresentar");
        }
        drop(f);
        self.damage.clear();
        self.full = false;
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let attrs = Window::default_attributes()
            .with_title("OpenVNC")
            .with_inner_size(winit::dpi::LogicalSize::new(1024.0, 768.0));
        let window = match el.create_window(attrs) {
            Ok(w) => Rc::new(w),
            Err(e) => {
                self.error = Some(format!("janela: {e}"));
                el.exit();
                return;
            }
        };
        match SoftPresenter::new(window.clone()) {
            Ok(p) => self.presenter = Some(p),
            Err(e) => {
                self.error = Some(format!("softbuffer: {e}"));
                el.exit();
                return;
            }
        }
        self.window = Some(window);
        if let Some(o) = self.opts.take() {
            let proxy = self.proxy.clone();
            let notify = Arc::new(move || {
                let _ = proxy.send_event(UserEvent::Wake);
            });
            self.session = Some(Session::spawn(self.rt.handle(), o, notify));
        }
    }

    fn user_event(&mut self, el: &ActiveEventLoop, _: UserEvent) {
        self.pump(el);
    }

    fn window_event(&mut self, el: &ActiveEventLoop, _: WindowId, ev: WindowEvent) {
        match ev {
            WindowEvent::CloseRequested => {
                self.release_all();
                el.exit();
            }
            WindowEvent::Resized(s) => {
                if let Some(p) = self.presenter.as_mut() {
                    p.resize(s.width, s.height);
                }
                self.full = true;
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
            WindowEvent::RedrawRequested => self.redraw(),
            WindowEvent::Focused(false) => self.release_all(),
            WindowEvent::CursorMoved {
                position: PhysicalPosition { x, y },
                ..
            } => {
                let (Some(p), Some((w, h))) = (self.presenter.as_ref(), self.fb_size()) else {
                    return;
                };
                if let Some(pos) = p.to_remote(x, y, w, h) {
                    self.pos = pos;
                    self.send_ptr(self.buttons);
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let bit = match button {
                    MouseButton::Left => 1,
                    MouseButton::Middle => 2,
                    MouseButton::Right => 4,
                    _ => return,
                };
                if state == ElementState::Pressed {
                    self.buttons |= bit;
                } else {
                    self.buttons &= !bit;
                }
                self.send_ptr(self.buttons);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let dy = match delta {
                    MouseScrollDelta::LineDelta(_, y) => f64::from(y),
                    MouseScrollDelta::PixelDelta(p) => p.y,
                };
                if dy != 0.0 {
                    self.send_ptr(self.buttons | if dy > 0.0 { 8 } else { 16 });
                    self.send_ptr(self.buttons);
                }
            }
            WindowEvent::KeyboardInput { event, .. } => {
                let Some(s) = &self.session else { return };
                match event.state {
                    ElementState::Pressed => {
                        let Some(ks) = key_to_keysym(&event.logical_key) else {
                            return;
                        };
                        // a soltura usa o mesmo keysym do aperto
                        self.pressed.insert(event.physical_key, ks);
                        s.send(Command::Key(KeyEvent {
                            down: true,
                            keysym: ks,
                        }));
                    }
                    ElementState::Released => {
                        if let Some(ks) = self.pressed.remove(&event.physical_key) {
                            s.send(Command::Key(KeyEvent {
                                down: false,
                                keysym: ks,
                            }));
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Roda o cliente com o renderer nativo ate a janela fechar.
pub fn run(opts: ConnectOptions) -> anyhow::Result<()> {
    let el = EventLoop::<UserEvent>::with_user_event().build()?;
    let mut app = App {
        rt: tokio::runtime::Runtime::new()?,
        opts: Some(opts),
        proxy: el.create_proxy(),
        window: None,
        presenter: None,
        session: None,
        generation: 0,
        damage: Vec::new(),
        full: true,
        pressed: HashMap::new(),
        buttons: 0,
        pos: (0, 0),
        title: String::new(),
        error: None,
    };
    el.run_app(&mut app)?;
    match app.error {
        Some(e) => anyhow::bail!(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_letterbox_and_one_to_one() {
        assert_eq!(
            fit((1024, 768), (800, 600)),
            Fit {
                k: 1.0,
                ox: 112.0,
                oy: 84.0
            }
        );
        let f = fit((400, 400), (800, 600));
        assert_eq!(f.k, 0.5);
        assert_eq!((f.ox, f.oy), (0.0, 50.0));
    }

    #[test]
    fn blit_scales_nearest() {
        let mut fb = Framebuffer::new(4, 2, openvnc_framebuffer::DEFAULT_MAX_BYTES).unwrap();
        fb.fill_rect(Rect::new(0, 0, 2, 2), [255, 0, 0, 255]);
        fb.fill_rect(Rect::new(2, 0, 2, 2), [0, 0, 255, 255]);
        let f = fit((2, 1), (4, 2));
        let mut buf = vec![0u32; 2];
        blit(&fb, &f, &mut buf, 2, (0, 0, 2, 1));
        assert_eq!(buf, vec![0xff0000, 0x0000ff]);
    }

    #[test]
    fn keysyms() {
        assert_eq!(key_to_keysym(&Key::Character("a".into())), Some(0x61));
        assert_eq!(key_to_keysym(&Key::Character("\u{1}".into())), Some(0x61));
        assert_eq!(key_to_keysym(&Key::Character("é".into())), Some(0xe9));
        assert_eq!(
            key_to_keysym(&Key::Character("€".into())),
            Some(0x0100_20ac)
        );
        assert_eq!(
            key_to_keysym(&Key::Named(NamedKey::Enter)),
            Some(keysym::RETURN)
        );
        assert_eq!(
            key_to_keysym(&Key::Named(NamedKey::Shift)),
            Some(keysym::SHIFT_L)
        );
    }
}
