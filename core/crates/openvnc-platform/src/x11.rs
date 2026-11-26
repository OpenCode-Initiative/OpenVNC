//! Backend Linux X11: captura com `GetImage` e entrada com XTest.
//!
//! Usa o x11rb em Rust puro. Com a extensao Damage, so o retangulo
//! envolvente das areas alteradas e lido a cada quadro; sem ela, cai para a
//! copia completa. Com MIT-SHM 1.2, o servidor X escreve os pixels num
//! segmento compartilhado (`ShmCreateSegment` + `mmap`), evitando copiar a
//! imagem pelo socket; sem a extensao (ou em X remoto), usa `GetImage`.

use openvnc_core::{Error, KeyEvent, PointerEvent, Result};
use openvnc_framebuffer::Framebuffer;
use x11rb::connection::Connection;
use x11rb::protocol::damage::{ConnectionExt as _, ReportLevel};
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, Window};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;

use crate::{button_changes, InputInjector, ScreenCapture};

fn err(e: impl std::fmt::Display) -> Error {
    Error::Unsupported(format!("X11: {e}"))
}

/// Captura da janela raiz do X.
pub struct X11Capture {
    conn: RustConnection,
    root: Window,
    w: u16,
    h: u16,
    /// Deslocamentos (bytes) de R, G e B num pixel de 32 bits.
    order: [usize; 3],
    row: Vec<[u8; 4]>,
    /// Objeto Damage na raiz, se a extensao existe.
    damage: Option<u32>,
    /// Proximo quadro precisa ser completo.
    full: bool,
    /// Segmento MIT-SHM do tamanho da tela, se disponivel.
    shm: Option<Shm>,
}

/// Segmento MIT-SHM mapeado neste processo.
struct Shm {
    seg: u32,
    map: memmap2::Mmap,
}

impl Shm {
    /// Cria um segmento de `size` bytes no servidor X e o mapeia (MIT-SHM 1.2).
    fn new(conn: &RustConnection, size: usize) -> Option<Shm> {
        let v = conn.shm_query_version().ok()?.reply().ok()?;
        if (v.major_version, v.minor_version) < (1, 2) {
            return None;
        }
        let seg = conn.generate_id().ok()?;
        let r = conn
            .shm_create_segment(seg, u32::try_from(size).ok()?, true)
            .ok()?
            .reply()
            .ok()?;
        // SAFETY: o fd e um segmento de memoria anonima de `size` bytes
        // criado pelo servidor X para este cliente. O mapeamento e somente
        // leitura e so e lido depois que o ShmGetImage correspondente
        // respondeu, quando o servidor ja terminou de escrever.
        #[allow(unsafe_code)]
        let map = unsafe { memmap2::MmapOptions::new().len(size).map(&r.shm_fd) };
        match map {
            Ok(map) => Some(Shm { seg, map }),
            Err(e) => {
                tracing::info!("mmap do segmento MIT-SHM falhou: {e}");
                let _ = conn.shm_detach(seg);
                None
            }
        }
    }
}

impl X11Capture {
    /// Conecta ao `$DISPLAY`.
    pub fn new() -> Result<Self> {
        let (conn, n) = x11rb::connect(None).map_err(err)?;
        let screen = &conn.setup().roots[n];
        let (root, w, h) = (screen.root, screen.width_in_pixels, screen.height_in_pixels);
        let visual = screen
            .allowed_depths
            .iter()
            .flat_map(|d| d.visuals.iter())
            .find(|v| v.visual_id == screen.root_visual)
            .ok_or_else(|| err("visual raiz ausente"))?;
        let lsb = conn.setup().image_byte_order == x11rb::protocol::xproto::ImageOrder::LSB_FIRST;
        let idx = |mask: u32| {
            let byte = (mask.trailing_zeros() / 8) as usize;
            if lsb {
                byte
            } else {
                3 - byte
            }
        };
        let order = [
            idx(visual.red_mask),
            idx(visual.green_mask),
            idx(visual.blue_mask),
        ];
        let bpp = conn
            .setup()
            .pixmap_formats
            .iter()
            .find(|f| f.depth == screen.root_depth)
            .map(|f| f.bits_per_pixel)
            .unwrap_or(0);
        if bpp != 32 {
            return Err(err(format!("profundidade nao suportada: {bpp} bpp")));
        }
        let damage = Self::init_damage(&conn, root);
        if damage.is_none() {
            tracing::info!("extensao Damage ausente; captura completa a cada quadro");
        }
        let shm = Self::local()
            .then(|| Shm::new(&conn, usize::from(w) * usize::from(h) * 4))
            .flatten();
        tracing::info!(shm = shm.is_some(), "captura X11");
        Ok(X11Capture {
            conn,
            root,
            w,
            h,
            order,
            row: vec![[0; 4]; usize::from(w)],
            damage,
            full: true,
            shm,
        })
    }

    /// MIT-SHM e opt-in (`OPENVNC_X11_SHM=1`) e so com o servidor X local:
    /// no Xvfb gastou mais CPU que GetImage (ver TD-004).
    fn local() -> bool {
        if std::env::var_os("OPENVNC_X11_SHM").is_none_or(|v| v != "1") {
            return false;
        }
        let d = std::env::var("DISPLAY").unwrap_or_default();
        d.starts_with(':') || d.starts_with("unix:") || d.starts_with('/')
    }

    fn init_damage(conn: &RustConnection, root: Window) -> Option<u32> {
        let ok = conn
            .damage_query_version(1, 1)
            .ok()
            .and_then(|c| c.reply().ok())
            .is_some();
        if !ok {
            return None;
        }
        let id = conn.generate_id().ok()?;
        conn.damage_create(id, root, ReportLevel::BOUNDING_BOX)
            .ok()?
            .check()
            .ok()?;
        Some(id)
    }

    /// Uniao dos retangulos danificados desde a ultima chamada.
    fn drain_damage(&mut self) -> Result<Option<(u16, u16, u16, u16)>> {
        let mut acc: Option<(i32, i32, i32, i32)> = None;
        while let Some(ev) = self.conn.poll_for_event().map_err(err)? {
            if let Event::DamageNotify(d) = ev {
                let a = d.area;
                let r = (
                    i32::from(a.x),
                    i32::from(a.y),
                    i32::from(a.x) + i32::from(a.width),
                    i32::from(a.y) + i32::from(a.height),
                );
                acc = Some(match acc {
                    None => r,
                    Some(b) => (b.0.min(r.0), b.1.min(r.1), b.2.max(r.2), b.3.max(r.3)),
                });
            }
        }
        if let (Some(id), Some(_)) = (self.damage, acc) {
            // zera a regiao acumulada no servidor para voltar a notificar
            self.conn
                .damage_subtract(id, x11rb::NONE, x11rb::NONE)
                .map_err(err)?;
        }
        Ok(acc.and_then(|(x0, y0, x1, y1)| clip(x0, y0, x1, y1, self.w, self.h)))
    }
}

impl X11Capture {
    /// Le um retangulo pelo segmento MIT-SHM. `false` se precisa de fallback.
    fn fetch_shm(&mut self, fb: &mut Framebuffer, x: u16, y: u16, w: u16, h: u16) -> Result<bool> {
        let Some(shm) = &self.shm else {
            return Ok(false);
        };
        let stride = usize::from(w) * 4;
        let need = stride * usize::from(h);
        if need > shm.map.len() {
            return Ok(false);
        }
        let reply = self
            .conn
            .shm_get_image(
                self.root,
                x as i16,
                y as i16,
                w,
                h,
                !0,
                ImageFormat::Z_PIXMAP.into(),
                shm.seg,
                0,
            )
            .map_err(err)?
            .reply();
        if let Err(e) = reply {
            tracing::info!("ShmGetImage falhou ({e}); voltando para GetImage");
            if let Some(s) = self.shm.take() {
                let _ = self.conn.shm_detach(s.seg);
            }
            return Ok(false);
        }
        let row = &mut self.row[..usize::from(w)];
        for (dy, src) in shm.map[..need].chunks_exact(stride).enumerate() {
            for (p, s) in row.iter_mut().zip(src.chunks_exact(4)) {
                *p = [s[self.order[0]], s[self.order[1]], s[self.order[2]], 255];
            }
            fb.put_rgba_row(x, y + dy as u16, row);
        }
        Ok(true)
    }

    /// Le um retangulo com GetImage em faixas de ~4 MiB.
    fn fetch(&mut self, fb: &mut Framebuffer, x: u16, y: u16, w: u16, h: u16) -> Result<()> {
        if self.fetch_shm(fb, x, y, w, h)? {
            return Ok(());
        }
        let stride = usize::from(w) * 4;
        let band = ((4 << 20) / stride.max(1)).clamp(1, usize::from(h).max(1)) as u16;
        let row = &mut self.row[..usize::from(w)];
        let mut y0 = y;
        while y0 < y + h {
            let bh = band.min(y + h - y0);
            let img = self
                .conn
                .get_image(
                    ImageFormat::Z_PIXMAP,
                    self.root,
                    x as i16,
                    y0 as i16,
                    w,
                    bh,
                    !0,
                )
                .map_err(err)?
                .reply()
                .map_err(err)?;
            for (dy, src) in img
                .data
                .chunks_exact(stride)
                .take(usize::from(bh))
                .enumerate()
            {
                for (p, s) in row.iter_mut().zip(src.chunks_exact(4)) {
                    *p = [s[self.order[0]], s[self.order[1]], s[self.order[2]], 255];
                }
                fb.put_rgba_row(x, y0 + dy as u16, row);
            }
            y0 += bh;
        }
        Ok(())
    }
}

/// Recorta `[x0,x1) x [y0,y1)` a tela; `None` se vazio.
fn clip(x0: i32, y0: i32, x1: i32, y1: i32, w: u16, h: u16) -> Option<(u16, u16, u16, u16)> {
    let (x0, y0) = (x0.max(0), y0.max(0));
    let (x1, y1) = (x1.min(i32::from(w)), y1.min(i32::from(h)));
    (x1 > x0 && y1 > y0).then(|| (x0 as u16, y0 as u16, (x1 - x0) as u16, (y1 - y0) as u16))
}

impl ScreenCapture for X11Capture {
    fn size(&self) -> (u16, u16) {
        (self.w, self.h)
    }

    fn capture(&mut self, fb: &mut Framebuffer) -> Result<bool> {
        let geo = self
            .conn
            .get_geometry(self.root)
            .map_err(err)?
            .reply()
            .map_err(err)?;
        if (geo.width, geo.height) != (self.w, self.h) {
            self.full = true;
            self.w = geo.width;
            self.h = geo.height;
            self.row = vec![[0; 4]; usize::from(self.w)];
            if let Some(s) = self.shm.take() {
                let _ = self.conn.shm_detach(s.seg);
                self.shm = Shm::new(&self.conn, usize::from(self.w) * usize::from(self.h) * 4);
            }
            return Ok(false);
        }
        if (fb.width(), fb.height()) != (self.w, self.h) {
            self.full = true;
            return Ok(false);
        }
        let rect = if self.full || self.damage.is_none() {
            self.full = false;
            // descarta eventos antigos: o quadro completo ja os cobre
            let _ = self.drain_damage()?;
            Some((0, 0, self.w, self.h))
        } else {
            self.drain_damage()?
        };
        if let Some((x, y, w, h)) = rect {
            self.fetch(fb, x, y, w, h)?;
        }
        Ok(true)
    }

    fn name(&self) -> &'static str {
        match (self.shm.is_some(), self.damage.is_some()) {
            (true, true) => "x11-shm-damage",
            (true, false) => "x11-shm",
            (false, true) => "x11-damage",
            (false, false) => "x11-getimage",
        }
    }
}

/// Injecao com a extensao XTest.
pub struct XTestInjector {
    conn: RustConnection,
    root: Window,
    min_keycode: u8,
    per: usize,
    map: Vec<u32>,
    buttons: u8,
}

impl XTestInjector {
    /// Conecta ao `$DISPLAY` e carrega o mapa de teclado.
    pub fn new() -> Result<Self> {
        let (conn, n) = x11rb::connect(None).map_err(err)?;
        let root = conn.setup().roots[n].root;
        conn.xtest_get_version(2, 2)
            .map_err(err)?
            .reply()
            .map_err(|_| err("extensao XTest ausente"))?;
        let (min, max) = (conn.setup().min_keycode, conn.setup().max_keycode);
        let km = conn
            .get_keyboard_mapping(min, max - min + 1)
            .map_err(err)?
            .reply()
            .map_err(err)?;
        Ok(XTestInjector {
            conn,
            root,
            min_keycode: min,
            per: usize::from(km.keysyms_per_keycode),
            map: km.keysyms,
            buttons: 0,
        })
    }

    /// Keycode cujo nivel 1 ou 2 produz o keysym. O cliente RFB ja envia
    /// Shift como tecla propria, entao nao sintetizamos modificadores.
    fn keycode(&self, ks: u32) -> Option<u8> {
        let per = self.per.max(1);
        self.map.iter().enumerate().find_map(|(i, &k)| {
            (k == ks && i % per < 2).then(|| self.min_keycode + (i / per) as u8)
        })
    }

    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16) -> Result<()> {
        self.conn
            .xtest_fake_input(kind, detail, 0, self.root, x, y, 0)
            .map_err(err)?;
        Ok(())
    }
}

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const MOTION: u8 = 6;

impl InputInjector for XTestInjector {
    fn key(&mut self, ev: KeyEvent) -> Result<()> {
        let Some(code) = self.keycode(ev.keysym) else {
            tracing::debug!(keysym = ev.keysym, "keysym sem keycode; ignorado");
            return Ok(());
        };
        self.fake(if ev.down { KEY_PRESS } else { KEY_RELEASE }, code, 0, 0)?;
        self.conn.flush().map_err(err)
    }

    fn pointer(&mut self, ev: PointerEvent) -> Result<()> {
        self.fake(MOTION, 0, ev.x as i16, ev.y as i16)?;
        for (b, down) in button_changes(self.buttons, ev.buttons) {
            // RFB bit n -> botao X n+1
            self.fake(
                if down { BUTTON_PRESS } else { BUTTON_RELEASE },
                b + 1,
                0,
                0,
            )?;
        }
        self.buttons = ev.buttons;
        self.conn.flush().map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::clip;

    #[test]
    fn recorte() {
        assert_eq!(clip(-5, -5, 10, 10, 8, 8), Some((0, 0, 8, 8)));
        assert_eq!(clip(2, 3, 4, 9, 8, 8), Some((2, 3, 2, 5)));
        assert_eq!(clip(9, 0, 12, 4, 8, 8), None);
    }

    /// Precisa de um servidor X local com MIT-SHM (ex.: `Xvfb :9`).
    /// `ci/x11/run.sh` roda este teste em container.
    #[test]
    #[ignore = "precisa de $DISPLAY"]
    fn shm_igual_getimage_e_mais_rapido() {
        use super::*;
        let mut c = X11Capture::new().expect("X11");
        assert!(c.shm.is_some(), "MIT-SHM indisponivel");
        let (w, h) = c.size();
        let mut a = Framebuffer::new(w, h, 1 << 30).unwrap();
        let mut b = Framebuffer::new(w, h, 1 << 30).unwrap();
        let n = 120;
        // aquece os dois caminhos (page faults do framebuffer e do mmap)
        c.fetch(&mut a, 0, 0, w, h).unwrap();
        let seg = c.shm.take();
        c.fetch(&mut b, 0, 0, w, h).unwrap();
        c.shm = seg;
        // tempo de CPU do processo (utime+stime em ticks de /proc/self/stat)
        fn cpu() -> u64 {
            let s = std::fs::read_to_string("/proc/self/stat").unwrap();
            let f: Vec<&str> = s[s.rfind(')').unwrap() + 2..].split(' ').collect();
            f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
        }
        let (t, c0) = (std::time::Instant::now(), cpu());
        for _ in 0..n {
            c.fetch(&mut a, 0, 0, w, h).unwrap();
        }
        let (shm, shm_cpu) = (t.elapsed() / n, cpu() - c0);
        let seg = c.shm.take();
        let (t, c0) = (std::time::Instant::now(), cpu());
        for _ in 0..n {
            c.fetch(&mut b, 0, 0, w, h).unwrap();
        }
        let (get, get_cpu) = (t.elapsed() / n, cpu() - c0);
        c.shm = seg;
        assert_eq!(a.data(), b.data(), "SHM e GetImage divergem");
        assert!(a.data().iter().any(|&p| p != 0 && p != 255), "tela vazia");
        // retangulo parcial tambem
        c.fetch(&mut a, 10, 20, 100, 50).unwrap();
        assert_eq!(a.data(), b.data());
        println!(
            "{w}x{h}, {n} quadros: MIT-SHM {shm:?}/quadro {shm_cpu} ticks de CPU, GetImage {get:?}/quadro {get_cpu} ticks de CPU"
        );
    }

    /// Damage contra quadro completo, com uma area de 64x64 mudando a cada
    /// quadro (caso tipico: cursor, relogio, digitacao). `ci/x11/run.sh`.
    #[test]
    #[ignore = "precisa de $DISPLAY"]
    fn damage_reduz_cpu() {
        use super::*;
        use x11rb::protocol::xproto::{CreateGCAux, Rectangle};
        let mut c = X11Capture::new().expect("X11");
        assert!(c.damage.is_some(), "Damage indisponivel");
        let _ = c.shm.take();
        let (w, h) = c.size();
        let mut fb = Framebuffer::new(w, h, 1 << 30).unwrap();
        let gc = c.conn.generate_id().unwrap();
        c.conn
            .create_gc(
                gc,
                c.root,
                &CreateGCAux::new()
                    .subwindow_mode(x11rb::protocol::xproto::SubwindowMode::INCLUDE_INFERIORS),
            )
            .unwrap();
        fn cpu() -> u64 {
            let s = std::fs::read_to_string("/proc/self/stat").unwrap();
            let f: Vec<&str> = s[s.rfind(')').unwrap() + 2..].split(' ').collect();
            f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
        }
        let draw = |c: &X11Capture, i: u32| {
            c.conn
                .change_gc(
                    gc,
                    &x11rb::protocol::xproto::ChangeGCAux::new().foreground(i * 0x010203),
                )
                .unwrap();
            let r = Rectangle {
                x: (i % 20 * 64) as i16,
                y: 300,
                width: 64,
                height: 64,
            };
            c.conn.poly_fill_rectangle(c.root, gc, &[r]).unwrap();
            c.conn.get_input_focus().unwrap().reply().unwrap();
        };
        assert!(c.capture(&mut fb).unwrap()); // quadro completo inicial
        let n = 120;
        let (t, c0) = (std::time::Instant::now(), cpu());
        for i in 0..n {
            draw(&c, i);
            c.capture(&mut fb).unwrap();
        }
        let (dmg, dmg_cpu) = (t.elapsed() / n, cpu() - c0);
        let (t, c0) = (std::time::Instant::now(), cpu());
        for i in 0..n {
            draw(&c, i);
            c.fetch(&mut fb, 0, 0, w, h).unwrap();
        }
        let (full, full_cpu) = (t.elapsed() / n, cpu() - c0);
        println!(
            "{w}x{h}, {n} quadros: Damage {dmg:?}/quadro {dmg_cpu} ticks de CPU, quadro completo {full:?}/quadro {full_cpu} ticks de CPU"
        );
        assert!(dmg_cpu < full_cpu, "Damage nao reduziu CPU");
    }
}
