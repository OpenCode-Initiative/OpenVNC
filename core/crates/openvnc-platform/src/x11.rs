//! Backend Linux X11: captura com `GetImage` e entrada com XTest.
//!
//! Sem `unsafe`: usa o x11rb em Rust puro. MIT-SHM e Damage ficam para
//! depois (hoje cada quadro e uma copia completa pelo socket).

use openvnc_core::{Error, KeyEvent, PointerEvent, Result};
use openvnc_framebuffer::Framebuffer;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, Window};
use x11rb::protocol::xtest::ConnectionExt as _;
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
        Ok(X11Capture {
            conn,
            root,
            w,
            h,
            order,
            row: vec![[0; 4]; usize::from(w)],
        })
    }
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
            self.w = geo.width;
            self.h = geo.height;
            self.row = vec![[0; 4]; usize::from(self.w)];
            return Ok(false);
        }
        if (fb.width(), fb.height()) != (self.w, self.h) {
            return Ok(false);
        }
        // faixas de ~4 MiB por resposta
        let stride = usize::from(self.w) * 4;
        let band = ((4 << 20) / stride.max(1)).clamp(1, usize::from(self.h)) as u16;
        let mut y0 = 0u16;
        while y0 < self.h {
            let bh = band.min(self.h - y0);
            let img = self
                .conn
                .get_image(
                    ImageFormat::Z_PIXMAP,
                    self.root,
                    0,
                    y0 as i16,
                    self.w,
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
                for (p, s) in self.row.iter_mut().zip(src.chunks_exact(4)) {
                    *p = [s[self.order[0]], s[self.order[1]], s[self.order[2]], 255];
                }
                fb.put_rgba_row(0, y0 + dy as u16, &self.row);
            }
            y0 += bh;
        }
        Ok(true)
    }

    fn name(&self) -> &'static str {
        "x11-getimage"
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
