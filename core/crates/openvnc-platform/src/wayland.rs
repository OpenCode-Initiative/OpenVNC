//! Backend Wayland: captura pelo portal ScreenCast + PipeWire e entrada
//! pelo portal RemoteDesktop (feature `wayland`).
//!
//! O compositor mostra o dialogo de permissao do portal na primeira
//! chamada. Tenta primeiro uma sessao RemoteDesktop (tela + teclado e
//! mouse); se o portal nao oferecer RemoteDesktop (ex.: xdg-desktop-portal-wlr),
//! cai para ScreenCast puro e a entrada fica indisponivel.
//!
//! Threads: uma com runtime tokio para o D-Bus do portal (atende os
//! comandos de entrada) e uma com o main loop do PipeWire, que deixa o
//! quadro mais recente num buffer compartilhado.

use std::os::fd::OwnedFd;
use std::sync::{mpsc, Arc, Mutex, OnceLock};

use ashpd::desktop::remote_desktop::{Axis, DeviceType, KeyState, RemoteDesktop};
use ashpd::desktop::screencast::{CursorMode, Screencast, SourceType};
use ashpd::desktop::PersistMode;
use openvnc_core::{Error, KeyEvent, PointerEvent, Result};
use openvnc_framebuffer::Framebuffer;
use pipewire as pw;
use pw::spa;
use pw::spa::param::format::{FormatProperties, MediaSubtype, MediaType};
use pw::spa::param::video::{VideoFormat, VideoInfoRaw};
use pw::spa::param::ParamType;
use pw::spa::pod::{Pod, Value};
use pw::spa::utils::{Direction, SpaTypes};

use crate::{button_changes, InputInjector, ScreenCapture};

fn err(e: impl std::fmt::Display) -> Error {
    Error::Unsupported(format!("Wayland: {e}"))
}

/// Quadro mais recente vindo do PipeWire.
#[derive(Default)]
struct Latest {
    w: u16,
    h: u16,
    /// Posicao de R, G, B num pixel de 4 bytes.
    order: [usize; 3],
    stride: usize,
    data: Vec<u8>,
    seq: u64,
    error: Option<String>,
}

enum Input {
    Motion(f64, f64),
    Button(i32, bool),
    Scroll(i32),
    Key(i32, bool),
}

/// Sessao do portal compartilhada por captura e entrada.
struct Portal {
    latest: Arc<Mutex<Latest>>,
    input: Option<tokio::sync::mpsc::UnboundedSender<Input>>,
}

static PORTAL: OnceLock<std::result::Result<Arc<Portal>, String>> = OnceLock::new();

fn portal() -> Result<Arc<Portal>> {
    PORTAL
        .get_or_init(|| Portal::start().map(Arc::new).map_err(|e| e.to_string()))
        .clone()
        .map_err(err)
}

struct Started {
    node: u32,
    fd: OwnedFd,
    input: bool,
}

async fn open_session(
    tx: tokio::sync::mpsc::UnboundedSender<Input>,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Input>,
    done: mpsc::Sender<std::result::Result<Started, String>>,
) -> std::result::Result<(), String> {
    drop(tx);
    let sc = Screencast::new().await.map_err(|e| e.to_string())?;
    // 1) RemoteDesktop + ScreenCast na mesma sessao
    let rd = match RemoteDesktop::new().await {
        Ok(rd) => Some(rd),
        Err(e) => {
            tracing::info!(%e, "portal RemoteDesktop ausente; so captura");
            None
        }
    };
    if let Some(rd) = rd {
        let attempt = async {
            let session = rd.create_session().await?;
            rd.select_devices(
                &session,
                DeviceType::Keyboard | DeviceType::Pointer,
                None,
                PersistMode::DoNot,
            )
            .await?;
            sc.select_sources(
                &session,
                CursorMode::Embedded,
                SourceType::Monitor.into(),
                false,
                None,
                PersistMode::DoNot,
            )
            .await?;
            let resp = rd.start(&session, None).await?.response()?;
            let node = resp
                .streams()
                .and_then(|s| s.first())
                .map(|s| s.pipe_wire_node_id())
                .ok_or(ashpd::Error::NoResponse)?;
            let fd = sc.open_pipe_wire_remote(&session).await?;
            Ok::<_, ashpd::Error>((session, node, fd))
        };
        match attempt.await {
            Ok((session, node, fd)) => {
                let _ = done.send(Ok(Started {
                    node,
                    fd,
                    input: true,
                }));
                while let Some(ev) = rx.recv().await {
                    let r = match ev {
                        Input::Motion(x, y) => {
                            rd.notify_pointer_motion_absolute(&session, node, x, y)
                                .await
                        }
                        Input::Button(b, down) => {
                            rd.notify_pointer_button(&session, b, state(down)).await
                        }
                        Input::Scroll(steps) => {
                            rd.notify_pointer_axis_discrete(&session, Axis::Vertical, steps)
                                .await
                        }
                        Input::Key(ks, down) => {
                            rd.notify_keyboard_keysym(&session, ks, state(down)).await
                        }
                    };
                    if let Err(e) = r {
                        tracing::debug!(%e, "entrada recusada pelo portal");
                    }
                }
                return Ok(());
            }
            Err(e) => tracing::info!(%e, "sessao RemoteDesktop falhou; so captura"),
        }
    }
    // 2) ScreenCast puro
    let session = sc.create_session().await.map_err(|e| e.to_string())?;
    sc.select_sources(
        &session,
        CursorMode::Embedded,
        SourceType::Monitor.into(),
        false,
        None,
        PersistMode::DoNot,
    )
    .await
    .map_err(|e| e.to_string())?;
    let resp = sc
        .start(&session, None)
        .await
        .and_then(|r| r.response())
        .map_err(|e| e.to_string())?;
    let node = resp
        .streams()
        .first()
        .map(|s| s.pipe_wire_node_id())
        .ok_or("portal sem stream")?;
    let fd = sc
        .open_pipe_wire_remote(&session)
        .await
        .map_err(|e| e.to_string())?;
    let _ = done.send(Ok(Started {
        node,
        fd,
        input: false,
    }));
    // mantem a sessao viva
    while rx.recv().await.is_some() {}
    std::future::pending::<()>().await;
    Ok(())
}

fn state(down: bool) -> KeyState {
    if down {
        KeyState::Pressed
    } else {
        KeyState::Released
    }
}

impl Portal {
    fn start() -> Result<Portal> {
        // Diagnostico: `OPENVNC_PIPEWIRE_NODE=<id>` liga direto num no do
        // PipeWire local, sem portal (e sem entrada).
        if let Some(node) = std::env::var("OPENVNC_PIPEWIRE_NODE")
            .ok()
            .and_then(|v| v.parse().ok())
        {
            tracing::warn!(node, "OPENVNC_PIPEWIRE_NODE: sem portal, sem entrada");
            return Ok(Portal {
                latest: Self::spawn_pipewire(None, node)?,
                input: None,
            });
        }
        let (done_tx, done_rx) = mpsc::channel();
        let (in_tx, mut in_rx) = tokio::sync::mpsc::unbounded_channel();
        let keep = in_tx.clone();
        std::thread::Builder::new()
            .name("portal".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = done_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let d = done_tx.clone();
                if let Err(e) = rt.block_on(open_session(in_tx, &mut in_rx, done_tx)) {
                    let _ = d.send(Err(e));
                }
            })
            .map_err(err)?;
        let started = done_rx
            .recv()
            .map_err(|_| err("thread do portal terminou"))?
            .map_err(err)?;
        Ok(Portal {
            latest: Self::spawn_pipewire(Some(started.fd), started.node)?,
            input: started.input.then_some(keep),
        })
    }

    fn spawn_pipewire(fd: Option<OwnedFd>, node: u32) -> Result<Arc<Mutex<Latest>>> {
        let latest = Arc::new(Mutex::new(Latest::default()));
        let l = latest.clone();
        std::thread::Builder::new()
            .name("pipewire".into())
            .spawn(move || {
                if let Err(e) = run_pipewire(fd, node, l.clone()) {
                    l.lock().expect("mutex").error = Some(e.to_string());
                }
            })
            .map_err(err)?;
        Ok(latest)
    }
}

struct StreamData {
    info: VideoInfoRaw,
    latest: Arc<Mutex<Latest>>,
}

fn run_pipewire(fd: Option<OwnedFd>, node: u32, latest: Arc<Mutex<Latest>>) -> anyhow_lite::Result {
    pw::init();
    let mainloop = pw::main_loop::MainLoop::new(None)?;
    let context = pw::context::Context::new(&mainloop)?;
    let core = match fd {
        Some(fd) => context.connect_fd(fd, None)?,
        None => context.connect(None)?,
    };
    let stream = pw::stream::Stream::new(
        &core,
        "openvnc-capture",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )?;
    let data = StreamData {
        info: VideoInfoRaw::default(),
        latest,
    };
    let _listener = stream
        .add_local_listener_with_user_data(data)
        .param_changed(|_, ud, id, param| {
            let Some(param) = param else { return };
            if id != ParamType::Format.as_raw() {
                return;
            }
            let Ok((mt, ms)) = pw::spa::param::format_utils::parse_format(param) else {
                return;
            };
            if mt != MediaType::Video || ms != MediaSubtype::Raw {
                return;
            }
            if ud.info.parse(param).is_err() {
                return;
            }
            let order = match ud.info.format() {
                VideoFormat::RGBx | VideoFormat::RGBA => [0, 1, 2],
                VideoFormat::BGRx | VideoFormat::BGRA => [2, 1, 0],
                VideoFormat::xRGB | VideoFormat::ARGB => [1, 2, 3],
                VideoFormat::xBGR | VideoFormat::ABGR => [3, 2, 1],
                f => {
                    ud.latest.lock().expect("mutex").error =
                        Some(format!("formato PipeWire nao suportado: {f:?}"));
                    return;
                }
            };
            let s = ud.info.size();
            let mut l = ud.latest.lock().expect("mutex");
            l.w = u16::try_from(s.width).unwrap_or(0);
            l.h = u16::try_from(s.height).unwrap_or(0);
            l.order = order;
            tracing::info!(w = l.w, h = l.h, format = ?ud.info.format(), "stream PipeWire");
        })
        .process(|stream, ud| {
            let Some(mut buffer) = stream.dequeue_buffer() else {
                return;
            };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let chunk = d.chunk();
            let (off, size, stride) = (
                chunk.offset() as usize,
                chunk.size() as usize,
                chunk.stride().max(0) as usize,
            );
            let Some(bytes) = d.data() else { return };
            if size == 0 || off + size > bytes.len() {
                return; // quadro so de metadados (ex.: cursor)
            }
            let mut l = ud.latest.lock().expect("mutex");
            let need = usize::from(l.h) * stride;
            if l.w == 0 || stride < usize::from(l.w) * 4 || size < need {
                return;
            }
            l.stride = stride;
            l.data.clear();
            l.data.extend_from_slice(&bytes[off..off + need]);
            l.seq += 1;
        })
        .register()?;

    let obj = spa::pod::object!(
        SpaTypes::ObjectParamFormat,
        ParamType::EnumFormat,
        spa::pod::property!(FormatProperties::MediaType, Id, MediaType::Video),
        spa::pod::property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        spa::pod::property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx,
            VideoFormat::BGRx,
            VideoFormat::BGRA,
            VideoFormat::RGBx,
            VideoFormat::RGBA,
            VideoFormat::xRGB,
            VideoFormat::xBGR
        ),
        spa::pod::property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            spa::utils::Rectangle {
                width: 1920,
                height: 1080
            },
            spa::utils::Rectangle {
                width: 1,
                height: 1
            },
            spa::utils::Rectangle {
                width: 8192,
                height: 8192
            }
        ),
        spa::pod::property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: 30, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction { num: 240, denom: 1 }
        ),
    );
    let values: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &Value::Object(obj),
    )?
    .0
    .into_inner();
    let mut params = [Pod::from_bytes(&values).ok_or("pod invalido")?];
    stream.connect(
        Direction::Input,
        Some(node),
        pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;
    mainloop.run();
    Ok(())
}

/// Erro boxed minimo (o crate nao depende de anyhow).
mod anyhow_lite {
    pub type Result = std::result::Result<(), Box<dyn std::error::Error>>;
}

/// Captura de um monitor escolhido no dialogo do portal.
pub struct WaylandCapture {
    portal: Arc<Portal>,
    seq: u64,
    row: Vec<[u8; 4]>,
}

impl WaylandCapture {
    /// Abre (ou reaproveita) a sessao do portal e espera o primeiro quadro.
    pub fn new() -> Result<Self> {
        let portal = portal()?;
        let t = std::time::Instant::now();
        loop {
            {
                let l = portal.latest.lock().expect("mutex");
                if let Some(e) = &l.error {
                    return Err(err(e));
                }
                if l.seq > 0 {
                    break;
                }
            }
            if t.elapsed() > std::time::Duration::from_secs(10) {
                return Err(err("nenhum quadro do PipeWire em 10 s"));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ok(WaylandCapture {
            portal,
            seq: 0,
            row: Vec::new(),
        })
    }
}

impl ScreenCapture for WaylandCapture {
    fn size(&self) -> (u16, u16) {
        let l = self.portal.latest.lock().expect("mutex");
        (l.w, l.h)
    }

    fn capture(&mut self, fb: &mut Framebuffer) -> Result<bool> {
        let l = self.portal.latest.lock().expect("mutex");
        if let Some(e) = &l.error {
            return Err(err(e));
        }
        if (fb.width(), fb.height()) != (l.w, l.h) {
            return Ok(false);
        }
        if l.seq == self.seq || l.data.is_empty() {
            return Ok(true);
        }
        self.seq = l.seq;
        self.row.resize(usize::from(l.w), [0; 4]);
        let o = l.order;
        for (y, src) in l
            .data
            .chunks_exact(l.stride)
            .take(usize::from(l.h))
            .enumerate()
        {
            for (p, s) in self.row.iter_mut().zip(src.chunks_exact(4)) {
                *p = [s[o[0]], s[o[1]], s[o[2]], 255];
            }
            fb.put_rgba_row(0, y as u16, &self.row);
        }
        Ok(true)
    }

    fn name(&self) -> &'static str {
        "wayland-portal-pipewire"
    }
}

/// Entrada pelo portal RemoteDesktop.
pub struct PortalInjector {
    tx: tokio::sync::mpsc::UnboundedSender<Input>,
    buttons: u8,
}

impl PortalInjector {
    /// Usa a sessao do portal (abrindo-a, se preciso).
    pub fn new() -> Result<Self> {
        let p = portal()?;
        let tx = p
            .input
            .clone()
            .ok_or_else(|| err("o portal nao oferece RemoteDesktop; entrada indisponivel"))?;
        Ok(PortalInjector { tx, buttons: 0 })
    }

    fn send(&self, i: Input) -> Result<()> {
        self.tx
            .send(i)
            .map_err(|_| err("sessao do portal encerrada"))
    }
}

/// Codigos evdev dos botoes (linux/input-event-codes.h).
const BTN_LEFT: i32 = 0x110;
const BTN_RIGHT: i32 = 0x111;
const BTN_MIDDLE: i32 = 0x112;

impl InputInjector for PortalInjector {
    fn key(&mut self, ev: KeyEvent) -> Result<()> {
        self.send(Input::Key(ev.keysym as i32, ev.down))
    }

    fn pointer(&mut self, ev: PointerEvent) -> Result<()> {
        self.send(Input::Motion(f64::from(ev.x), f64::from(ev.y)))?;
        for (b, down) in button_changes(self.buttons, ev.buttons) {
            match b {
                0 => self.send(Input::Button(BTN_LEFT, down))?,
                1 => self.send(Input::Button(BTN_MIDDLE, down))?,
                2 => self.send(Input::Button(BTN_RIGHT, down))?,
                3 if down => self.send(Input::Scroll(-1))?,
                4 if down => self.send(Input::Scroll(1))?,
                _ => {}
            }
        }
        self.buttons = ev.buttons;
        Ok(())
    }
}
