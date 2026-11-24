//! Servidor RFB 3.8 de referencia do OpenVNC.
//!
//! Uma thread captura quadros (FPS adaptativo: desacelera com a tela
//! parada) e publica num `watch`; cada cliente compara o quadro novo com o
//! ultimo que enviou, em tiles de 64x64, e responde aos pedidos de
//! atualizacao com CopyRect (rolagem vertical) + o encoding preferido.

mod config;
mod diff;

use anyhow::Context as _;
use clap::Parser;
use config::{CaptureKind, Config};
use openvnc_core::{KeyEvent, PointerEvent, Rect};
use openvnc_framebuffer::{Framebuffer, DEFAULT_MAX_BYTES};
use openvnc_platform::{InputInjector, NullInjector, ScreenCapture, TestPattern};
use openvnc_rfb::{Server, ServerConfig, ServerEvent};
use openvnc_security::Password;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Parser, Debug)]
#[command(version, about = "Servidor RFB 3.8 de referencia do OpenVNC")]
struct Cli {
    /// Arquivo TOML de configuracao.
    #[arg(long, short)]
    config: Option<std::path::PathBuf>,
    /// Endereco de escuta (sobrepoe o arquivo).
    #[arg(long)]
    listen: Option<std::net::SocketAddr>,
    /// Fonte de quadros (sobrepoe o arquivo).
    #[arg(long, value_enum)]
    capture: Option<CaptureKind>,
    /// Limite de FPS (sobrepoe o arquivo).
    #[arg(long)]
    max_fps: Option<u32>,
    /// Aceitar clientes sem senha (so em loopback).
    #[arg(long)]
    allow_no_auth: bool,
}

/// Quadro publicado pela thread de captura.
#[derive(Clone)]
pub struct Frame {
    gen: u64,
    fb: Arc<Framebuffer>,
}

enum Input {
    Key(KeyEvent),
    Pointer(PointerEvent),
}

/// Contexto compartilhado entre conexoes.
struct Shared {
    cfg: Config,
    password: Option<String>,
    frames: watch::Receiver<Frame>,
    input: Option<mpsc::Sender<Input>>,
    clients: AtomicUsize,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let mut cfg = match &cli.config {
        Some(p) => Config::from_toml(
            &std::fs::read_to_string(p).with_context(|| format!("lendo {}", p.display()))?,
        )?,
        None => Config::default(),
    };
    if let Some(l) = cli.listen {
        cfg.listen = l;
    }
    if let Some(c) = cli.capture {
        cfg.capture = c;
    }
    if let Some(f) = cli.max_fps {
        cfg.max_fps = f;
    }
    cfg.allow_no_auth |= cli.allow_no_auth;
    let password = cfg.resolve_password();
    cfg.validate(&password)?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = TcpListener::bind(cfg.listen).await?;
        tracing::info!(addr = %listener.local_addr()?, capture = ?cfg.capture, "escutando");
        run(listener, cfg, password).await
    })
}

/// Sobe captura, entrada e aceita conexoes para sempre.
async fn run(listener: TcpListener, cfg: Config, password: Option<String>) -> anyhow::Result<()> {
    let capture: Box<dyn ScreenCapture> = match cfg.capture {
        CaptureKind::TestPattern => {
            let (w, h) = cfg.test_pattern_size;
            Box::new(TestPattern::new(w, h))
        }
        CaptureKind::Native => openvnc_platform::native_capture()?,
    };
    tracing::info!(backend = capture.name(), size = ?capture.size(), "captura");
    let frames = spawn_capture(capture, cfg.max_fps)?;
    let input = if cfg.view_only {
        None
    } else {
        let inj: Box<dyn InputInjector> = match cfg.capture {
            CaptureKind::TestPattern => Box::new(NullInjector),
            CaptureKind::Native => openvnc_platform::native_injector()?,
        };
        Some(spawn_injector(inj))
    };
    let shared = Arc::new(Shared {
        cfg,
        password,
        frames,
        input,
        clients: AtomicUsize::new(0),
    });
    loop {
        let (sock, peer) = listener.accept().await?;
        let n = shared.clients.load(Ordering::SeqCst);
        if n >= shared.cfg.max_clients {
            tracing::warn!(%peer, "limite de clientes; recusado");
            continue;
        }
        shared.clients.fetch_add(1, Ordering::SeqCst);
        let sh = shared.clone();
        tokio::spawn(async move {
            tracing::info!(%peer, "conectado");
            if let Err(e) = serve(sock, &sh).await {
                tracing::info!(%peer, "desconectado: {e:#}");
            } else {
                tracing::info!(%peer, "desconectado");
            }
            sh.clients.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Thread de captura com FPS adaptativo: no maximo `max_fps`; a cada
/// quadro identico ao anterior o intervalo dobra (ate 250 ms), e volta ao
/// minimo na primeira mudanca.
fn spawn_capture(
    mut cap: Box<dyn ScreenCapture>,
    max_fps: u32,
) -> anyhow::Result<watch::Receiver<Frame>> {
    let (w, h) = cap.size();
    let mut fb = Framebuffer::new(w, h, DEFAULT_MAX_BYTES)?;
    cap.capture(&mut fb)?;
    let (tx, rx) = watch::channel(Frame {
        gen: 0,
        fb: Arc::new(fb.clone()),
    });
    let min = Duration::from_secs(1) / max_fps;
    let idle_max = Duration::from_millis(250).max(min);
    std::thread::Builder::new()
        .name("captura".into())
        .spawn(move || {
            let mut gen = 0u64;
            let mut interval = min;
            loop {
                let t0 = Instant::now();
                match cap.capture(&mut fb) {
                    Ok(true) => {}
                    Ok(false) => {
                        let (w, h) = cap.size();
                        match Framebuffer::new(w, h, DEFAULT_MAX_BYTES) {
                            Ok(n) => fb = n,
                            Err(e) => {
                                tracing::error!("tela grande demais: {e}");
                                return;
                            }
                        }
                        tracing::info!(w, h, "tela redimensionada");
                        continue;
                    }
                    Err(e) => {
                        tracing::error!("captura falhou: {e}");
                        return;
                    }
                }
                let changed = {
                    let last = tx.borrow();
                    last.fb.width() != fb.width()
                        || last.fb.height() != fb.height()
                        || last.fb.data() != fb.data()
                };
                if changed {
                    gen += 1;
                    interval = min;
                    if tx
                        .send(Frame {
                            gen,
                            fb: Arc::new(fb.clone()),
                        })
                        .is_err()
                    {
                        return;
                    }
                } else {
                    interval = (interval * 2).min(idle_max);
                }
                if let Some(rest) = interval.checked_sub(t0.elapsed()) {
                    std::thread::sleep(rest);
                }
            }
        })?;
    Ok(rx)
}

fn spawn_injector(mut inj: Box<dyn InputInjector>) -> mpsc::Sender<Input> {
    let (tx, rx) = mpsc::channel::<Input>();
    std::thread::spawn(move || {
        for ev in rx {
            let r = match ev {
                Input::Key(k) => inj.key(k),
                Input::Pointer(p) => inj.pointer(p),
            };
            if let Err(e) = r {
                tracing::warn!("injecao falhou: {e}");
            }
        }
    });
    tx
}

fn challenge() -> anyhow::Result<[u8; 16]> {
    let mut c = [0u8; 16];
    getrandom::getrandom(&mut c).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    Ok(c)
}

fn intersect(a: Rect, b: Rect) -> Option<Rect> {
    let x0 = a.x.max(b.x);
    let y0 = a.y.max(b.y);
    let x1 = (u32::from(a.x) + u32::from(a.width)).min(u32::from(b.x) + u32::from(b.width));
    let y1 = (u32::from(a.y) + u32::from(a.height)).min(u32::from(b.y) + u32::from(b.height));
    (x1 > u32::from(x0) && y1 > u32::from(y0)).then(|| {
        Rect::new(
            x0,
            y0,
            (x1 - u32::from(x0)) as u16,
            (y1 - u32::from(y0)) as u16,
        )
    })
}

/// Estado do que o cliente ja tem.
struct ClientView {
    sent: Option<Frame>,
    /// Pedido pendente: (incremental, area).
    pending: Option<(bool, Rect)>,
}

/// Planeja a atualizacao: CopyRects e retangulos a codificar.
fn plan(old: &Framebuffer, new: &Framebuffer, area: Rect) -> (Vec<(Rect, u16, u16)>, Vec<Rect>) {
    let dirty = diff::dirty_tiles(old, new);
    let Some(b) = diff::bounds(&dirty) else {
        return (Vec::new(), Vec::new());
    };
    let clip = |v: Vec<Rect>| v.into_iter().filter_map(|r| intersect(r, area)).collect();
    if b.area() >= 128 * 128 {
        if let Some((dst, src_y)) = diff::detect_vertical_scroll(old, new, b, 256) {
            if intersect(dst, area) == Some(dst) {
                let mut sim = old.clone();
                sim.copy_rect(dst.x, src_y, dst);
                let rest = diff::dirty_tiles(&sim, new);
                return (vec![(dst, dst.x, src_y)], clip(rest));
            }
        }
    }
    (Vec::new(), clip(dirty))
}

async fn serve(mut sock: TcpStream, sh: &Shared) -> anyhow::Result<()> {
    sock.set_nodelay(true)?;
    let mut frames = sh.frames.clone();
    let first = frames.borrow_and_update().clone();
    let mut srv = Server::new(
        ServerConfig {
            password: sh.password.clone().map(Password::new),
            allow_no_auth: sh.cfg.allow_no_auth,
            name: sh.cfg.name.clone(),
            challenge: challenge()?,
            ..Default::default()
        },
        first.fb.width(),
        first.fb.height(),
    )?;
    let mut view = ClientView {
        sent: None,
        pending: None,
    };
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = (first.fb.width(), first.fb.height());
    let (mut updates, mut bytes, mut since) = (0u32, 0usize, Instant::now());
    loop {
        let out = srv.take_output();
        if !out.is_empty() {
            bytes += out.len();
            sock.write_all(&out).await?;
        }
        if since.elapsed() >= Duration::from_secs(5) {
            let secs = since.elapsed().as_secs_f64();
            tracing::info!(
                fps = format!("{:.1}", f64::from(updates) / secs),
                kbps = format!("{:.0}", bytes as f64 * 8.0 / 1000.0 / secs),
                "estatisticas"
            );
            (updates, bytes, since) = (0, 0, Instant::now());
        }
        while let Some(ev) = srv.poll_event() {
            match ev {
                ServerEvent::AuthFailed => {
                    let out = srv.take_output();
                    sock.write_all(&out).await?;
                    anyhow::bail!("autenticacao falhou");
                }
                ServerEvent::UpdateRequest { incremental, rect } => {
                    // pedido nao incremental sobrepoe o incremental pendente
                    let inc = incremental && view.pending.is_none_or(|(i, _)| i);
                    let r = match view.pending {
                        Some((_, p)) => p.union(&rect),
                        None => rect,
                    };
                    view.pending = Some((inc, r));
                }
                ServerEvent::Key(k) => {
                    if let Some(tx) = &sh.input {
                        let _ = tx.send(Input::Key(k));
                    }
                }
                ServerEvent::Pointer(p) => {
                    if let Some(tx) = &sh.input {
                        let _ = tx.send(Input::Pointer(p));
                    }
                }
                ServerEvent::Initialized { shared, version } => {
                    tracing::debug!(shared, ?version, "cliente pronto");
                }
                ServerEvent::Encodings(e) => tracing::debug!(?e, "encodings"),
                ServerEvent::PixelFormatChanged(pf) => tracing::debug!(?pf, "formato"),
                ServerEvent::CutText(_) => {}
            }
        }
        // responde ao pedido pendente se ha algo novo
        if let Some((inc, area)) = view.pending {
            let cur = frames.borrow().clone();
            let cur_size = (cur.fb.width(), cur.fb.height());
            if cur_size != size {
                if !srv.send_desktop_size(cur_size.0, cur_size.1) {
                    anyhow::bail!("tela mudou de tamanho e o cliente nao aceita DesktopSize");
                }
                size = cur_size;
                view.sent = None;
                view.pending = None;
                continue;
            }
            let fresh = view.sent.as_ref().is_none_or(|s| s.gen != cur.gen);
            if !inc || fresh {
                let (copies, rects) = match (&view.sent, inc) {
                    (Some(old), true) => plan(&old.fb, &cur.fb, area),
                    _ => (Vec::new(), vec![area]),
                };
                view.sent = Some(cur.clone());
                if !copies.is_empty() || !rects.is_empty() || !inc {
                    srv.send_update(&cur.fb, &copies, &rects)?;
                    updates += 1;
                    view.pending = None;
                    continue;
                }
                // mudou fora da area pedida: segue esperando
            }
        }
        tokio::select! {
            n = sock.read(&mut buf) => {
                let n = n?;
                if n == 0 {
                    return Ok(());
                }
                srv.feed(&buf[..n])?;
            }
            r = frames.changed(), if view.pending.is_some() => {
                if r.is_err() {
                    anyhow::bail!("captura encerrada");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvnc_rfb::{Client, Config as CConfig, Event};

    async fn start(cfg: Config, pw: Option<&str>) -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let pw = pw.map(String::from);
        tokio::spawn(async move { run(l, cfg, pw).await });
        addr
    }

    async fn pump(sock: &mut TcpStream, c: &mut Client, buf: &mut [u8]) -> Vec<Event> {
        let out = c.take_output();
        if !out.is_empty() {
            sock.write_all(&out).await.unwrap();
        }
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(buf))
            .await
            .expect("timeout")
            .unwrap();
        assert!(n > 0, "servidor fechou");
        c.feed(&buf[..n]).unwrap();
        std::iter::from_fn(|| c.poll_event()).collect()
    }

    #[tokio::test]
    async fn two_clients_see_animation() {
        let cfg = Config {
            test_pattern_size: (200, 120),
            max_fps: 60,
            ..Default::default()
        };
        let addr = start(cfg, Some("teste")).await;
        let mut socks = Vec::new();
        for _ in 0..2 {
            let s = TcpStream::connect(addr).await.unwrap();
            let c = Client::new(CConfig {
                password: Some(Password::new("teste")),
                ..Default::default()
            });
            socks.push((s, c, vec![0u8; 1 << 16]));
        }
        for (s, c, buf) in &mut socks {
            let mut updates = 0;
            let mut snaps = Vec::new();
            while updates < 4 {
                for e in pump(s, c, buf).await {
                    if e == Event::UpdateComplete {
                        updates += 1;
                        snaps.push(c.framebuffer().unwrap().data().to_vec());
                        c.request_incremental();
                    }
                }
            }
            assert_eq!(c.framebuffer().unwrap().width(), 200);
            // a animacao chegou: quadros sucessivos diferem
            assert!(snaps.windows(2).any(|w| w[0] != w[1]));
        }
    }

    #[tokio::test]
    async fn incremental_matches_server_frame() {
        let cfg = Config {
            test_pattern_size: (160, 100),
            allow_no_auth: true,
            ..Default::default()
        };
        let addr = start(cfg, None).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut c = Client::new(CConfig::default());
        let mut buf = vec![0u8; 1 << 16];
        loop {
            if pump(&mut s, &mut c, &mut buf)
                .await
                .contains(&Event::UpdateComplete)
            {
                break;
            }
        }
        // o quadro recebido e exatamente um dos quadros do padrao
        let got = c.framebuffer().unwrap().data().to_vec();
        let mut tp = TestPattern::new(160, 100);
        let mut want = Framebuffer::new(160, 100, DEFAULT_MAX_BYTES).unwrap();
        let hit = (0..10_000).any(|_| {
            tp.capture(&mut want).unwrap();
            want.data() == got.as_slice()
        });
        assert!(hit, "quadro recebido nao corresponde ao padrao");
    }

    #[test]
    fn plan_uses_copyrect_for_scroll() {
        let mut a = Framebuffer::new(256, 256, DEFAULT_MAX_BYTES).unwrap();
        for y in 0..256u16 {
            a.fill_rect(Rect::new(0, y, 256, 1), [y as u8, 0, 0, 255]);
            a.fill_rect(Rect::new(y, y, 3, 1), [0, 255, 0, 255]);
        }
        let mut b = a.clone();
        b.copy_rect(0, 20, Rect::new(0, 0, 256, 236));
        let full = Rect::new(0, 0, 256, 256);
        let (copies, rects) = plan(&a, &b, full);
        assert_eq!(copies, vec![(Rect::new(0, 0, 256, 236), 0, 20)]);
        // sobra so a faixa de baixo
        let mut sim = a.clone();
        sim.copy_rect(0, 20, Rect::new(0, 0, 256, 236));
        for r in &rects {
            sim.copy_from(&b, *r);
        }
        assert_eq!(sim.data(), b.data());
        assert!(rects.iter().all(|r| r.y >= 192));
    }

    #[test]
    fn intersect_works() {
        let a = Rect::new(0, 0, 10, 10);
        assert_eq!(
            intersect(a, Rect::new(5, 5, 10, 10)),
            Some(Rect::new(5, 5, 5, 5))
        );
        assert_eq!(intersect(a, Rect::new(10, 0, 5, 5)), None);
    }
}
