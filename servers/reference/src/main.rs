//! Servidor RFB 3.8 de referencia do OpenVNC.
//!
//! Uma thread captura quadros (FPS adaptativo: desacelera com a tela
//! parada) e publica num `watch`; cada cliente compara o quadro novo com o
//! ultimo que enviou, em tiles de 64x64, e responde aos pedidos de
//! atualizacao com CopyRect (rolagem vertical) + o encoding preferido.

mod config;
mod diff;
mod dpapi;
mod extauth;
mod files;
mod fsexplorer;
mod idle;
mod inputlock;
mod lockout;
mod native;
mod tray;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use config::{CaptureKind, Config};
use openvnc_core::{KeyEvent, PointerEvent, Rect};
use openvnc_framebuffer::{Framebuffer, DEFAULT_MAX_BYTES};
use openvnc_platform::{InputInjector, NullInjector, ScreenCapture, TestPattern};
use openvnc_rfb::{PlainVerifier, Server, ServerConfig, ServerEvent};
use openvnc_security::audit::AuditLog;
use openvnc_security::pairing::{DeviceStore, Verdict};
use openvnc_security::{passhash, Password};
use openvnc_transport::tls::{ServerIdentity, TlsAcceptor};
use openvnc_transport::BoxStream;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
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
    /// Oferecer VeNCrypt (TLS 1.3).
    #[arg(long)]
    tls: bool,
    /// Oferecer somente VeNCrypt (implica --tls).
    #[arg(long)]
    require_tls: bool,
    /// Autenticar dispositivos pareados (exige TLS).
    #[arg(long)]
    pairing: bool,
    /// Escuta o protocolo nativo (QUIC, com fallback TCP+TLS na mesma
    /// porta) neste endereco.
    #[arg(long)]
    native: Option<std::net::SocketAddr>,
    /// Diretorio de estado (certificado, dispositivos, auditoria).
    #[arg(long)]
    state_dir: Option<std::path::PathBuf>,
    /// Mostra um icone na bandeja do sistema (Windows).
    #[arg(long)]
    tray: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Gerencia dispositivos pareados.
    Pair {
        #[command(subcommand)]
        op: PairOp,
    },
    /// Mostra (gerando se preciso) a impressao digital SHA-256 do
    /// certificado TLS, para conferir/fixar no cliente.
    Fingerprint,
    /// Le uma senha da entrada padrao e imprime o hash Argon2id.
    HashPassword,
    /// Le uma senha da entrada padrao e imprime cifrada com DPAPI da
    /// maquina (para `password_protected`).
    ProtectPassword,
}

#[derive(Subcommand, Debug)]
enum PairOp {
    /// Pareia um novo dispositivo e mostra o token (uma unica vez).
    Add {
        /// Nome do dispositivo.
        name: String,
    },
    /// Lista os dispositivos.
    List,
    /// Revoga um dispositivo.
    Revoke {
        /// Id (`dev-...`).
        id: String,
    },
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

/// Escolha do monitor capturado: pedido dos clientes e estado atual.
#[derive(Clone)]
pub(crate) struct Screens {
    /// Monitor pedido; `NO_REQUEST` = nada pendente.
    req: Arc<AtomicU8>,
    /// (monitor atual, total).
    pub(crate) info: watch::Receiver<(u8, u8)>,
}

const NO_REQUEST: u8 = u8::MAX;

impl Screens {
    /// Pede um monitor; 255 = o proximo.
    pub(crate) fn select(&self, index: u8) {
        let (cur, n) = *self.info.borrow();
        let i = if index == u8::MAX {
            (cur + 1) % n.max(1)
        } else {
            index
        };
        self.req.store(i, Ordering::Relaxed);
    }
}

/// Contexto compartilhado entre conexoes.
struct Shared {
    cfg: Config,
    password: Option<String>,
    frames: watch::Receiver<Frame>,
    screens: Screens,
    input: Option<mpsc::Sender<Input>>,
    clients: AtomicUsize,
    tls: Option<TlsAcceptor>,
    devices: Option<DeviceStore>,
    audit: Arc<AuditLog>,
    lockout: lockout::Lockout,
    oidc: Option<openvnc_security::oidc::Verifier>,
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
    cfg.tls |= cli.tls;
    cfg.require_tls |= cli.require_tls;
    cfg.pairing |= cli.pairing;
    if cli.native.is_some() {
        cfg.native_listen = cli.native;
    }
    if cli.state_dir.is_some() {
        cfg.state_dir = cli.state_dir.clone();
    }
    match &cli.cmd {
        Some(Cmd::Pair { op }) => return pair_cmd(&cfg, op),
        Some(Cmd::Fingerprint) => {
            println!("{}", identity(&cfg)?.fingerprint());
            return Ok(());
        }
        Some(Cmd::HashPassword) => {
            println!(
                "{}",
                passhash::hash(&read_stdin_secret()?).map_err(anyhow::Error::msg)?
            );
            return Ok(());
        }
        Some(Cmd::ProtectPassword) => {
            println!("{}", dpapi::protect(read_stdin_secret()?.as_bytes())?);
            return Ok(());
        }
        None => {}
    }
    let mut password = cfg.resolve_password();
    if password.is_none() {
        if let Some(p) = &cfg.password_protected {
            password = Some(dpapi::unprotect(p).context("decifrando password_protected")?);
        }
    }
    cfg.validate(&password)?;

    if cli.tray && !single_instance() {
        tracing::warn!("ja existe um OpenVNC Server com bandeja rodando; saindo");
        return Ok(());
    }
    let rt = tokio::runtime::Runtime::new()?;
    let tray = cli.tray;
    let admin = cfg.admin_password_hash.is_some();
    rt.block_on(async move {
        let listener = TcpListener::bind(cfg.listen).await?;
        tracing::info!(addr = %listener.local_addr()?, capture = ?cfg.capture, "escutando");
        files::set_sending(cfg.files_send);
        if tray {
            tray::spawn(listener.local_addr()?.port(), cfg.name.clone(), admin);
        }
        run(listener, cfg, password).await
    })
}

/// Garante uma so instancia com bandeja por sessao (mutex nomeado). O
/// handle fica aberto ate o processo sair.
#[cfg(windows)]
#[allow(unsafe_code)]
fn single_instance() -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let name: Vec<u16> = "Local\\OpenVNC.Server.Tray\0".encode_utf16().collect();
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    !h.is_null() && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
}

#[cfg(not(windows))]
fn single_instance() -> bool {
    true
}

fn read_stdin_secret() -> anyhow::Result<String> {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let s = s.trim_end_matches(['\r', '\n']).to_string();
    if s.is_empty() {
        anyhow::bail!("senha vazia");
    }
    Ok(s)
}

fn identity(cfg: &Config) -> anyhow::Result<ServerIdentity> {
    let (c, k) = cfg.tls_paths();
    Ok(ServerIdentity::load_or_create(&c, &k, &cfg.tls_names)?)
}

fn pair_cmd(cfg: &Config, op: &PairOp) -> anyhow::Result<()> {
    let st = DeviceStore::new(cfg.devices_path());
    let audit = match cfg.audit_log.clone() {
        Some(p) => AuditLog::open(&p)?,
        None => AuditLog::open(&cfg.state_dir().join("audit.log"))?,
    };
    match op {
        PairOp::Add { name } => {
            let (d, tok) = st.pair(name)?;
            audit.record("device_paired", &[("device", &d.id), ("name", &d.name)]);
            println!("dispositivo: {}", d.id);
            println!("token:       {}", tok.as_str());
            println!(
                "impressao digital do servidor: {}",
                identity(cfg)?.fingerprint()
            );
            println!("\nO token nao fica guardado no servidor; entregue-o ao dispositivo agora.");
            println!(
                "Cliente: openvnc info <host> ... --tls --pin <impressao> --user {} \
                 --password-stdin",
                d.id
            );
        }
        PairOp::List => {
            for d in st.list()? {
                println!(
                    "{}\t{}\t{}\t{}",
                    d.id,
                    if d.revoked { "revogado" } else { "ativo" },
                    d.created,
                    d.name
                );
            }
        }
        PairOp::Revoke { id } => {
            st.revoke(id)?;
            audit.record("device_revoked", &[("device", id)]);
            println!("{id} revogado");
        }
    }
    Ok(())
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
    let (frames, screens) = spawn_capture(capture, cfg.max_fps)?;
    let input = if cfg.view_only {
        None
    } else {
        let inj: Box<dyn InputInjector> = match cfg.capture {
            CaptureKind::TestPattern => Box::new(NullInjector),
            CaptureKind::Native => openvnc_platform::native_injector()?,
        };
        Some(spawn_injector(inj))
    };
    let tls = if cfg.tls {
        let id = identity(&cfg)?;
        tracing::info!(fingerprint = %id.fingerprint(), require = cfg.require_tls, "TLS ativo");
        Some(id.acceptor()?)
    } else {
        None
    };
    let devices = cfg.pairing.then(|| DeviceStore::new(cfg.devices_path()));
    let audit = Arc::new(match cfg.audit_path() {
        Some(p) => AuditLog::open(&p)?,
        None => AuditLog::disabled(),
    });
    if let Err(e) = start_audit_forward(&cfg, &audit) {
        tracing::warn!("encaminhamento da auditoria ao central desligado: {e}");
    }
    audit.record(
        "server_start",
        &[
            ("listen", &cfg.listen.to_string()),
            (
                "tls",
                if cfg.require_tls {
                    "required"
                } else if cfg.tls {
                    "offered"
                } else {
                    "off"
                },
            ),
        ],
    );
    let native = match cfg.native_listen {
        Some(a) => {
            let l = native::bind(a, &cfg).await?;
            tracing::info!(addr = %l.local_addr()?, "protocolo nativo (QUIC + TCP/TLS)");
            Some(l)
        }
        None => None,
    };
    let oidc = match (&cfg.oidc_issuer, &cfg.oidc_client_id) {
        (Some(issuer), Some(aud)) => {
            let ca = match &cfg.oidc_ca {
                Some(p) => {
                    Some(std::fs::read(p).with_context(|| format!("lendo {}", p.display()))?)
                }
                None => None,
            };
            let v = openvnc_security::oidc::Verifier::new(
                openvnc_security::oidc::Policy {
                    issuer: issuer.clone(),
                    audience: aud.clone(),
                    user_claim: cfg.oidc_user_claim.clone(),
                    groups_claim: cfg.oidc_groups_claim.clone(),
                    allowed_groups: cfg.oidc_allowed_groups.clone(),
                    machine: cfg.central_machine_id.clone(),
                },
                ca.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("oidc: {e}"))?;
            tracing::info!(%issuer, "SSO OIDC ligado");
            Some(v)
        }
        _ => None,
    };
    let shared = Arc::new(Shared {
        oidc,
        cfg,
        password,
        frames,
        screens,
        input,
        clients: AtomicUsize::new(0),
        tls,
        devices,
        audit,
        lockout: lockout::Lockout::default(),
    });
    if let Some(l) = native {
        tokio::spawn(native::serve(l, shared.clone()));
    }
    loop {
        let (sock, peer) = listener.accept().await?;
        if !shared.cfg.peer_allowed(peer.ip()) {
            tracing::warn!(%peer, "fora da rede local; recusado");
            shared.audit.record(
                "rejected",
                &[("peer", &peer.to_string()), ("reason", "lan_only")],
            );
            continue;
        }
        if let Some(left) = shared.lockout.blocked(peer.ip(), Instant::now()) {
            tracing::warn!(%peer, secs = left.as_secs(), "bloqueado por falhas de autenticacao");
            shared.audit.record(
                "rejected",
                &[("peer", &peer.to_string()), ("reason", "lockout")],
            );
            continue;
        }
        let n = shared.clients.load(Ordering::SeqCst);
        if n >= shared.cfg.max_clients {
            tracing::warn!(%peer, "limite de clientes; recusado");
            shared.audit.record(
                "rejected",
                &[("peer", &peer.to_string()), ("reason", "max_clients")],
            );
            continue;
        }
        shared.clients.fetch_add(1, Ordering::SeqCst);
        tray::CLIENTS.fetch_add(1, Ordering::Relaxed);
        let sh = shared.clone();
        tokio::spawn(async move {
            tracing::info!(%peer, "conectado");
            let p = peer.to_string();
            sh.audit.record("connect", &[("peer", &p)]);
            if let Err(e) = serve(sock, &sh, &p).await {
                tracing::info!(%peer, "desconectado: {e:#}");
                sh.audit
                    .record("disconnect", &[("peer", &p), ("error", &format!("{e:#}"))]);
            } else {
                tracing::info!(%peer, "desconectado");
                sh.audit.record("disconnect", &[("peer", &p)]);
            }
            sh.clients.fetch_sub(1, Ordering::SeqCst);
            tray::CLIENTS.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Thread de captura com FPS adaptativo: no maximo `max_fps`; a cada
/// quadro identico ao anterior o intervalo dobra (ate 250 ms), e volta ao
/// minimo na primeira mudanca.
fn spawn_capture(
    mut cap: Box<dyn ScreenCapture>,
    max_fps: u32,
) -> anyhow::Result<(watch::Receiver<Frame>, Screens)> {
    let (w, h) = cap.size();
    let req = Arc::new(AtomicU8::new(NO_REQUEST));
    let (info_tx, info) = watch::channel(cap.screens());
    let screens = Screens {
        req: req.clone(),
        info,
    };
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
                let want = req.swap(NO_REQUEST, Ordering::Relaxed);
                if want != NO_REQUEST {
                    match cap.select_screen(want) {
                        Ok(()) => tracing::info!(monitor = want, "monitor trocado"),
                        Err(e) => tracing::warn!("troca de monitor falhou: {e}"),
                    }
                    let _ = info_tx.send(cap.screens());
                }
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
    Ok((rx, screens))
}

fn spawn_injector(mut inj: Box<dyn InputInjector>) -> mpsc::Sender<Input> {
    let (tx, rx) = mpsc::channel::<Input>();
    std::thread::spawn(move || {
        for ev in rx {
            let r = match ev {
                Input::Key(k) => inj.key(k),
                Input::Pointer(p) => {
                    tracing::trace!(x = p.x, y = p.y, buttons = p.buttons, "ponteiro");
                    inj.pointer(p)
                }
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

fn verifier(
    st: Option<DeviceStore>,
    hash: Option<String>,
    ext: Option<(Vec<String>, Duration)>,
    audit: Arc<AuditLog>,
    peer: String,
    who: Arc<std::sync::Mutex<String>>,
) -> PlainVerifier {
    PlainVerifier(Arc::new(move |user: &str, token: &[u8]| {
        // conta da empresa (LDAP/AD/SSO): nome que nao e dispositivo pareado
        if let Some((cmd, t)) = &ext {
            // arquivo ilegivel conta como dispositivo: falha fechada
            let is_device = st.as_ref().is_some_and(|s| {
                s.list()
                    .map(|d| d.iter().any(|x| x.id == user))
                    .unwrap_or(true)
            });
            if user != config::REMOTE_USER && !user.is_empty() && !is_device {
                return match extauth::check(cmd, *t, user, &peer, token) {
                    Ok(()) => {
                        audit.record("user_auth", &[("peer", &peer), ("user", user)]);
                        if let Ok(mut w) = who.lock() {
                            *w = user.to_string();
                        }
                        true
                    }
                    Err(why) => {
                        audit.record(
                            "user_auth_failed",
                            &[("peer", &peer), ("user", user), ("reason", &why)],
                        );
                        false
                    }
                };
            }
        }
        if user == config::REMOTE_USER || user.is_empty() {
            let ok = hash.as_deref().is_some_and(|h| passhash::verify(token, h));
            if ok {
                audit.record(
                    "password_auth",
                    &[("peer", &peer), ("user", config::REMOTE_USER)],
                );
            } else {
                audit.record(
                    "password_auth_failed",
                    &[("peer", &peer), ("user", config::REMOTE_USER)],
                );
            }
            return ok;
        }
        let Some(st) = &st else { return false };
        let v = st.verify(user, token);
        if v == Verdict::Ok {
            audit.record("device_auth", &[("peer", &peer), ("device", user)]);
        } else {
            audit.record(
                "device_auth_failed",
                &[("peer", &peer), ("device", user), ("reason", v.as_str())],
            );
        }
        v == Verdict::Ok
    }))
}

async fn serve(sock: TcpStream, sh: &Shared, peer: &str) -> anyhow::Result<()> {
    sock.set_nodelay(true)?;
    let mut sock: BoxStream = Box::new(sock);
    let mut frames = sh.frames.clone();
    let first = frames.borrow_and_update().clone();
    // usuario da empresa autenticado (mostrado no pedido de aprovacao)
    let who = Arc::new(std::sync::Mutex::new(String::new()));
    let mut srv = Server::new(
        ServerConfig {
            password: sh.password.clone().map(Password::new),
            allow_no_auth: sh.cfg.allow_no_auth || sh.cfg.allow_attended,
            name: sh.cfg.name.clone(),
            challenge: challenge()?,
            vencrypt: sh.tls.is_some(),
            require_tls: sh.cfg.require_tls,
            plain: (sh.devices.is_some()
                || sh.cfg.password_hash.is_some()
                || sh.cfg.ext_auth().is_some())
            .then(|| {
                verifier(
                    sh.devices.clone(),
                    sh.cfg.password_hash.clone(),
                    sh.cfg
                        .ext_auth()
                        .map(|c| (c.to_vec(), Duration::from_secs(sh.cfg.auth_timeout_secs))),
                    sh.audit.clone(),
                    peer.to_string(),
                    who.clone(),
                )
            }),
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
    // aprovacao do usuario local, valida enquanto a sessao durar
    let mut _approval: Option<tray::Approval> = None;
    let mut idle = idle::Idle::new(peer, sh.cfg.idle_timeout_secs);
    let mut size = (first.fb.width(), first.fb.height());
    let (mut updates, mut bytes, mut since) = (0u32, 0usize, Instant::now());
    loop {
        let out = srv.take_output();
        if !out.is_empty() {
            bytes += out.len();
            sock.write_all(&out).await?;
            sock.flush().await?;
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
                    // conta antes de responder: o cliente nao pode reconectar
                    // antes de a falha valer
                    sh.audit.record("auth_failed", &[("peer", peer)]);
                    lock_fail(sh, peer);
                    let out = srv.take_output();
                    sock.write_all(&out).await?;
                    // entrega o motivo e fecha o TLS limpo (close_notify)
                    let _ = sock.shutdown().await;
                    anyhow::bail!("autenticacao falhou");
                }
                ServerEvent::StartTls => {
                    let out = srv.take_output();
                    sock.write_all(&out).await?;
                    sock.flush().await?;
                    let acc = sh.tls.as_ref().expect("vencrypt so com TLS");
                    let hs = tokio::time::timeout(Duration::from_secs(10), acc.accept(sock));
                    sock = Box::new(
                        hs.await
                            .map_err(|_| anyhow::anyhow!("timeout no handshake TLS"))?
                            .context("handshake TLS")?,
                    );
                    let sub = srv.tls_subtype().unwrap_or(0).to_string();
                    sh.audit.record("tls", &[("peer", peer), ("subtype", &sub)]);
                    srv.tls_established()?;
                    // ex.: desafio do X509Vnc; enviar ja, antes do proximo read
                    let out = srv.take_output();
                    sock.write_all(&out).await?;
                    sock.flush().await?;
                }
                // o verificador ja registrou o tipo certo de login
                // (password_auth, device_auth ou user_auth)
                ServerEvent::PlainLogin { .. } => {}
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
                    idle.touch();
                    if let Some(tx) = &sh.input {
                        let _ = tx.send(Input::Key(k));
                    }
                }
                ServerEvent::Pointer(p) => {
                    idle.touch();
                    if let Some(tx) = &sh.input {
                        let _ = tx.send(Input::Pointer(p));
                    }
                }
                ServerEvent::Initialized { shared, version } => {
                    tracing::debug!(shared, ?version, "cliente pronto");
                    // sem credencial, so com autorizacao local (allow_attended)
                    let ask = sh.cfg.ask_before_accept
                        || (srv.unauthenticated() && !sh.cfg.allow_no_auth);
                    let label = who.lock().map(|w| w.clone()).unwrap_or_default();
                    if ask {
                        _approval = tray::ask_once(&label, peer).await;
                        if _approval.is_none() {
                            sh.audit
                                .record("rejected", &[("peer", peer), ("reason", "local_user")]);
                            anyhow::bail!("recusado pelo usuario local");
                        }
                    }
                    let enc = if srv.tls_subtype().is_some() {
                        "tls"
                    } else {
                        "none"
                    };
                    sh.audit
                        .record("session", &[("peer", peer), ("encryption", enc)]);
                    if let Some(ip) = lockout::peer_ip(peer) {
                        sh.lockout.success(ip);
                    }
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
                if let Err(e) = srv.feed(&buf[..n]) {
                    // entrega o motivo (ex.: SecurityResult de falha) e
                    // fecha limpo (close_notify no TLS). Falha de senha
                    // conta antes de responder: o cliente nao pode
                    // reconectar antes de o bloqueio valer
                    while let Some(ev) = srv.poll_event() {
                        if matches!(ev, ServerEvent::AuthFailed) {
                            sh.audit.record("auth_failed", &[("peer", peer)]);
                            lock_fail(sh, peer);
                        }
                    }
                    let out = srv.take_output();
                    let _ = sock.write_all(&out).await;
                    let _ = sock.shutdown().await;
                    sh.audit
                        .record("protocol_error", &[("peer", peer), ("error", &e.to_string())]);
                    return Err(e.into());
                }
            }
            r = frames.changed(), if view.pending.is_some() => {
                if r.is_err() {
                    anyhow::bail!("captura encerrada");
                }
            }
            _ = tokio::time::sleep_until(idle.deadline().into()) => {
                if !idle.expired() {
                    continue;
                }
                sh.audit.record("idle_timeout", &[("peer", peer)]);
                let _ = sock.shutdown().await;
                return Ok(());
            }
        }
    }
}

/// Conta uma falha de autenticacao de `peer` e audita se virou bloqueio.
pub(crate) fn lock_fail(sh: &Shared, peer: &str) {
    let Some(ip) = lockout::peer_ip(peer) else {
        return;
    };
    if let Some(d) = sh.lockout.fail(ip, Instant::now()) {
        let secs = d.as_secs().to_string();
        tracing::warn!(peer, secs, "IP bloqueado por falhas de autenticacao");
        sh.audit
            .record("lockout", &[("peer", peer), ("secs", &secs)]);
    }
}

/// Encaminha a auditoria ao servidor central numa thread propria: fila
/// limitada, envio em lotes, melhor esforco (falhas so geram aviso e o
/// segredo nunca vai para o log).
fn start_audit_forward(cfg: &config::Config, audit: &AuditLog) -> anyhow::Result<()> {
    let (Some(url), Some(id)) = (&cfg.central_url, &cfg.central_machine_id) else {
        return Ok(());
    };
    let secret = cfg
        .central_secret()
        .ok_or_else(|| anyhow::anyhow!("central_secret ausente"))?;
    let ca = match &cfg.oidc_ca {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("lendo {}", p.display()))?),
        None => None,
    };
    let c = openvnc_security::central::Central::new(url, ca.as_deref())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
    audit.set_forward(tx);
    let id = id.clone();
    std::thread::Builder::new()
        .name("audit-central".into())
        .spawn(move || {
            let mut warned = false;
            while let Ok(first) = rx.recv() {
                let mut batch = first;
                while let Ok(l) = rx.try_recv() {
                    batch.push('\n');
                    batch.push_str(&l);
                    if batch.len() > 128 * 1024 {
                        break;
                    }
                }
                match c.send_audit(&id, &secret, &batch) {
                    Ok(()) => warned = false,
                    Err(e) if !warned => {
                        tracing::warn!("auditoria nao enviada ao central: {e}");
                        warned = true;
                    }
                    Err(_) => {}
                }
            }
        })?;
    tracing::info!(%url, "auditoria encaminhada ao servidor central");
    Ok(())
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

    /// Handshake VeNCrypt completo pelo servidor real; devolve o resultado
    /// (`Ok` = chegou ao primeiro quadro).
    async fn tls_session(
        addr: std::net::SocketAddr,
        fp: String,
        cc: CConfig,
    ) -> Result<(), String> {
        use openvnc_transport::tls::{ClientTls, Trust};
        let tls = ClientTls {
            trust: Trust::Pinned(fp),
        };
        let mut sock: BoxStream = Box::new(TcpStream::connect(addr).await.unwrap());
        let mut c = Client::new(CConfig {
            require_tls: true,
            ..cc
        });
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let out = c.take_output();
            if !out.is_empty() {
                sock.write_all(&out).await.unwrap();
                sock.flush().await.unwrap();
            }
            let mut start = false;
            while let Some(e) = c.poll_event() {
                match e {
                    Event::StartTls => start = true,
                    Event::UpdateComplete => return Ok(()),
                    _ => {}
                }
            }
            if start {
                sock = Box::new(
                    tls.connect(sock, "localhost", "t")
                        .await
                        .map_err(|e| e.to_string())?,
                );
                c.tls_established().map_err(|e| e.to_string())?;
                continue;
            }
            let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
                .await
                .expect("timeout")
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("servidor fechou".into());
            }
            c.feed(&buf[..n]).map_err(|e| e.to_string())?;
        }
    }

    fn tls_cfg(dir: &std::path::Path) -> Config {
        Config {
            test_pattern_size: (64, 48),
            require_tls: true,
            tls: true,
            state_dir: Some(dir.to_path_buf()),
            ..Default::default()
        }
    }

    async fn native_roundtrip(t: openvnc_client::native::NativeTransport) {
        use openvnc_client::native::*;
        use openvnc_transport::tls::{ClientTls, Trust};
        let dir = tempfile::tempdir().unwrap();
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut cfg = tls_cfg(dir.path());
        cfg.native_listen = Some(([127, 0, 0, 1], port).into());
        let fp = identity(&cfg).unwrap().fingerprint();
        start(cfg, Some("teste")).await;
        let mut o = NativeOptions {
            address: format!("127.0.0.1:{port}"),
            tls: ClientTls {
                trust: Trust::Pinned(fp),
            },
            transport: t,
            auth: NativeAuth::Password("teste".into()),
            timeout: std::time::Duration::from_secs(5),
        };
        let mut c = None;
        for _ in 0..50 {
            match NativeClient::connect(&o).await {
                Ok(x) => {
                    c = Some(x);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        let mut c = c.expect("conexao nativa");
        assert_eq!(
            (c.framebuffer().width(), c.framebuffer().height()),
            (64, 48)
        );
        let ev = tokio::time::timeout(std::time::Duration::from_secs(5), c.next_event())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(ev, NativeEvent::Frame(ref r) if !r.is_empty()));
        assert!(c.framebuffer().data().iter().any(|&b| b != 0));
        c.send_input(openvnc_protocol::Input::Pointer {
            x: 1,
            y: 1,
            buttons: 0,
        })
        .unwrap();
        c.close().await;
        // senha errada e recusada
        o.auth = NativeAuth::Password("errada".into());
        assert!(NativeClient::connect(&o).await.is_err());
    }

    #[tokio::test]
    async fn native_quic() {
        native_roundtrip(openvnc_client::native::NativeTransport::Quic).await;
    }

    #[tokio::test]
    async fn native_tcp_tls() {
        native_roundtrip(openvnc_client::native::NativeTransport::Tcp).await;
    }

    /// Envia um arquivo ao servidor e recebe outro dele, em loopback.
    #[tokio::test]
    async fn native_file_transfer() {
        use openvnc_client::native::*;
        use openvnc_transport::tls::{ClientTls, Trust};
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut cfg = tls_cfg(dir.path());
        cfg.native_listen = Some(([127, 0, 0, 1], port).into());
        cfg.files_send = true;
        cfg.files_receive = true;
        cfg.files_dir = Some(dir.path().join("srv-in"));
        let fp = identity(&cfg).unwrap().fingerprint();
        files::set_sending(true);
        start(cfg, Some("teste")).await;
        let o = NativeOptions {
            address: format!("127.0.0.1:{port}"),
            tls: ClientTls {
                trust: Trust::Pinned(fp),
            },
            transport: NativeTransport::Tcp,
            auth: NativeAuth::Password("teste".into()),
            timeout: Duration::from_secs(5),
        };
        let mut c = None;
        for _ in 0..50 {
            match NativeClient::connect(&o).await {
                Ok(x) => {
                    c = Some(x);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        let mut c = c.expect("conexao nativa");
        c.set_download_dir(dir.path().join("cli-in"), u64::MAX);
        async fn ev(c: &mut NativeClient) -> NativeEvent {
            tokio::time::timeout(Duration::from_secs(10), c.next_event())
                .await
                .expect("tempo esgotado")
                .expect("evento")
        }

        // cliente -> servidor (mais de um bloco)
        let up: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let src = dir.path().join("subida.bin");
        std::fs::write(&src, &up).unwrap();
        let id = c.offer_file(src).unwrap();
        let mut answered = false;
        loop {
            match ev(&mut c).await {
                NativeEvent::FileAnswer { id: i, accepted } if i == id => {
                    assert!(accepted);
                    answered = true;
                }
                NativeEvent::FileSent { id: i, bytes } if i == id => {
                    assert_eq!(bytes, up.len() as u64);
                    break;
                }
                NativeEvent::FileFailed { reason, .. } => panic!("{reason}"),
                _ => {}
            }
        }
        assert!(answered);
        let dest = dir.path().join("srv-in").join("subida.bin");
        let mut ok = false;
        for _ in 0..100 {
            if std::fs::read(&dest).ok().as_deref() == Some(&up[..]) {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ok, "servidor nao gravou o arquivo");

        // servidor -> cliente (a sessao ja assinou as ofertas)
        let down = b"ola do servidor".to_vec();
        let src = dir.path().join("descida.txt");
        std::fs::write(&src, &down).unwrap();
        assert!(files::offer_file(src) >= 1);
        let got = loop {
            match ev(&mut c).await {
                NativeEvent::FileOffer { id, name, size } if name == "descida.txt" => {
                    assert_eq!(size, down.len() as u64);
                    c.accept_file(id).unwrap();
                }
                NativeEvent::FileOffer { id, .. } => c.reject_file(id).unwrap(),
                NativeEvent::FileReceived { path, .. } => break path,
                NativeEvent::FileFailed { reason, .. } => panic!("{reason}"),
                _ => {}
            }
        };
        assert_eq!(std::fs::read(got).unwrap(), down);
        c.close().await;
    }

    #[tokio::test]
    async fn tls_with_pinned_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = tls_cfg(dir.path());
        let fp = identity(&cfg).unwrap().fingerprint();
        let addr = start(cfg, Some("teste")).await;
        let cc = || CConfig {
            password: Some(Password::new("teste")),
            ..Default::default()
        };
        tls_session(addr, fp, cc()).await.unwrap();
        // impressao digital errada: falha no handshake
        let other = ServerIdentity::self_signed(&["localhost".into()])
            .unwrap()
            .fingerprint();
        assert!(tls_session(addr, other, cc()).await.is_err());
        // cliente sem TLS nao consegue nada (sem downgrade)
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut c = Client::new(cc());
        let mut buf = vec![0u8; 4096];
        let mut failed = false;
        for _ in 0..4 {
            let out = c.take_output();
            s.write_all(&out).await.unwrap();
            let n = s.read(&mut buf).await.unwrap_or(0);
            if n == 0 || c.feed(&buf[..n]).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
        let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(log.contains("\"tls\""), "{log}");
    }

    #[tokio::test]
    async fn paired_device_then_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = tls_cfg(dir.path());
        cfg.pairing = true;
        let fp = identity(&cfg).unwrap().fingerprint();
        let st = DeviceStore::new(cfg.devices_path());
        let (d, tok) = st.pair("notebook").unwrap();
        let addr = start(cfg, None).await;
        let cc = |t: &str| CConfig {
            username: Some(d.id.clone()),
            password: Some(Password::new(t)),
            ..Default::default()
        };
        tls_session(addr, fp.clone(), cc(tok.as_str()))
            .await
            .unwrap();
        assert!(tls_session(addr, fp.clone(), cc("errado")).await.is_err());
        st.revoke(&d.id).unwrap();
        assert!(tls_session(addr, fp, cc(tok.as_str())).await.is_err());
        let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(log.contains("\"device_auth\""), "{log}");
        assert!(log.contains("revoked"), "{log}");
        assert!(log.contains("bad_token"), "{log}");
    }

    /// Ponta a ponta: 5 senhas erradas bloqueiam o IP, inclusive a senha
    /// certa, e o bloqueio vai para a auditoria.
    #[tokio::test]
    async fn forca_bruta_bloqueia_o_ip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = tls_cfg(dir.path());
        let fp = identity(&cfg).unwrap().fingerprint();
        let addr = start(cfg, Some("certa")).await;
        let cc = |p: &str| CConfig {
            password: Some(Password::new(p)),
            ..Default::default()
        };
        tls_session(addr, fp.clone(), cc("certa")).await.unwrap();
        for _ in 0..lockout::FREE_FAILS {
            assert!(tls_session(addr, fp.clone(), cc("errada")).await.is_err());
        }
        // bloqueado: nem a senha certa entra
        assert!(tls_session(addr, fp, cc("certa")).await.is_err());
        let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(log.contains("\"lockout\""), "{log}");
        assert!(log.contains("\"reason\":\"lockout\""), "{log}");
        assert!(
            !log.contains("errada") && !log.contains("certa"),
            "senha no log: {log}"
        );
    }
}
