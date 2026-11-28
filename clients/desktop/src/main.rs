//! Cliente VNC desktop: egui + wgpu. A rede roda numa task tokio
//! (`openvnc-client`); a UI apenas le o quadro compartilhado e envia entrada.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub(crate) mod explorer;
mod hud;
mod input;
mod native;
pub(crate) mod transfer;

use std::sync::Arc;

use eframe::egui;
use openvnc_client::native::NativeAuth;
use openvnc_client::{Command, ConnectOptions, Session, SessionEvent};
use openvnc_core::PointerEvent;
use openvnc_rfb::Password;
use openvnc_transport::tls::{load_certs, normalize_fingerprint, ClientTls, KnownHosts, Trust};

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    // `openvnc-desktop [host]` conecta direto (senha via OPENVNC_PASSWORD)
    let target = std::env::args().nth(1);
    // Com host na linha de comando o padrao e o renderer nativo (softbuffer,
    // ~12 MB); OPENVNC_RENDERER=glow|wgpu volta para a GUI egui.
    let renderer = std::env::var("OPENVNC_RENDERER").unwrap_or_default();
    if let (Some(t), "" | "native") = (&target, renderer.as_str()) {
        if let Err(e) = run_native_renderer(t) {
            eprintln!("openvnc-desktop: {e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("OpenVNC")
            .with_inner_size([1024.0, 768.0])
            .with_icon(std::sync::Arc::new(
                eframe::icon_data::from_png_bytes(include_bytes!(
                    "../../../assets/brand/openvnc-256.png"
                ))
                .unwrap_or_default(),
            )),
        // Padrao: OpenGL (glow), ~100 MB de RAM contra ~360 MB do wgpu
        // sobre Vulkan medidos no Windows. OPENVNC_RENDERER=wgpu troca.
        renderer: match std::env::var("OPENVNC_RENDERER").as_deref() {
            Ok("wgpu") => eframe::Renderer::Wgpu,
            _ => eframe::Renderer::Glow,
        },
        ..Default::default()
    };
    eframe::run_native(
        "OpenVNC",
        opts,
        Box::new(move |cc| {
            ui_style(&cc.egui_ctx);
            let mut app = App::new();
            if let Some(t) = target {
                app.host = t;
                if let Ok(p) = std::env::var("OPENVNC_PASSWORD") {
                    app.password = p;
                }
                app.connect(&cc.egui_ctx);
            }
            Ok(Box::new(app))
        }),
    )
}

fn run_native_renderer(host: &str) -> anyhow::Result<()> {
    let mut o = ConnectOptions::new(openvnc_transport::parse_address(host)?);
    if let Ok(p) = std::env::var("OPENVNC_PASSWORD") {
        o.config.password = Some(Password::new(p));
    }
    // OPENVNC_TLS=tofu (padrao)|tofu-accept|tls|pin:<sha256>|ca:<arquivo>|none,
    // OPENVNC_USER=<dispositivo>. Sem TLS so quando pedido explicitamente (none).
    let sec = std::env::var("OPENVNC_TLS").unwrap_or_default();
    let (mode, arg) = sec.split_once(':').unwrap_or((sec.as_str(), ""));
    let (mode, accept) = match mode {
        "" | "tofu" => (Security::Tofu, false),
        "none" | "plain" => (Security::None, false),
        "tls" => (Security::WebPki, false),
        "tofu-accept" => (Security::Tofu, true),
        "pin" => (Security::Pin, false),
        "ca" => (Security::Ca, false),
        m => anyhow::bail!("OPENVNC_TLS invalido: {m}"),
    };
    o.tls = build_tls(mode, arg, accept)?;
    o.config.username = std::env::var("OPENVNC_USER").ok().filter(|u| !u.is_empty());
    if o.tls.is_none() && o.config.username.is_some() {
        anyhow::bail!("OPENVNC_USER exige OPENVNC_TLS");
    }
    native::run(o)
}

/// Remove caracteres de controle da area de transferencia recebida, exceto
/// quebra de linha, tab e retorno de carro.
fn clean_clipboard(t: &str) -> String {
    t.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t' | '\r'))
        .collect()
}

/// Modo de seguranca escolhido na tela de conexao.
#[derive(PartialEq, Clone, Copy, Debug)]
enum Security {
    None,
    WebPki,
    Tofu,
    Pin,
    Ca,
}

impl Security {
    fn label(self) -> &'static str {
        match self {
            Security::None => "Sem TLS (legado)",
            Security::WebPki => "TLS (CA publica)",
            Security::Tofu => "TLS (confiar na 1a conexao)",
            Security::Pin => "TLS (impressao fixa)",
            Security::Ca => "TLS (CA propria, PEM)",
        }
    }
}

fn build_tls(mode: Security, arg: &str, accept_new: bool) -> anyhow::Result<Option<ClientTls>> {
    let trust = match mode {
        Security::None => return Ok(None),
        Security::WebPki => Trust::default(),
        Security::Pin => Trust::Pinned(normalize_fingerprint(arg)?),
        Security::Ca => Trust::WebPki {
            extra_roots: load_certs(&std::fs::read(arg)?)?,
        },
        Security::Tofu => Trust::Tofu {
            store: KnownHosts::new(
                KnownHosts::default_path()
                    .ok_or_else(|| anyhow::anyhow!("sem diretorio para known_hosts"))?,
            ),
            accept_new,
        },
    };
    Ok(Some(ClientTls { trust }))
}

/// Falha de confianca TLS detectada no motivo da desconexao.
enum TrustIssue {
    /// Host novo em TOFU: pedir confirmacao da impressao digital.
    Unknown(String),
    /// Certificado diferente do conhecido: bloqueia.
    Changed(String),
}

fn trust_issue(reason: &str) -> Option<TrustIssue> {
    if reason.contains("CERTIFICADO MUDOU") {
        return Some(TrustIssue::Changed(reason.to_string()));
    }
    let i = reason.find("host desconhecido")?;
    let fp = reason[i..]
        .split("fingerprint ")
        .nth(1)
        .and_then(|r| r.split(')').next())
        .unwrap_or("?");
    Some(TrustIssue::Unknown(fp.to_string()))
}

#[derive(PartialEq, Clone, Copy)]
enum Scale {
    Fit,
    Native,
}

struct Remote {
    session: Session,
    texture: Option<egui::TextureHandle>,
    generation: u64,
    title: String,
    status: String,
    legacy_auth: bool,
    encrypted: bool,
    connected: bool,
    ended: bool,
    /// recebeu ao menos um update de tela (sessao realmente aberta)
    got_frame: bool,
    keys: input::KeyState,
    buttons: u8,
    last_pos: (u16, u16),
    /// Cursor remoto (textura, ponto quente).
    cursor: Option<(egui::TextureHandle, egui::Vec2)>,
    /// Conexao nativa de arquivos (aberta apos o RFB conectar, se houver TLS).
    files: Option<transfer::FileLink>,
    /// Endereco nativo e credenciais para abrir `files`.
    files_plan: Option<(String, NativeAuth)>,
    show_files: bool,
    /// Explorador em dois paineis (criado ao abrir).
    explorer: Option<explorer::Explorer>,
    show_explorer: bool,
    send_path: String,
    /// Nome exibido na aba (nome do desktop remoto, ou o endereco).
    label: String,
    /// Seguranca usada nesta conexao (para abrir a conexao de arquivos).
    security: Security,
    tls_arg: String,
    /// Conectou informando senha/token (para explicar recusas).
    had_password: bool,
    /// A janela ja foi ajustada ao tamanho remoto.
    fitted: bool,
}

const REMOTE_FOCUS_ID: &str = "openvnc_remote_focus";
const OSK_ID: &str = "openvnc_osk";

/// Se o teclado virtual do celular deve aparecer: campos de texto sempre;
/// na tela remota, so quando o botao "Teclado" esta ligado (senao cada
/// toque do mouse virtual abriria o teclado).
#[allow(dead_code)]
pub fn wants_soft_keyboard(ctx: &egui::Context) -> bool {
    let (remote, osk) = ctx.data(|d| {
        (
            d.get_temp::<bool>(egui::Id::new(REMOTE_FOCUS_ID))
                .unwrap_or(false),
            d.get_temp::<bool>(egui::Id::new(OSK_ID)).unwrap_or(false),
        )
    });
    if osk {
        true
    } else if remote {
        false
    } else {
        ctx.wants_keyboard_input()
    }
}

/// Chamado a cada quadro no celular; devolve as faixas (topo, base) cobertas
/// pelas barras do sistema.
pub type MobileHook = Box<dyn FnMut(&egui::Context) -> (f32, f32)>;

/// Ponto de entrada da GUI compartilhado com o app Android
/// (`clients/android`): abre a tela de conexao com o mouse virtual ligado e
/// chama `hook` a cada quadro (ex.: mostrar o teclado virtual).
#[allow(dead_code)]
pub fn run_mobile(opts: eframe::NativeOptions, hook: MobileHook) -> eframe::Result<()> {
    struct Mobile {
        app: App,
        hook: MobileHook,
    }
    impl eframe::App for Mobile {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            // o hook devolve as faixas (em pontos) cobertas pela barra de status
            // e pela de navegacao; reservadas antes da UI para nada ficar por baixo
            let (top, bottom) = (self.hook)(ctx);
            for (id, h, is_top) in [("safe_top", top, true), ("safe_bottom", bottom, false)] {
                if h > 0.0 {
                    let p = if is_top {
                        egui::TopBottomPanel::top(id)
                    } else {
                        egui::TopBottomPanel::bottom(id)
                    };
                    p.exact_height(h)
                        .show_separator_line(false)
                        .frame(egui::Frame::default().fill(ctx.style().visuals.panel_fill))
                        .show(ctx, |_| {});
                }
            }
            self.app.update(ctx, frame);
        }
    }
    eframe::run_native(
        "OpenVNC",
        opts,
        Box::new(move |cc| {
            ui_style(&cc.egui_ctx);
            // telas pequenas: tudo um pouco maior para o dedo
            cc.egui_ctx.set_zoom_factor(1.0);
            let mut app = App::new();
            app.touchpad = true;
            app.mobile = true;
            Ok(Box::new(Mobile { app, hook }))
        }),
    )
}

struct App {
    rt: tokio::runtime::Runtime,
    /// Celular: barra compacta e explorador em painel unico.
    mobile: bool,
    host: String,
    password: String,
    shared: bool,
    scale: Scale,
    /// Mouse virtual: arrastar move o cursor remoto, toque clica (celular,
    /// tablet, tela de toque).
    touchpad: bool,
    touch_seen: bool,
    /// Teclado virtual do celular para digitar na maquina remota.
    osk: bool,
    fullscreen: bool,
    /// Aceita a area de transferencia enviada pelo servidor (so com a janela em foco).
    recv_clipboard: bool,
    /// Confirmacao explicita para enviar a senha sem TLS.
    plain_ok: bool,
    error: Option<String>,
    /// Conexoes abertas, uma por aba.
    tabs: Vec<Remote>,
    /// Aba ativa; None = tela de nova conexao.
    active: Option<usize>,
    security: Security,
    /// Impressao (Pin) ou caminho do PEM (Ca).
    tls_arg: String,
    user: String,
    /// Senha guardada enquanto se decide uma confirmacao TOFU.
    pending_password: String,
    trust: Option<TrustIssue>,
    /// Porta do protocolo nativo (arquivos); vazio = porta + 1.
    files_port: String,
    /// Porta VNC usada quando o endereco nao traz uma.
    port: String,
    /// Entrar com SSO da empresa (OIDC, protocolo nativo).
    sso: bool,
    /// CA extra (PEM) do provedor de identidade; vazio = CAs do sistema.
    sso_ca: String,
    /// Login SSO em andamento.
    sso_wait: Option<SsoWait>,
    /// Modo servidor central da empresa.
    central: CentralUi,
}

type CentralConn = Arc<(
    openvnc_security::central::Central,
    openvnc_security::central::Session,
)>;

/// Estado do modo "Servidor central da empresa".
#[derive(Default)]
struct CentralUi {
    on: bool,
    url: String,
    ca: String,
    user: String,
    password: String,
    /// Sessao aberta no central.
    conn: Option<CentralConn>,
    /// Maquinas liberadas para o usuario.
    machines: Vec<openvnc_security::central::Machine>,
    /// Tarefa em andamento (login ou ticket).
    busy: Option<std::sync::mpsc::Receiver<CentralMsg>>,
}

/// Respostas das tarefas do modo central.
enum CentralMsg {
    Login(Result<(CentralConn, Vec<openvnc_security::central::Machine>), String>),
    Ticket(Result<(openvnc_client::native::NativeOptions, String), String>),
}

/// Mensagens da tarefa de login SSO para a UI.
enum SsoMsg {
    /// Codigo para aprovar: (url, codigo, validade em s).
    Code(String, String, u64),
    /// Terminou: opcoes autenticadas ou erro.
    Done(Result<openvnc_client::native::NativeOptions, String>),
}

/// Login SSO aguardando aprovacao no navegador.
struct SsoWait {
    rx: std::sync::mpsc::Receiver<SsoMsg>,
    code: Option<(String, String, u64)>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    label: String,
    security: Security,
    tls_arg: String,
}

/// Textos e campos maiores, com mais respiro.
fn ui_style(ctx: &egui::Context) {
    use egui::{FontFamily, FontId, TextStyle};
    ctx.all_styles_mut(|s| {
        s.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(28.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(17.0, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(17.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(14.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(15.0, FontFamily::Monospace),
            ),
        ]
        .into();
        s.spacing.item_spacing = egui::vec2(10.0, 8.0);
        s.spacing.button_padding = egui::vec2(12.0, 7.0);
        s.spacing.interact_size.y = 34.0;
        s.spacing.icon_width = 20.0;
        s.visuals.widgets.inactive.corner_radius = 6.0.into();
        s.visuals.widgets.hovered.corner_radius = 6.0.into();
        s.visuals.widgets.active.corner_radius = 6.0.into();
    });
}

impl App {
    fn new() -> Self {
        App {
            rt: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime tokio"),
            host: String::new(),
            password: String::new(),
            shared: true,
            scale: Scale::Fit,
            touchpad: false,
            touch_seen: false,
            osk: false,
            fullscreen: false,
            recv_clipboard: true,
            plain_ok: false,
            error: None,
            tabs: Vec::new(),
            active: None,
            security: Security::Tofu,
            tls_arg: String::new(),
            user: String::new(),
            pending_password: String::new(),
            trust: None,
            files_port: String::new(),
            port: "5900".into(),
            mobile: false,
            sso: false,
            sso_ca: String::new(),
            sso_wait: None,
            central: CentralUi::default(),
        }
    }

    /// Endereco final: se o campo ja traz porta ou display, vale como esta;
    /// senao junta o host com a porta escolhida.
    fn target(&self) -> String {
        let h = self.host.trim();
        let port = match self.port.trim() {
            "" => "5900",
            p => p,
        };
        let colons = h.matches(':').count();
        if h.starts_with('[') {
            if h.ends_with(']') {
                format!("{h}:{port}")
            } else {
                h.to_string()
            }
        } else if colons > 2 || h.starts_with("::") {
            // IPv6 sem colchetes
            format!("[{h}]:{port}")
        } else if colons > 0 {
            // host:display ou host::porta digitados a mao
            h.to_string()
        } else {
            format!("{h}::{port}")
        }
    }

    fn connect(&mut self, ctx: &egui::Context) {
        self.connect_with(ctx, false);
    }

    fn connect_with(&mut self, ctx: &egui::Context, accept_new: bool) {
        let addr = match openvnc_transport::parse_address(&self.target()) {
            Ok(a) => a,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        let mut o = ConnectOptions::new(addr.clone());
        o.config.shared = self.shared;
        o.tls = match build_tls(self.security, self.tls_arg.trim(), accept_new) {
            Ok(t) => t,
            Err(e) => {
                self.error = Some(format!("TLS: {e:#}"));
                return;
            }
        };
        if o.tls.is_none() && !self.user.is_empty() {
            self.error = Some("usuario/dispositivo exige TLS".into());
            return;
        }
        o.config.username = (!self.user.is_empty()).then(|| self.user.clone());
        if self.security == Security::Tofu && !accept_new {
            // guarda a senha caso seja preciso reconectar apos confirmar o host
            self.pending_password = self.password.clone();
        }
        let files_port = match self.files_port.trim() {
            "" => Ok(addr
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .map_or(5901, |p| p.wrapping_add(1))),
            p => p.parse::<u16>(),
        };
        let files_plan = match (o.tls.is_some(), files_port.clone()) {
            (true, Ok(port)) if port > 0 => {
                let auth = if !self.user.is_empty() && !self.user.starts_with("dev-") {
                    NativeAuth::User {
                        user: self.user.clone(),
                        password: self.password.clone(),
                    }
                } else if !self.user.is_empty() {
                    NativeAuth::Device {
                        id: self.user.clone(),
                        token: self.password.clone(),
                    }
                } else if !self.password.is_empty() {
                    NativeAuth::Password(self.password.clone())
                } else {
                    NativeAuth::None
                };
                Some((transfer::native_address(&addr, port), auth))
            }
            _ => None,
        };
        if self.sso {
            let Some(tls) = o.tls.take() else {
                self.error = Some("SSO exige TLS (escolha uma opcao de seguranca)".into());
                return;
            };
            match files_port {
                Ok(port) if port > 0 => {
                    self.start_sso(ctx, transfer::native_address(&addr, port), tls)
                }
                _ => self.error = Some("porta nativa invalida".into()),
            }
            return;
        }
        let had_password = !self.password.is_empty();
        if had_password {
            o.config.password = Some(Password::new(std::mem::take(&mut self.password)));
        }
        let c = ctx.clone();
        let session = Session::spawn(self.rt.handle(), o, Arc::new(move || c.request_repaint()));
        self.error = None;
        let (label, sec, arg) = (
            self.host.trim().to_string(),
            self.security,
            self.tls_arg.trim().to_string(),
        );
        self.push_tab(session, addr, label, sec, arg, files_plan, had_password);
    }

    /// Inicia o login SSO (codigo de dispositivo) numa tarefa separada.
    fn start_sso(&mut self, ctx: &egui::Context, addr: String, tls: ClientTls) {
        use openvnc_client::native::{NativeClient, NativeOptions, NativeTransport};
        use std::sync::atomic::{AtomicBool, Ordering};
        let ca = match self.sso_ca.trim() {
            "" => None,
            p => match std::fs::read(p) {
                Ok(b) => Some(b),
                Err(e) => {
                    self.error = Some(format!("CA do SSO ({p}): {e}"));
                    return;
                }
            },
        };
        let no = NativeOptions {
            address: addr,
            tls,
            transport: NativeTransport::Auto,
            auth: NativeAuth::None,
            timeout: std::time::Duration::from_secs(15),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let (c1, c2, t1) = (ctx.clone(), ctx.clone(), tx.clone());
        let stop = cancel.clone();
        self.rt.spawn(async move {
            let r = NativeClient::oidc_login(
                &no,
                move |d| {
                    let url = d
                        .verification_uri_complete
                        .clone()
                        .unwrap_or_else(|| d.verification_uri.clone());
                    let _ = t1.send(SsoMsg::Code(url, d.user_code.clone(), d.expires_in));
                    c1.request_repaint();
                },
                move || stop.load(Ordering::Relaxed),
                ca,
            )
            .await;
            let _ = tx.send(SsoMsg::Done(r.map_err(|e| format!("{e:#}"))));
            c2.request_repaint();
        });
        self.error = None;
        self.sso_wait = Some(SsoWait {
            rx,
            code: None,
            cancel,
            label: self.host.trim().to_string(),
            security: self.security,
            tls_arg: self.tls_arg.trim().to_string(),
        });
    }

    /// Tela de espera do SSO. Retorna true enquanto o login esta em andamento.
    fn sso_screen(&mut self, ctx: &egui::Context) -> bool {
        use std::sync::atomic::Ordering;
        let Some(w) = self.sso_wait.as_mut() else {
            return false;
        };
        let mut done = None;
        while let Ok(m) = w.rx.try_recv() {
            match m {
                SsoMsg::Code(u, c, e) => w.code = Some((u, c, e)),
                SsoMsg::Done(r) => done = Some(r),
            }
        }
        if let Some(r) = done {
            let Some(w) = self.sso_wait.take() else {
                return false;
            };
            match r {
                Ok(no) => {
                    let c = ctx.clone();
                    let addr = no.address.clone();
                    let session = Session::spawn_native(
                        self.rt.handle(),
                        no,
                        Arc::new(move || c.request_repaint()),
                    );
                    self.push_tab(session, addr, w.label, w.security, w.tls_arg, None, false);
                }
                Err(e) if w.cancel.load(Ordering::Relaxed) => {
                    tracing::info!("SSO cancelado: {e}");
                }
                Err(e) => match trust_issue(&e) {
                    Some(t) => self.trust = Some(t),
                    None => self.error = Some(format!("SSO: {e}")),
                },
            }
            return false;
        }
        let mut cancel = false;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.heading("Entrar com a conta da empresa");
                ui.add_space(12.0);
                match &w.code {
                    None => {
                        ui.spinner();
                        ui.label("consultando o servidor...");
                    }
                    Some((url, code, exp)) => {
                        ui.label(
                            "Abra o endereco abaixo, entre com sua conta e confirme o codigo:",
                        );
                        ui.add_space(8.0);
                        ui.hyperlink(url);
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(code).size(30.0).strong().monospace());
                        ui.label(egui::RichText::new(format!("valido por {exp} s")).weak());
                        ui.add_space(8.0);
                        ui.spinner();
                    }
                }
                ui.add_space(16.0);
                if w.cancel.load(Ordering::Relaxed) {
                    ui.label("cancelando...");
                } else {
                    cancel = ui.button("Cancelar").clicked();
                }
            });
        });
        if cancel {
            w.cancel.store(true, Ordering::Relaxed);
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn push_tab(
        &mut self,
        session: Session,
        addr: String,
        label: String,
        security: Security,
        tls_arg: String,
        files_plan: Option<(String, NativeAuth)>,
        had_password: bool,
    ) {
        self.tabs.push(Remote {
            session,
            texture: None,
            generation: 0,
            label,
            security,
            tls_arg,
            had_password,
            fitted: false,
            title: addr,
            status: "conectando...".into(),
            legacy_auth: false,
            encrypted: false,
            connected: false,
            ended: false,
            got_frame: false,
            keys: input::KeyState::default(),
            buttons: 0,
            last_pos: (0, 0),
            cursor: None,
            files: None,
            files_plan,
            show_files: false,
            explorer: None,
            show_explorer: false,
            send_path: String::new(),
        });
        self.active = Some(self.tabs.len() - 1);
    }

    /// Remove a aba `i` e ajusta a aba ativa.
    fn close_tab(&mut self, i: usize) {
        self.tabs.remove(i);
        self.active = match self.active {
            _ if self.tabs.is_empty() => None,
            Some(a) if a == i => Some(i.min(self.tabs.len() - 1)),
            Some(a) if a > i => Some(a - 1),
            a => a,
        };
    }

    /// Processa os eventos de todas as conexoes (inclusive abas em segundo plano).
    fn pump(&mut self, ctx: &egui::Context) {
        let mut i = 0;
        while i < self.tabs.len() {
            let mut drop_tab = false;
            let remote = &mut self.tabs[i];
            while let Some(e) = remote.session.try_event() {
                match e {
                    SessionEvent::Connected {
                        width,
                        height,
                        name,
                        legacy_auth,
                        encrypted,
                        ..
                    } => {
                        remote.connected = true;
                        if let Some((addr, auth)) = remote.files_plan.take() {
                            match files_tls(remote.security, &remote.tls_arg, &remote.title) {
                                Ok(tls) => {
                                    remote.files = Some(transfer::FileLink::spawn(
                                        self.rt.handle(),
                                        addr,
                                        tls,
                                        auth,
                                        ctx.clone(),
                                    ));
                                }
                                Err(e) => tracing::warn!("arquivos: {e:#}"),
                            }
                        }
                        remote.legacy_auth = legacy_auth;
                        remote.encrypted = encrypted;
                        if !name.trim().is_empty() {
                            remote.label = name.clone();
                        }
                        remote.status = format!("{name} ({width}x{height})");
                    }
                    SessionEvent::Disconnected { reason, .. } if trust_issue(&reason).is_some() => {
                        // falha de confianca nunca e repetida em silencio
                        self.trust = trust_issue(&reason);
                        drop_tab = true;
                        break;
                    }
                    SessionEvent::Disconnected { reason, retrying } => {
                        remote.connected = false;
                        remote.status = if retrying {
                            format!("conexao perdida ({reason}); reconectando...")
                        } else {
                            remote.ended = true;
                            let r = reason.to_string();
                            if r.contains("sub-tipo VeNCrypt") && !remote.had_password {
                                "Este computador exige senha. Digite a senha de acesso \
                                 remoto definida no servidor."
                                    .to_string()
                            } else if !remote.got_frame
                                && (r.contains("close_notify") || r.contains("recusad"))
                            {
                                "O computador remoto recusou ou nao aprovou a conexao                                  (a pessoa na maquina precisa clicar em Permitir)."
                                    .to_string()
                            } else {
                                format!("desconectado: {r}")
                            }
                        };
                    }
                    SessionEvent::CutText(t) => {
                        // so com a janela em foco, para o servidor nao trocar a area de
                        // transferencia local em segundo plano
                        let focused = ctx.input(|i| i.viewport().focused.unwrap_or(false));
                        if self.recv_clipboard && focused {
                            ctx.copy_text(clean_clipboard(&t));
                        }
                    }
                    SessionEvent::Cursor {
                        hot_x,
                        hot_y,
                        width,
                        height,
                        rgba,
                    } => {
                        remote.cursor = (width > 0 && height > 0).then(|| {
                            let img = egui::ColorImage::from_rgba_unmultiplied(
                                [usize::from(width), usize::from(height)],
                                &rgba,
                            );
                            let tex =
                                ctx.load_texture("cursor", img, egui::TextureOptions::NEAREST);
                            (tex, egui::vec2(f32::from(hot_x), f32::from(hot_y)))
                        });
                    }
                    SessionEvent::Resized { width, height } => {
                        remote.status = format!("{width}x{height}");
                    }
                    SessionEvent::Updated => remote.got_frame = true,
                    SessionEvent::Bell => {}
                }
            }
            if !drop_tab && remote.ended && !remote.connected && !remote.got_frame {
                // nunca chegou a mostrar a tela: volta ao formulario com o erro
                self.error = Some(remote.status.clone());
                drop_tab = true;
            }
            if drop_tab {
                let was_active = self.active == Some(i);
                self.close_tab(i);
                if was_active {
                    self.active = None;
                }
            } else {
                sync_texture(ctx, &mut self.tabs[i]);
                i += 1;
            }
        }
    }

    /// Barra de abas: uma por conexao, mais "+" para abrir outra.
    fn tab_bar(&mut self, ctx: &egui::Context) {
        let mut close = None;
        egui::TopBottomPanel::top("tabs")
            .frame(
                egui::Frame::side_top_panel(&ctx.style())
                    .inner_margin(egui::Margin::symmetric(8, 6)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::horizontal().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        for (i, t) in self.tabs.iter().enumerate() {
                            let dot = if t.connected {
                                egui::RichText::new("\u{25CF}")
                                    .color(egui::Color32::from_rgb(80, 180, 80))
                            } else {
                                egui::RichText::new("\u{25CF}")
                                    .color(egui::Color32::from_rgb(220, 160, 0))
                            };
                            let on = self.active == Some(i);
                            egui::Frame::NONE
                                .fill(if on {
                                    ui.visuals().selection.bg_fill
                                } else {
                                    ui.visuals().widgets.inactive.weak_bg_fill
                                })
                                .corner_radius(8.0)
                                .inner_margin(egui::Margin::symmetric(10, 4))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(dot);
                                        let r = ui
                                            .add(
                                                egui::Label::new(
                                                    egui::RichText::new(&t.label).strong(),
                                                )
                                                .selectable(false)
                                                .sense(egui::Sense::click()),
                                            )
                                            .on_hover_text(format!("{}\n{}", t.title, t.status));
                                        if r.clicked() {
                                            self.active = Some(i);
                                        }
                                        if ui
                                            .add(egui::Button::new("\u{2715}").frame(false))
                                            .on_hover_text("Desconectar e fechar a aba")
                                            .clicked()
                                        {
                                            close = Some(i);
                                        }
                                    });
                                });
                        }
                        let plus = ui
                            .add(
                                egui::Button::new(egui::RichText::new("+").size(20.0).strong())
                                    .selected(self.active.is_none())
                                    .min_size(egui::vec2(36.0, 30.0)),
                            )
                            .on_hover_text("Nova conexao (Ctrl+T)");
                        if plus.clicked() {
                            self.active = None;
                        }
                    });
                });
            });
        if let Some(i) = close {
            self.close_tab(i);
        }
    }

    /// Dialogos de confianca TLS. Retorna true se um dialogo esta aberto.
    fn trust_dialog(&mut self, ctx: &egui::Context) -> bool {
        let Some(issue) = &self.trust else {
            return false;
        };
        let mut close = false;
        let mut accept = false;
        match issue {
            TrustIssue::Unknown(fp) => {
                egui::Window::new("Servidor desconhecido")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(format!("Primeira conexao com {}.", self.host));
                        ui.label("Confira a impressao digital SHA-256 com o administrador do servidor:");
                        ui.add_space(6.0);
                        ui.monospace(fp);
                        ui.add_space(6.0);
                        ui.label("Ao aceitar, ela fica gravada em known_hosts e toda conexao futura exige o mesmo certificado.");
                        ui.horizontal(|ui| {
                            if ui.button("Aceitar e conectar").clicked() {
                                accept = true;
                            }
                            if ui.button("Cancelar").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            TrustIssue::Changed(reason) => {
                egui::Window::new("CERTIFICADO DO SERVIDOR MUDOU")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.colored_label(egui::Color32::RED, "Conexao bloqueada.");
                        ui.label("O certificado apresentado nao e o mesmo da conexao anterior. Pode ser um ataque (man-in-the-middle) ou uma troca legitima de certificado.");
                        ui.add_space(6.0);
                        ui.monospace(reason);
                        ui.add_space(6.0);
                        if let Some(p) = KnownHosts::default_path() {
                            ui.label(format!("Se a troca foi legitima, confirme com o administrador e remova a linha do host em {}.", p.display()));
                        }
                        if ui.button("Fechar").clicked() {
                            close = true;
                        }
                    });
            }
        }
        if accept {
            self.trust = None;
            self.password = std::mem::take(&mut self.pending_password);
            self.connect_with(ctx, true);
        } else if close {
            self.trust = None;
            self.pending_password.clear();
        }
        true
    }

    fn connect_screen(&mut self, ctx: &egui::Context) {
        if self.trust_dialog(ctx) || self.sso_screen(ctx) {
            return;
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            // Cartao centralizado: largura acompanha a janela (ate 460 px)
            let avail = ui.available_size();
            let w = (avail.x - 32.0).clamp(280.0, 520.0);
            let est = if self.security == Security::None {
                440.0
            } else {
                400.0
            };
            egui::ScrollArea::vertical()
                .auto_shrink(false)
                .show(ui, |ui| {
                    ui.add_space(((avail.y - est) / 2.0).max(16.0));
                    ui.vertical_centered(|ui| {
                        ui.set_max_width(w);
                        egui::Frame::group(ui.style())
                            .inner_margin(egui::Margin::same(28))
                            .corner_radius(12.0)
                            .show(ui, |ui| {
                                ui.set_width(w - 56.0);
                                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                                    self.connect_form(ui);
                                });
                            });
                    });
                });
        });
    }

    /// Login no servidor central numa thread (chamadas HTTP bloqueantes).
    fn central_login(&mut self, ctx: &egui::Context) {
        let ca = match self.central.ca.trim() {
            "" => None,
            p => match std::fs::read(p) {
                Ok(b) => Some(b),
                Err(e) => {
                    self.error = Some(format!("CA do servidor central ({p}): {e}"));
                    return;
                }
            },
        };
        let url = self.central.url.trim().to_string();
        let user = self.central.user.trim().to_string();
        let pw = std::mem::take(&mut self.central.password);
        let (tx, rx) = std::sync::mpsc::channel();
        let c = ctx.clone();
        std::thread::spawn(move || {
            let r = (|| {
                let cen = openvnc_security::central::Central::new(&url, ca.as_deref())
                    .map_err(|e| e.to_string())?;
                let s = cen.login(&user, &pw).map_err(|e| e.to_string())?;
                let m = cen.machines(&s).map_err(|e| e.to_string())?;
                Ok((Arc::new((cen, s)), m))
            })();
            drop(pw);
            let _ = tx.send(CentralMsg::Login(r));
            c.request_repaint();
        });
        self.error = None;
        self.central.busy = Some(rx);
    }

    /// Pede o ticket da maquina e prepara a conexao nativa (TLS fixado
    /// pela impressao digital do catalogo, quando houver).
    fn central_open(&mut self, ctx: &egui::Context, m: openvnc_security::central::Machine) {
        use openvnc_client::native::{NativeOptions, NativeTransport};
        let Some(conn) = self.central.conn.clone() else {
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let c = ctx.clone();
        std::thread::spawn(move || {
            let r = (|| {
                let trust = match &m.fingerprint {
                    Some(f) => Trust::Pinned(normalize_fingerprint(f).map_err(|e| e.to_string())?),
                    None => Trust::default(),
                };
                let ticket = conn.0.ticket(&conn.1, &m.id).map_err(|e| e.to_string())?;
                let address = if m.address.contains(':') && !m.address.starts_with('[') {
                    format!("[{}]:{}", m.address, m.port)
                } else {
                    format!("{}:{}", m.address, m.port)
                };
                let label = if m.name.is_empty() {
                    m.id.clone()
                } else {
                    m.name.clone()
                };
                Ok((
                    NativeOptions {
                        address,
                        tls: ClientTls { trust },
                        transport: NativeTransport::Auto,
                        auth: NativeAuth::OidcToken(ticket),
                        timeout: std::time::Duration::from_secs(15),
                    },
                    label,
                ))
            })();
            let _ = tx.send(CentralMsg::Ticket(r));
            c.request_repaint();
        });
        self.error = None;
        self.central.busy = Some(rx);
    }

    /// Processa a resposta pendente do modo central.
    fn central_poll(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.central.busy else {
            return;
        };
        let msg = match rx.try_recv() {
            Ok(m) => m,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(_) => {
                self.central.busy = None;
                return;
            }
        };
        self.central.busy = None;
        match msg {
            CentralMsg::Login(Ok((conn, m))) => {
                self.central.conn = Some(conn);
                self.central.machines = m;
            }
            CentralMsg::Ticket(Ok((no, label))) => {
                let c = ctx.clone();
                let addr = no.address.clone();
                let session = Session::spawn_native(
                    self.rt.handle(),
                    no,
                    Arc::new(move || c.request_repaint()),
                );
                self.push_tab(
                    session,
                    addr,
                    label,
                    Security::Pin,
                    String::new(),
                    None,
                    false,
                );
            }
            CentralMsg::Login(Err(e)) | CentralMsg::Ticket(Err(e)) => {
                self.error = Some(format!("servidor central: {e}"));
            }
        }
    }

    /// Formulario do modo servidor central.
    fn central_form(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.central_poll(&ctx);
        let field = |ui: &mut egui::Ui, label: &str| {
            ui.add_space(5.0);
            ui.label(egui::RichText::new(label).strong());
        };
        let busy = self.central.busy.is_some();
        if self.central.conn.is_none() {
            field(ui, "Endereco do servidor central");
            ui.add(
                egui::TextEdit::singleline(&mut self.central.url)
                    .hint_text("https://central.empresa.local:8443")
                    .desired_width(f32::INFINITY),
            );
            field(ui, "CA do servidor central (PEM, opcional)");
            ui.add(
                egui::TextEdit::singleline(&mut self.central.ca)
                    .hint_text("vazio = certificados do sistema")
                    .desired_width(f32::INFINITY),
            );
            field(ui, "Usuario");
            ui.add(egui::TextEdit::singleline(&mut self.central.user).desired_width(f32::INFINITY));
            field(ui, "Senha");
            let p = ui.add(
                egui::TextEdit::singleline(&mut self.central.password)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(12.0);
            let ok = !busy
                && !self.central.url.trim().is_empty()
                && !self.central.user.trim().is_empty()
                && !self.central.password.is_empty();
            let enter = p.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let btn = egui::Button::new("Entrar").min_size(egui::vec2(ui.available_width(), 40.0));
            if (ui.add_enabled(ok, btn).clicked() || enter) && ok {
                self.central_login(&ctx);
            }
        } else {
            let who = self
                .central
                .conn
                .as_ref()
                .map(|c| c.1.user.clone())
                .unwrap_or_default();
            ui.horizontal(|ui| {
                ui.label(format!("Conectado como {who}"));
                if ui.button("Sair").clicked() {
                    self.central.conn = None;
                    self.central.machines.clear();
                }
            });
            field(ui, "Maquinas liberadas");
            if self.central.machines.is_empty() {
                ui.label(egui::RichText::new("nenhuma maquina liberada").weak());
            }
            let mut pick = None;
            for m in &self.central.machines {
                let name = if m.name.is_empty() { &m.id } else { &m.name };
                let t = format!(
                    "{name}  ({}:{})  [{}]",
                    m.address,
                    m.port,
                    m.perms.join(",")
                );
                let b = egui::Button::new(t).min_size(egui::vec2(ui.available_width(), 32.0));
                if ui.add_enabled(!busy, b).clicked() {
                    pick = Some(m.clone());
                }
            }
            if let Some(m) = pick {
                self.central_open(&ctx, m);
            }
        }
        if busy {
            ui.add_space(8.0);
            ui.spinner();
        }
        if let Some(e) = &self.error {
            ui.add_space(10.0);
            ui.colored_label(egui::Color32::RED, e);
        }
    }

    fn connect_form(&mut self, ui: &mut egui::Ui) {
        let field = |ui: &mut egui::Ui, label: &str| {
            ui.add_space(5.0);
            ui.label(egui::RichText::new(label).strong());
        };
        fn big(t: egui::TextEdit<'_>) -> egui::TextEdit<'_> {
            t.margin(egui::vec2(8.0, 6.0)).font(egui::TextStyle::Body)
        }
        ui.vertical_centered(|ui| {
            ui.heading(egui::RichText::new("OpenVNC").size(26.0).strong());
            ui.label(egui::RichText::new("Acesse outro computador").weak());
        });
        ui.add_space(6.0);
        if self.central.on {
            if ui.button("< Conexao direta").clicked() {
                self.central.on = false;
            }
            self.central_form(ui);
            return;
        }
        ui.add_space(4.0);
        field(ui, "Endereco do computador");
        let r = ui
            .horizontal(|ui| {
                let pw = 90.0;
                let r = ui.add(big(egui::TextEdit::singleline(&mut self.host)
                    .hint_text("ex.: 192.168.0.10 ou nome-do-pc")
                    .desired_width(ui.available_width() - pw - 10.0)));
                ui.add(big(egui::TextEdit::singleline(&mut self.port)
                    .hint_text("5900")
                    .desired_width(pw)))
                    .on_hover_text(
                        "Porta do servidor (padrao 5900). So mude se o servidor usar outra.",
                    );
                r
            })
            .inner;
        field(
            ui,
            if self.user.is_empty() {
                "Senha"
            } else {
                "Token do dispositivo"
            },
        );
        let p = ui.add(big(egui::TextEdit::singleline(&mut self.password)
            .password(true)
            .hint_text("senha de acesso remoto")
            .desired_width(f32::INFINITY)));
        ui.add_space(10.0);
        egui::CollapsingHeader::new("Opcoes avancadas").show(ui, |ui| {
            ui.checkbox(&mut self.central.on, "Servidor central da empresa")
                .on_hover_text("Entra no servidor central OpenVNC e lista as maquinas liberadas.");
            field(ui, "Seguranca");
            egui::ComboBox::from_id_salt("sec")
                .width(ui.available_width())
                .selected_text(self.security.label())
                .show_ui(ui, |ui| {
                    for m in [
                        Security::Tofu,
                        Security::WebPki,
                        Security::Pin,
                        Security::Ca,
                        Security::None,
                    ] {
                        ui.selectable_value(&mut self.security, m, m.label());
                    }
                });
            match self.security {
                Security::Pin => {
                    field(ui, "Impressao digital SHA-256");
                    ui.add(big(egui::TextEdit::singleline(&mut self.tls_arg)
                        .hint_text("AB:CD:...")
                        .desired_width(f32::INFINITY)));
                }
                Security::Ca => {
                    field(ui, "CA (PEM)");
                    ui.add(big(egui::TextEdit::singleline(&mut self.tls_arg)
                        .hint_text("caminho do arquivo")
                        .desired_width(f32::INFINITY)));
                }
                _ => {}
            }
            if self.security != Security::None {
                ui.add_space(6.0);
                ui.checkbox(&mut self.sso, "Entrar com a conta da empresa (SSO)")
                    .on_hover_text(
                        "Login OIDC no navegador (Entra ID, Okta, Keycloak...). Usa o \
                         protocolo nativo na porta de arquivos; a senha nao e usada.",
                    );
                if self.sso {
                    field(ui, "CA do provedor SSO (opcional)");
                    ui.add(big(egui::TextEdit::singleline(&mut self.sso_ca)
                        .hint_text("vazio = certificados do sistema")
                        .desired_width(f32::INFINITY)));
                }
                field(ui, "Usuario do dispositivo pareado");
                ui.add(big(egui::TextEdit::singleline(&mut self.user)
                    .hint_text("vazio = entrar com a senha")
                    .desired_width(f32::INFINITY)));
                field(ui, "Porta de arquivos");
                ui.add(big(egui::TextEdit::singleline(&mut self.files_port)
                    .hint_text("automatica (porta + 1)")
                    .desired_width(f32::INFINITY)));
            }
            ui.add_space(6.0);
            ui.checkbox(&mut self.shared, "Sessao compartilhada")
                .on_hover_text("Permite que outras pessoas fiquem conectadas ao mesmo tempo.");
        });
        let enter =
            (r.lost_focus() || p.lost_focus()) && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.add_space(16.0);
        let btn = egui::Button::new(
            egui::RichText::new("Conectar")
                .size(17.0)
                .strong()
                .color(egui::Color32::WHITE),
        )
        .fill(egui::Color32::from_rgb(0x2F, 0x6F, 0xEB))
        .corner_radius(8.0)
        .min_size(egui::vec2(ui.available_width(), 40.0));
        let plain_pw = self.security == Security::None && !self.password.is_empty();
        if plain_pw {
            ui.checkbox(
                &mut self.plain_ok,
                "Entendo que a senha sera enviada sem criptografia (sem TLS)",
            );
        } else {
            self.plain_ok = false;
        }
        let ok = !self.host.trim().is_empty() && (!plain_pw || self.plain_ok);
        if (ui.add_enabled(ok, btn).clicked() || enter) && ok {
            self.connect(ui.ctx());
        }
        if self.security == Security::None {
            ui.add_space(10.0);
            ui.colored_label(
                egui::Color32::from_rgb(220, 160, 0),
                "Conexoes VNC legadas NAO sao criptografadas. Use um tunel SSH \
                 (ssh -L 5901:localhost:5901 host) em redes nao confiaveis.",
            );
        }
        if let Some(e) = &self.error {
            ui.add_space(10.0);
            ui.colored_label(egui::Color32::RED, e);
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // marcados de novo neste quadro pela sessao, se houver
        ctx.data_mut(|d| {
            d.insert_temp(egui::Id::new(REMOTE_FOCUS_ID), false);
            d.insert_temp(egui::Id::new(OSK_ID), false);
        });
        self.pump(ctx);
        // Ctrl+T: nova conexao; Ctrl+Tab: proxima aba
        let (new_tab, next_tab) = ctx.input(|i| {
            (
                i.modifiers.ctrl && i.key_pressed(egui::Key::T),
                i.modifiers.ctrl && i.key_pressed(egui::Key::Tab),
            )
        });
        if new_tab {
            self.active = None;
        }
        if next_tab && !self.tabs.is_empty() {
            self.active = Some(self.active.map_or(0, |a| (a + 1) % self.tabs.len()));
        }
        // celular conectado: tela cheia, as abas ficam no menu flutuante
        if !self.tabs.is_empty() && !(self.mobile && self.active.is_some()) {
            self.tab_bar(ctx);
        }
        let title = match self.active {
            Some(i) => format!("OpenVNC - {}", self.tabs[i].label),
            None => "OpenVNC".to_string(),
        };
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
        let Some(i) = self.active else {
            self.connect_screen(ctx);
            return;
        };
        let (f11, touched) = ctx.input(|i| {
            (
                i.key_pressed(egui::Key::F11),
                i.events
                    .iter()
                    .any(|e| matches!(e, egui::Event::Touch { .. })),
            )
        });
        if f11 {
            self.fullscreen = !self.fullscreen;
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.fullscreen));
        }
        // tela de toque: liga o mouse virtual na primeira vez que tocarem
        if touched && !self.touch_seen {
            self.touch_seen = true;
            self.touchpad = true;
        }
        let remote = &mut self.tabs[i];
        // primeira imagem: janela do tamanho remoto (limitada pela tela)
        if !remote.fitted && !self.fullscreen {
            if let Some(t) = &remote.texture {
                remote.fitted = true;
                fit_window(ctx, t.size_vec2());
            }
        }

        let mut disconnect = false;
        let mobile = self.mobile;
        let (mut switch_to, mut new_conn) = (None, false);
        let tabs_list: Vec<(String, bool)> = if mobile {
            self.tabs
                .iter()
                .map(|t| (t.label.clone(), t.connected))
                .collect()
        } else {
            Vec::new()
        };
        let remote = &mut self.tabs[i];
        if mobile {
            let mut fit = self.scale == Scale::Fit;
            let mut want_screen = false;
            let many = remote.files.as_ref().is_some_and(|f| f.screen_count() > 1);
            hud::show(
                ctx,
                hud::Hud {
                    disconnect: &mut disconnect,
                    fit: &mut fit,
                    touchpad: &mut self.touchpad,
                    osk: &mut self.osk,
                    show_files: &mut remote.show_files,
                    show_explorer: &mut remote.show_explorer,
                    files: remote.files.as_ref(),
                    title: &remote.title,
                    status: &remote.status,
                    encrypted: remote.encrypted,
                    tabs: tabs_list,
                    active: i,
                    switch_to: &mut switch_to,
                    new_conn: &mut new_conn,
                    next_screen: many.then_some(&mut want_screen),
                },
            );
            if want_screen {
                if let Some(f) = &remote.files {
                    f.next_screen();
                }
            }
            self.scale = if fit { Scale::Fit } else { Scale::Native };
            let osk = self.osk;
            ctx.data_mut(|d| d.insert_temp(egui::Id::new(OSK_ID), osk));
        }
        egui::TopBottomPanel::top("bar").show_animated(ctx, !mobile, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Desconectar").clicked() {
                    disconnect = true;
                }
                ui.separator();
                ui.selectable_value(&mut self.scale, Scale::Fit, "Ajustar");
                ui.selectable_value(&mut self.scale, Scale::Native, "1:1");
                if let Some(t) = &remote.texture {
                    if ui
                        .button("Janela")
                        .on_hover_text("Ajusta a janela a resolucao remota, sem passar da tela")
                        .clicked()
                    {
                        fit_window(ui.ctx(), t.size_vec2());
                    }
                }
                if ui
                    .toggle_value(&mut self.fullscreen, "Tela cheia")
                    .on_hover_text("F11")
                    .changed()
                {
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.fullscreen));
                }
                ui.toggle_value(&mut self.touchpad, "Touchpad").on_hover_text(
                    "Mouse virtual: arraste para mover, toque para clicar, toque longo = botao direito, dois dedos = rolagem",
                );
                if self.touch_seen {
                    ui.toggle_value(&mut self.osk, "Teclado")
                        .on_hover_text("Abre o teclado do celular para digitar no computador remoto");
                }
                let osk = self.osk;
                ui.ctx().data_mut(|d| d.insert_temp(egui::Id::new(OSK_ID), osk));
                ui.toggle_value(&mut self.recv_clipboard, "Receber area de transferencia")
                    .on_hover_text(
                        "Copia para este computador o texto copiado na maquina remota (so com a janela em foco)",
                    );
                ui.separator();
                if remote.files.is_some() {
                    ui.toggle_value(&mut remote.show_files, "Arquivos");
                    ui.toggle_value(&mut remote.show_explorer, "Explorador");
                    if let Some(link) = &remote.files {
                        explorer::lock_toggle(ui, link, false);
                    }
                    ui.separator();
                }
                ui.label(&remote.title);
                ui.label(&remote.status);
                if remote.encrypted {
                    ui.colored_label(egui::Color32::from_rgb(80, 180, 80), "TLS");
                } else {
                    ui.colored_label(egui::Color32::from_rgb(220, 160, 0), "sem criptografia");
                }
                if remote.legacy_auth {
                    ui.colored_label(egui::Color32::from_rgb(220, 160, 0), "VNC Auth (DES) fraca");
                }
            });
        });
        if let Some(link) = &remote.files {
            let dropped: Vec<_> = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .collect()
            });
            if !dropped.is_empty() {
                remote.show_files = true;
                for p in dropped {
                    link.offer(p);
                }
            }
            if remote.show_files {
                files_panel(ctx, link, &mut remote.send_path);
            }
            explorer::show(
                ctx,
                self.rt.handle(),
                link,
                &mut remote.explorer,
                &mut remote.show_explorer,
                mobile,
            );
        }
        let scale = self.scale;
        let touchpad = self.touchpad;
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(egui::Color32::BLACK))
            .show(ctx, |ui| {
                let Some(tex) = remote.texture.clone() else {
                    ui.centered_and_justified(|ui| ui.label(&remote.status));
                    return;
                };
                let size = tex.size_vec2();
                let draw = |ui: &mut egui::Ui, remote: &mut Remote| {
                    let avail = ui.available_size();
                    let k = match scale {
                        Scale::Fit => fit_scale(avail, size),
                        Scale::Native => 1.0,
                    };
                    let (rect, resp) =
                        ui.allocate_exact_size(size * k, egui::Sense::click_and_drag());
                    ui.painter().image(
                        tex.id(),
                        rect,
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        egui::Color32::WHITE,
                    );
                    if remote.connected {
                        if touchpad {
                            touchpad_input(ui, remote, rect, size, &resp);
                        }
                        handle_input(ui, remote, rect, size, &resp, touchpad);
                    }
                    if touchpad {
                        draw_virtual_cursor(ui, remote, rect, size);
                    }
                    // cursor remoto (pseudo-encoding Cursor) desenhado localmente
                    let hover = resp.hover_pos().filter(|_| !touchpad);
                    if let (Some((cur, hot)), Some(pos)) = (&remote.cursor, hover) {
                        let min = pos - *hot * k;
                        ui.painter().image(
                            cur.id(),
                            egui::Rect::from_min_size(min, cur.size_vec2() * k),
                            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                            egui::Color32::WHITE,
                        );
                        if cur.size_vec2().x > 0.0 {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::None);
                        }
                    }
                };
                match scale {
                    Scale::Fit => {
                        ui.centered_and_justified(|ui| draw(ui, remote));
                    }
                    Scale::Native => {
                        egui::ScrollArea::both().show(ui, |ui| draw(ui, remote));
                    }
                }
            });
        if disconnect {
            self.close_tab(i);
        } else if new_conn {
            self.active = None;
        } else if let Some(j) = switch_to {
            self.active = Some(j);
        }
    }
}

/// TLS da conexao de arquivos. No TOFU, fixa o certificado ja aceito para o
/// endereco RFB (e o mesmo servidor, em outra porta).
fn files_tls(mode: Security, arg: &str, rfb_addr: &str) -> anyhow::Result<ClientTls> {
    if mode == Security::Tofu {
        let store = KnownHosts::new(
            KnownHosts::default_path()
                .ok_or_else(|| anyhow::anyhow!("sem diretorio para known_hosts"))?,
        );
        let fp = store
            .get(rfb_addr)?
            .ok_or_else(|| anyhow::anyhow!("host ainda nao confirmado"))?;
        return Ok(ClientTls {
            trust: Trust::Pinned(fp),
        });
    }
    build_tls(mode, arg, false)?.ok_or_else(|| anyhow::anyhow!("arquivos exigem TLS"))
}

fn files_panel(ctx: &egui::Context, link: &transfer::FileLink, send_path: &mut String) {
    let Ok(s) = link.shared.lock() else {
        return;
    };
    egui::SidePanel::right("files")
        .resizable(true)
        .default_width(300.0)
        .show(ctx, |ui| {
            ui.heading("Arquivos");
            ui.label(egui::RichText::new(&s.status).small().weak());
            ui.separator();
            ui.add_enabled_ui(s.connected, |ui| {
                ui.label("Enviar ao servidor (ou arraste arquivos para a janela):");
                ui.horizontal(|ui| {
                    let r = ui.add(
                        egui::TextEdit::singleline(send_path)
                            .hint_text("caminho do arquivo")
                            .desired_width(ui.available_width() - 60.0),
                    );
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (ui.button("Enviar").clicked() || enter) && !send_path.trim().is_empty() {
                        let p = send_path.trim().trim_matches('"').to_string();
                        link.offer(std::path::PathBuf::from(p));
                        send_path.clear();
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("Recebidos em {}", link.download_dir.display()))
                        .small(),
                );
                if ui.small_button("Abrir pasta").clicked() {
                    let _ = std::fs::create_dir_all(&link.download_dir);
                    open_path(&link.download_dir);
                }
            });
            for (id, name, size) in &s.offers {
                ui.separator();
                ui.label(format!(
                    "O servidor quer enviar {name} ({})",
                    transfer::human(*size)
                ));
                ui.horizontal(|ui| {
                    if ui.button("Aceitar").clicked() {
                        link.accept(*id);
                    }
                    if ui.button("Recusar").clicked() {
                        link.reject(*id);
                    }
                });
            }
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                if s.items.is_empty() {
                    ui.label(egui::RichText::new("Nenhuma transferencia ainda.").weak());
                }
                for i in s.items.iter().rev() {
                    let arrow = match i.dir {
                        transfer::Dir::Up => "enviar",
                        transfer::Dir::Down => "receber",
                    };
                    ui.label(egui::RichText::new(&i.name).strong());
                    let frac = if i.size == 0 {
                        if i.finished {
                            1.0
                        } else {
                            0.0
                        }
                    } else {
                        i.done as f32 / i.size as f32
                    };
                    ui.add(egui::ProgressBar::new(frac).text(format!(
                        "{arrow}: {} de {}",
                        transfer::human(i.done),
                        transfer::human(i.size)
                    )));
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&i.state).small());
                        if let Some(p) = &i.path {
                            if ui.small_button("Abrir").clicked() {
                                open_path(p);
                            }
                        }
                    });
                    ui.add_space(4.0);
                }
            });
        });
}

/// Abre um arquivo ou pasta no gerenciador do sistema.
fn open_path(p: &std::path::Path) {
    #[cfg(windows)]
    let r = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(p).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let r = std::process::Command::new("xdg-open").arg(p).spawn();
    if let Err(e) = r {
        tracing::warn!("abrir {}: {e}", p.display());
    }
}

fn sync_texture(ctx: &egui::Context, remote: &mut Remote) {
    let mut guard = remote.session.frame().lock().expect("mutex");
    let f = &mut *guard;
    let Some(fb) = f.fb.as_ref() else { return };
    let opts = egui::TextureOptions::LINEAR;
    let (w, h) = (usize::from(fb.width()), usize::from(fb.height()));
    if remote.texture.is_none() || remote.generation != f.generation {
        let img = egui::ColorImage::from_rgba_unmultiplied([w, h], fb.data());
        remote.texture = Some(ctx.load_texture("remote", img, opts));
        remote.generation = f.generation;
        f.damage.clear();
        return;
    }
    let damage = std::mem::take(&mut f.damage);
    let tex = remote.texture.as_mut().expect("textura");
    for r in damage {
        let r = r.clip_to(fb.width(), fb.height());
        if r.is_empty() {
            continue;
        }
        // atualizacao parcial: so a regiao alterada sobe para a GPU
        let mut px = Vec::with_capacity(r.area() as usize * 4);
        for y in r.y..r.y + r.height {
            let o = usize::from(y) * fb.stride() + usize::from(r.x) * 4;
            px.extend_from_slice(&fb.data()[o..o + usize::from(r.width) * 4]);
        }
        let img = egui::ColorImage::from_rgba_unmultiplied(
            [usize::from(r.width), usize::from(r.height)],
            &px,
        );
        tex.set_partial([usize::from(r.x), usize::from(r.y)], img, opts);
    }
}

/// Ajusta a janela ao tamanho remoto `size`, sem passar de 90% do monitor.
fn fit_window(ctx: &egui::Context, size: egui::Vec2) {
    let (monitor, maximized) = ctx.input(|i| (i.viewport().monitor_size, i.viewport().maximized));
    if maximized == Some(true) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(false));
    }
    // barra de ferramentas e abas
    let chrome = egui::vec2(0.0, 64.0);
    let want = size + chrome;
    let max = monitor.map_or(want, |m| m * 0.9);
    let k = (max.x / want.x).min(max.y / want.y).min(1.0);
    let inner = egui::vec2((size.x * k).max(480.0), (size.y * k).max(320.0)) + chrome;
    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(inner));
}

/// Mouse virtual (modo touchpad): arrastar move o cursor remoto de forma
/// relativa, toque = clique esquerdo, toque longo ou clique secundario =
/// botao direito, dois dedos = rolagem.
fn touchpad_input(
    ui: &egui::Ui,
    remote: &mut Remote,
    rect: egui::Rect,
    size: egui::Vec2,
    resp: &egui::Response,
) {
    let send = |remote: &mut Remote, buttons: u8| {
        let (x, y) = remote.last_pos;
        remote
            .session
            .send(Command::Pointer(PointerEvent { buttons, x, y }));
    };
    let multi = ui.input(|i| i.multi_touch());
    if let Some(m) = multi.filter(|m| m.num_touches >= 2) {
        if let Some(bit) = scroll_bit(m.translation_delta.y) {
            send(remote, bit);
            send(remote, 0);
        }
        return;
    }
    // Nao usa resp.dragged(): o egui decide o alvo do arrasto no toque com o
    // layout do quadro anterior, e o primeiro toque depois de o teclado do
    // celular fechar (layout deslocado) caia fora da imagem e era perdido.
    // A origem do toque e o deslocamento do ponteiro nao dependem disso.
    let (down, delta, origin) = ui.input(|i| {
        (
            i.pointer.primary_down(),
            i.pointer.delta(),
            i.pointer.press_origin(),
        )
    });
    if down && delta != egui::Vec2::ZERO && origin.is_some_and(|o| rect.contains(o)) {
        // ganho 1.5: atravessa a tela sem tirar o dedo varias vezes
        remote.last_pos = touch_move(remote.last_pos, delta, size, rect.width());
        send(remote, 0);
    }
    let bit = if resp.secondary_clicked() || resp.long_touched() {
        4
    } else if resp.clicked() {
        1
    } else {
        0
    };
    if bit != 0 {
        send(remote, bit);
        send(remote, 0);
    }
}

/// Escala que faz a tela remota `size` caber inteira em `avail`, sem distorcer.
fn fit_scale(avail: egui::Vec2, size: egui::Vec2) -> f32 {
    (avail.x / size.x).min(avail.y / size.y).max(0.01)
}

/// Nova posicao do cursor virtual apos arrastar `delta` (pixels da janela)
/// numa imagem de largura `shown`; ganho 1.5 e limitada a tela remota.
fn touch_move(last: (u16, u16), delta: egui::Vec2, size: egui::Vec2, shown: f32) -> (u16, u16) {
    let d = delta * (1.5 * size.x / shown.max(1.0));
    let nx = (f32::from(last.0) + d.x).clamp(0.0, size.x - 1.0);
    let ny = (f32::from(last.1) + d.y).clamp(0.0, size.y - 1.0);
    (nx as u16, ny as u16)
}

/// Botao de rolagem (RFB: 8 = cima, 16 = baixo) para o deslocamento de dois
/// dedos; ignora tremidas de ate 4 px.
fn scroll_bit(dy: f32) -> Option<u8> {
    (dy.abs() > 4.0).then_some(if dy > 0.0 { 8 } else { 16 })
}

/// Seta desenhada na posicao remota quando o mouse e virtual.
fn draw_virtual_cursor(ui: &egui::Ui, remote: &Remote, rect: egui::Rect, size: egui::Vec2) {
    let (x, y) = remote.last_pos;
    let p = rect.min
        + egui::vec2(
            f32::from(x) / size.x * rect.width(),
            f32::from(y) / size.y * rect.height(),
        );
    let pts = vec![
        p,
        p + egui::vec2(0.0, 18.0),
        p + egui::vec2(5.0, 14.0),
        p + egui::vec2(12.0, 13.0),
    ];
    ui.painter().add(egui::Shape::convex_polygon(
        pts,
        egui::Color32::WHITE,
        egui::Stroke::new(1.5_f32, egui::Color32::BLACK),
    ));
}

fn handle_input(
    ui: &egui::Ui,
    remote: &mut Remote,
    rect: egui::Rect,
    size: egui::Vec2,
    resp: &egui::Response,
    touchpad: bool,
) {
    let osk = ui
        .ctx()
        .data(|d| d.get_temp::<bool>(egui::Id::new(OSK_ID)).unwrap_or(false));
    // Com o teclado do celular ligado, a tela remota recebe o que for
    // digitado mesmo depois do toque no botao "Teclado".
    if resp.clicked() || resp.drag_started() || (osk && !resp.has_focus()) {
        resp.request_focus();
    }
    let focused = resp.has_focus();
    ui.ctx()
        .data_mut(|d| d.insert_temp(egui::Id::new(REMOTE_FOCUS_ID), focused));
    let events = ui.input(|i| i.events.clone());
    let to_remote = |p: egui::Pos2| -> (u16, u16) {
        let x = ((p.x - rect.min.x) / rect.width() * size.x).clamp(0.0, size.x - 1.0);
        let y = ((p.y - rect.min.y) / rect.height() * size.y).clamp(0.0, size.y - 1.0);
        (x as u16, y as u16)
    };
    let send_ptr = |remote: &mut Remote, buttons: u8| {
        let (x, y) = remote.last_pos;
        remote
            .session
            .send(Command::Pointer(PointerEvent { buttons, x, y }));
    };
    let hovered = resp.hovered();
    tracing::trace!(focus = resp.has_focus(), n = events.len(), "entrada");
    for ev in &events {
        match ev {
            egui::Event::PointerMoved(p) if rect.contains(*p) && !touchpad => {
                remote.last_pos = to_remote(*p);
                send_ptr(remote, remote.buttons);
            }
            egui::Event::PointerButton {
                pos,
                button,
                pressed,
                ..
            } if !touchpad && (rect.contains(*pos) || remote.buttons != 0) => {
                remote.last_pos = to_remote(*pos);
                let bit = match button {
                    egui::PointerButton::Primary => 1,
                    egui::PointerButton::Middle => 2,
                    egui::PointerButton::Secondary => 4,
                    _ => 0,
                };
                if *pressed {
                    remote.buttons |= bit;
                } else {
                    remote.buttons &= !bit;
                }
                send_ptr(remote, remote.buttons);
            }
            egui::Event::MouseWheel { delta, .. } if hovered && delta.y != 0.0 => {
                let bit = if delta.y > 0.0 { 8 } else { 16 };
                send_ptr(remote, remote.buttons | bit);
                send_ptr(remote, remote.buttons);
            }
            _ => {}
        }
    }
    if resp.has_focus() {
        // impede que Tab/setas movam o foco do egui
        ui.memory_mut(|m| {
            m.set_focus_lock_filter(
                resp.id,
                egui::EventFilter {
                    tab: true,
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    escape: true,
                },
            )
        });
        let mods = ui.input(|i| i.modifiers);
        let keys = remote.keys.translate(&events, mods);
        if !keys.is_empty() {
            tracing::debug!(n = keys.len(), "teclas enviadas");
        }
        for k in keys {
            remote.session.send(Command::Key(k));
        }
    } else {
        for k in remote.keys.release_all() {
            remote.session.send(Command::Key(k));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_falhas_de_confianca() {
        let r =
            "tls: host desconhecido h:5900 (fingerprint AA:BB); confira e aceite explicitamente";
        assert!(matches!(trust_issue(r), Some(TrustIssue::Unknown(f)) if f == "AA:BB"));
        let r = "CERTIFICADO MUDOU: esperado AA, recebido BB";
        assert!(matches!(trust_issue(r), Some(TrustIssue::Changed(_))));
        assert!(trust_issue("connection refused").is_none());
    }

    #[test]
    fn ajustar_cabe_na_janela_sem_distorcer() {
        let tela = egui::vec2(1920.0, 1080.0);
        // celular em pe: limitado pela largura
        let k = fit_scale(egui::vec2(390.0, 800.0), tela);
        assert!((k - 390.0 / 1920.0).abs() < 1e-6);
        assert!(tela.y * k <= 800.0);
        // janela maior que a tela remota: amplia
        assert!((fit_scale(egui::vec2(3840.0, 2160.0), tela) - 2.0).abs() < 1e-6);
        // janela minimizada nao zera a escala
        assert!(fit_scale(egui::vec2(0.0, 0.0), tela) > 0.0);
    }

    #[test]
    fn mouse_virtual_move_relativo_e_fica_na_tela() {
        let tela = egui::vec2(1920.0, 1080.0);
        // imagem exibida com 390 px: 10 px de dedo = 10 * 1.5 * 1920/390
        let p = touch_move((100, 100), egui::vec2(10.0, 0.0), tela, 390.0);
        assert_eq!(p, (100 + (10.0 * 1.5 * 1920.0 / 390.0) as u16, 100));
        assert_eq!(
            touch_move((5, 5), egui::vec2(-500.0, -500.0), tela, 390.0),
            (0, 0)
        );
        assert_eq!(
            touch_move((1900, 1000), egui::vec2(900.0, 900.0), tela, 390.0),
            (1919, 1079)
        );
        assert!(touch_move((7, 7), egui::vec2(1.0, 1.0), tela, 0.0).0 > 7);
    }

    #[test]
    fn dois_dedos_rolam_e_ignoram_tremida() {
        assert_eq!(scroll_bit(3.0), None);
        assert_eq!(scroll_bit(-4.0), None);
        assert_eq!(scroll_bit(12.0), Some(8));
        assert_eq!(scroll_bit(-12.0), Some(16));
    }
}
