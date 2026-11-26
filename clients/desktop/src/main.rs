//! Cliente VNC desktop: egui + wgpu. A rede roda numa task tokio
//! (`openvnc-client`); a UI apenas le o quadro compartilhado e envia entrada.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod input;
mod native;
mod transfer;

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
            .with_inner_size([1024.0, 768.0]),
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
    // OPENVNC_TLS=tls|tofu|tofu-accept|pin:<sha256>|ca:<arquivo>, OPENVNC_USER=<dispositivo>
    let sec = std::env::var("OPENVNC_TLS").unwrap_or_default();
    let (mode, arg) = sec.split_once(':').unwrap_or((sec.as_str(), ""));
    let (mode, accept) = match mode {
        "" => (Security::None, false),
        "tls" => (Security::WebPki, false),
        "tofu" => (Security::Tofu, false),
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
    send_path: String,
    /// Nome exibido na aba (nome do desktop remoto, ou o endereco).
    label: String,
    /// Seguranca usada nesta conexao (para abrir a conexao de arquivos).
    security: Security,
    tls_arg: String,
    /// Conectou informando senha/token (para explicar recusas).
    had_password: bool,
}

struct App {
    rt: tokio::runtime::Runtime,
    host: String,
    password: String,
    shared: bool,
    scale: Scale,
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
        let files_plan = match (o.tls.is_some(), files_port) {
            (true, Ok(port)) if port > 0 => {
                let auth = if !self.user.is_empty() {
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
        let had_password = !self.password.is_empty();
        if had_password {
            o.config.password = Some(Password::new(std::mem::take(&mut self.password)));
        }
        let c = ctx.clone();
        let session = Session::spawn(self.rt.handle(), o, Arc::new(move || c.request_repaint()));
        self.error = None;
        self.tabs.push(Remote {
            session,
            texture: None,
            generation: 0,
            label: self.host.trim().to_string(),
            security: self.security,
            tls_arg: self.tls_arg.trim().to_string(),
            had_password,
            title: addr,
            status: "conectando...".into(),
            legacy_auth: false,
            encrypted: false,
            connected: false,
            ended: false,
            keys: input::KeyState::default(),
            buttons: 0,
            last_pos: (0, 0),
            cursor: None,
            files: None,
            files_plan,
            show_files: false,
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
                            } else {
                                format!("desconectado: {r}")
                            }
                        };
                    }
                    SessionEvent::CutText(t) => ctx.copy_text(t),
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
                    SessionEvent::Bell | SessionEvent::Updated => {}
                }
            }
            if !drop_tab && remote.ended && !remote.connected && remote.texture.is_none() {
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
        if self.trust_dialog(ctx) {
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

    fn connect_form(&mut self, ui: &mut egui::Ui) {
        let field = |ui: &mut egui::Ui, label: &str| {
            ui.add_space(8.0);
            ui.label(egui::RichText::new(label).strong());
        };
        fn big(t: egui::TextEdit<'_>) -> egui::TextEdit<'_> {
            t.margin(egui::vec2(10.0, 8.0)).font(egui::TextStyle::Body)
        }
        ui.vertical_centered(|ui| {
            ui.heading(egui::RichText::new("OpenVNC").size(34.0).strong());
            ui.label(egui::RichText::new("Acesse outro computador").weak());
        });
        ui.add_space(14.0);
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
                .size(19.0)
                .strong()
                .color(egui::Color32::WHITE),
        )
        .fill(egui::Color32::from_rgb(0x2F, 0x6F, 0xEB))
        .corner_radius(8.0)
        .min_size(egui::vec2(ui.available_width(), 44.0));
        let ok = !self.host.trim().is_empty();
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
        if !self.tabs.is_empty() {
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
        let remote = &mut self.tabs[i];

        let mut disconnect = false;
        egui::TopBottomPanel::top("bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Desconectar").clicked() {
                    disconnect = true;
                }
                ui.separator();
                ui.selectable_value(&mut self.scale, Scale::Fit, "Ajustar");
                ui.selectable_value(&mut self.scale, Scale::Native, "1:1");
                ui.separator();
                if remote.files.is_some() {
                    ui.toggle_value(&mut remote.show_files, "Arquivos");
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
        }
        let scale = self.scale;
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
                        Scale::Fit => (avail.x / size.x).min(avail.y / size.y).max(0.01),
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
                        handle_input(ui, remote, rect, size, &resp);
                    }
                    // cursor remoto (pseudo-encoding Cursor) desenhado localmente
                    if let (Some((cur, hot)), Some(pos)) = (&remote.cursor, resp.hover_pos()) {
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

fn handle_input(
    ui: &egui::Ui,
    remote: &mut Remote,
    rect: egui::Rect,
    size: egui::Vec2,
    resp: &egui::Response,
) {
    if resp.clicked() || resp.drag_started() {
        resp.request_focus();
    }
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
            egui::Event::PointerMoved(p) if rect.contains(*p) => {
                remote.last_pos = to_remote(*p);
                send_ptr(remote, remote.buttons);
            }
            egui::Event::PointerButton {
                pos,
                button,
                pressed,
                ..
            } if rect.contains(*pos) || remote.buttons != 0 => {
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
}
