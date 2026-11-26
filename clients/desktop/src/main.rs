//! Cliente VNC desktop: egui + wgpu. A rede roda numa task tokio
//! (`openvnc-client`); a UI apenas le o quadro compartilhado e envia entrada.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod input;
mod native;

use std::sync::Arc;

use eframe::egui;
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
}

struct App {
    rt: tokio::runtime::Runtime,
    host: String,
    password: String,
    shared: bool,
    scale: Scale,
    error: Option<String>,
    remote: Option<Remote>,
    security: Security,
    /// Impressao (Pin) ou caminho do PEM (Ca).
    tls_arg: String,
    user: String,
    /// Senha guardada enquanto se decide uma confirmacao TOFU.
    pending_password: String,
    trust: Option<TrustIssue>,
}

impl App {
    fn new() -> Self {
        App {
            rt: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime tokio"),
            host: "localhost:0".into(),
            password: String::new(),
            shared: true,
            scale: Scale::Fit,
            error: None,
            remote: None,
            security: Security::Tofu,
            tls_arg: String::new(),
            user: String::new(),
            pending_password: String::new(),
            trust: None,
        }
    }

    fn connect(&mut self, ctx: &egui::Context) {
        self.connect_with(ctx, false);
    }

    fn connect_with(&mut self, ctx: &egui::Context, accept_new: bool) {
        let addr = match openvnc_transport::parse_address(&self.host) {
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
        if !self.password.is_empty() {
            o.config.password = Some(Password::new(std::mem::take(&mut self.password)));
        }
        let c = ctx.clone();
        let session = Session::spawn(self.rt.handle(), o, Arc::new(move || c.request_repaint()));
        self.error = None;
        self.remote = Some(Remote {
            session,
            texture: None,
            generation: 0,
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
        });
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
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.heading("OpenVNC");
                ui.add_space(20.0);
                egui::Grid::new("conn").num_columns(2).show(ui, |ui| {
                    ui.label("Servidor");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut self.host).hint_text("host:display ou host::porta"),
                    );
                    ui.end_row();
                    ui.label("Seguranca");
                    egui::ComboBox::from_id_salt("sec")
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
                    ui.end_row();
                    match self.security {
                        Security::Pin => {
                            ui.label("SHA-256");
                            ui.add(egui::TextEdit::singleline(&mut self.tls_arg).hint_text("AB:CD:..."));
                            ui.end_row();
                        }
                        Security::Ca => {
                            ui.label("CA (PEM)");
                            ui.add(egui::TextEdit::singleline(&mut self.tls_arg).hint_text("caminho do arquivo"));
                            ui.end_row();
                        }
                        _ => {}
                    }
                    if self.security != Security::None {
                        ui.label("Dispositivo");
                        ui.add(egui::TextEdit::singleline(&mut self.user).hint_text("opcional (servidor com --pairing)"));
                        ui.end_row();
                    }
                    ui.label(if self.user.is_empty() { "Senha" } else { "Token" });
                    let p = ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    ui.end_row();
                    ui.label("");
                    ui.checkbox(&mut self.shared, "Sessao compartilhada");
                    ui.end_row();
                    let enter = (r.lost_focus() || p.lost_focus())
                        && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if enter {
                        self.connect(ui.ctx());
                    }
                });
                ui.add_space(10.0);
                if ui.button("Conectar").clicked() {
                    self.connect(ui.ctx());
                }
                ui.add_space(10.0);
                if self.security == Security::None {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 0),
                    "Conexoes VNC legadas NAO sao criptografadas. Use um tunel SSH\n(ssh -L 5901:localhost:5901 host) em redes nao confiaveis.",
                );
                }
                if let Some(e) = &self.error {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::RED, e);
                }
            });
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let Some(remote) = self.remote.as_mut() else {
            self.connect_screen(ctx);
            return;
        };
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
                    remote.legacy_auth = legacy_auth;
                    remote.encrypted = encrypted;
                    remote.status = format!("{name} — {width}x{height}");
                    ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!(
                        "OpenVNC — {name}"
                    )));
                }
                SessionEvent::Disconnected { reason, .. } if trust_issue(&reason).is_some() => {
                    // falha de confianca nunca e repetida em silencio
                    self.trust = trust_issue(&reason);
                    self.remote = None;
                    self.connect_screen(ctx);
                    return;
                }
                SessionEvent::Disconnected { reason, retrying } => {
                    remote.connected = false;
                    remote.status = if retrying {
                        format!("conexao perdida ({reason}); reconectando...")
                    } else {
                        remote.ended = true;
                        format!("desconectado: {reason}")
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
                        let tex = ctx.load_texture("cursor", img, egui::TextureOptions::NEAREST);
                        (tex, egui::vec2(f32::from(hot_x), f32::from(hot_y)))
                    });
                }
                SessionEvent::Resized { width, height } => {
                    remote.status = format!("{width}x{height}");
                }
                SessionEvent::Bell | SessionEvent::Updated => {}
            }
        }
        if remote.ended && !remote.connected && remote.texture.is_none() {
            self.error = Some(remote.status.clone());
            self.remote = None;
            self.connect_screen(ctx);
            return;
        }
        sync_texture(ctx, remote);

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
            self.remote = None;
        }
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
