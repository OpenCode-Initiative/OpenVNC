//! OpenVNC Configuracoes: assistente da primeira execucao e tela de ajustes
//! do servidor. Edita `%ProgramData%\OpenVNC\openvnc.toml`, ajusta o firewall
//! e a tarefa agendada e reinicia o servidor. Precisa rodar elevado.
//!
//! `openvnc-config --stop` pede a senha de administracao (se houver) e
//! encerra o servidor; e o que a bandeja chama em "Sair".

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use eframe::egui;
use openvnc_security::passhash;

const TASK: &str = "OpenVNC Server";
const RULE: &str = "OpenVNC Server";

fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("OpenVNC")
}

fn config_path() -> PathBuf {
    data_dir().join("openvnc.toml")
}

fn server_exe() -> PathBuf {
    std::env::current_exe()
        .map(|e| e.with_file_name("openvnc-server.exe"))
        .unwrap_or_else(|_| PathBuf::from("openvnc-server.exe"))
}

/// Comando sem janela de console.
fn cmd(program: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut c = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c
}

/// Roda e devolve a saida padrao; erro com a saida de erro.
fn run(c: &mut Command, stdin: Option<&str>) -> anyhow::Result<String> {
    use std::io::Write as _;
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(s) = stdin {
        if let Some(mut i) = child.stdin.take() {
            writeln!(i, "{s}")?;
        }
    } else {
        drop(child.stdin.take());
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn server(args: &[&str], stdin: Option<&str>) -> anyhow::Result<String> {
    let cfg = config_path();
    let mut c = cmd(server_exe());
    c.arg("--config").arg(&cfg).args(args);
    run(&mut c, stdin)
}

fn powershell(script: &str) -> anyhow::Result<String> {
    run(
        cmd("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script]),
        None,
    )
}

/// Reabre este programa elevado (UAC) se a pasta de dados nao for legivel.
fn ensure_elevated() -> bool {
    let p = config_path();
    match std::fs::File::open(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
        _ => return true,
    }
    let exe = std::env::current_exe().unwrap_or_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut script = format!("Start-Process -FilePath '{}' -Verb RunAs", exe.display());
    if !args.is_empty() {
        script.push_str(&format!(" -ArgumentList '{}'", args.join(" ")));
    }
    let _ = powershell(&script);
    false
}

fn stop_server() -> anyhow::Result<()> {
    let _ = run(cmd("schtasks.exe").args(["/End", "/TN", TASK]), None);
    let _ = run(
        cmd("taskkill.exe").args(["/F", "/IM", "openvnc-server.exe"]),
        None,
    );
    Ok(())
}

fn restart_server() -> anyhow::Result<()> {
    stop_server()?;
    run(cmd("schtasks.exe").args(["/Run", "/TN", TASK]), None)?;
    Ok(())
}

/// Etapas do assistente (e abas da tela de ajustes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Page {
    Intro,
    Password,
    Admin,
    Access,
    Files,
    Pair,
    Summary,
}

const PAGES: [Page; 7] = [
    Page::Intro,
    Page::Password,
    Page::Admin,
    Page::Access,
    Page::Files,
    Page::Pair,
    Page::Summary,
];

impl Page {
    fn title(self) -> &'static str {
        match self {
            Page::Intro => "Introducao",
            Page::Password => "Senha de acesso remoto",
            Page::Admin => "Senha de administracao",
            Page::Access => "Acesso remoto",
            Page::Files => "Arquivos",
            Page::Pair => "Parear dispositivo",
            Page::Summary => "Resumo",
        }
    }

    /// Explicacao do (?) ao lado do titulo da etapa.
    fn help(self) -> &'static str {
        match self {
            Page::Intro => "Visao geral do assistente e de como os ajustes funcionam.",
            Page::Password => {
                "A senha que a outra pessoa digita no OpenVNC Cliente para acessar este \
                 computador. Fica guardada so como hash (Argon2): nem este programa \
                 consegue mostra-la depois. Se esquecer, basta definir outra aqui."
            }
            Page::Admin => {
                "Senha local, para quem usa ESTE computador. Sem ela, qualquer usuario \
                 daqui pode abrir estes ajustes ou encerrar o servidor pela bandeja. \
                 Nao e usada no acesso remoto; use uma diferente da senha remota."
            }
            Page::Access => {
                "Como e de onde as conexoes sao aceitas. Passe o mouse sobre cada (?) \
                 para ver o que a opcao muda."
            }
            Page::Files => {
                "Transferencia de arquivos entre o cliente e este computador. Cada \
                 arquivo, em qualquer sentido, precisa ser aceito por quem recebe."
            }
            Page::Pair => {
                "Parear e cadastrar um aparelho especifico (ex.: o notebook do suporte) \
                 com credencial propria: um usuario e um token gerados aqui. Esse \
                 aparelho entra com eles em vez da senha de acesso remoto.\n\n\
                 Vantagem: se o aparelho for perdido ou nao deva mais acessar, voce \
                 revoga so ele, sem trocar a senha de todo mundo.\n\n\
                 Como usar: digite um nome, clique em Parear e, no OpenVNC Cliente \
                 daquele aparelho, informe o usuario no campo Usuario e o token no \
                 campo Senha. Totalmente opcional: pode pular esta etapa."
            }
            Page::Summary => {
                "Confira tudo antes de concluir. A impressao digital identifica este \
                 servidor: na primeira conexao o cliente mostra o mesmo codigo. Se for \
                 diferente, alguem pode estar interceptando a conexao."
            }
        }
    }
}

/// Marcador (?) com explicacao ao passar o mouse.
fn tip(ui: &mut egui::Ui, text: &str) {
    let r = ui
        .add(
            egui::Button::new(egui::RichText::new("?").strong().size(13.0))
                .corner_radius(10.0)
                .min_size(egui::vec2(22.0, 22.0)),
        )
        .on_hover_cursor(egui::CursorIcon::Help);
    let id = r.id.with("tip");
    if r.clicked() {
        ui.memory_mut(|m| m.toggle_popup(id));
    }
    let open = ui.memory(|m| m.is_popup_open(id));
    let r = if open { r } else { r.on_hover_text(text) };
    #[allow(deprecated)]
    egui::popup_below_widget(
        ui,
        id,
        &r,
        egui::PopupCloseBehavior::CloseOnClickOutside,
        |ui| {
            ui.set_max_width(380.0);
            ui.label(text);
        },
    );
}

/// Opcao seguida do (?) na mesma linha.
fn with_tip<R>(ui: &mut egui::Ui, text: &str, f: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.horizontal(|ui| {
        let r = f(ui);
        tip(ui, text);
        r
    })
    .inner
}

struct App {
    table: toml::Table,
    wizard: bool,
    page: Page,
    /// Tela de ajustes protegida: senha de administracao ainda nao conferida.
    locked: bool,
    unlock: String,
    // senha remota
    pw: String,
    pw2: String,
    show_pw: bool,
    generated: bool,
    legacy: bool,
    // administracao
    admin: String,
    admin2: String,
    // acesso
    port: String,
    control: bool,
    tls: bool,
    lan_only: bool,
    ask: bool,
    autostart: bool,
    // arquivos
    f_recv: bool,
    f_send: bool,
    f_dir: String,
    f_max: String,
    // pareamento
    pair_name: String,
    pair_out: Option<String>,
    fingerprint: Option<String>,
    msg: Option<(bool, String)>,
    done: bool,
}

fn get_bool(t: &toml::Table, k: &str, d: bool) -> bool {
    t.get(k).and_then(|v| v.as_bool()).unwrap_or(d)
}

fn get_str(t: &toml::Table, k: &str) -> Option<String> {
    t.get(k).and_then(|v| v.as_str()).map(str::to_string)
}

impl App {
    fn load() -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(config_path()).unwrap_or_default();
        let table: toml::Table = text.parse()?;
        let wizard = !get_bool(&table, "setup_done", false);
        let port = get_str(&table, "listen")
            .and_then(|l| l.rsplit_once(':').map(|(_, p)| p.to_string()))
            .unwrap_or_else(|| "5900".into());
        let locked = !wizard && table.contains_key("admin_password_hash");
        let autostart = task_enabled().unwrap_or(true);
        Ok(App {
            wizard,
            page: Page::Intro,
            locked,
            unlock: String::new(),
            pw: String::new(),
            pw2: String::new(),
            show_pw: false,
            generated: false,
            legacy: table.contains_key("password_protected"),
            admin: String::new(),
            admin2: String::new(),
            port,
            control: !get_bool(&table, "view_only", false),
            tls: get_bool(&table, "require_tls", true),
            lan_only: get_bool(&table, "lan_only", true),
            ask: get_bool(&table, "allow_attended", false),
            autostart,
            f_recv: get_bool(&table, "files_receive", true),
            f_send: get_bool(&table, "files_send", true),
            f_dir: get_str(&table, "files_dir").unwrap_or_default(),
            f_max: table
                .get("files_max_mb")
                .and_then(|v| v.as_integer())
                .unwrap_or(4096)
                .to_string(),
            pair_name: String::new(),
            pair_out: None,
            fingerprint: None,
            msg: None,
            done: false,
            table,
        })
    }

    fn has_remote_password(&self) -> bool {
        ["password", "password_hash", "password_protected"]
            .iter()
            .any(|k| self.table.contains_key(*k))
    }

    /// Valida a etapa atual; `Err` com a mensagem para o usuario.
    fn check(&self, page: Page) -> Result<(), String> {
        match page {
            Page::Password => {
                if self.pw.is_empty() {
                    if self.has_remote_password() || !self.wizard {
                        return Ok(());
                    }
                    return Err("defina a senha de acesso remoto".into());
                }
                if self.pw != self.pw2 {
                    return Err("as senhas nao conferem".into());
                }
                if passhash::strength(&self.pw) < 2 {
                    return Err("senha fraca: use 12 caracteres ou mais, com variedade".into());
                }
                Ok(())
            }
            Page::Admin => {
                if self.admin != self.admin2 {
                    return Err("as senhas de administracao nao conferem".into());
                }
                if !self.admin.is_empty() && self.admin == self.pw {
                    return Err("use uma senha de administracao diferente da remota".into());
                }
                Ok(())
            }
            Page::Access => match self.port.trim().parse::<u16>() {
                Ok(p) if p > 0 && p < u16::MAX => {
                    if !self.tls && !self.legacy {
                        return Err(
                            "sem TLS so funciona com a compatibilidade com VNC antigo".into()
                        );
                    }
                    Ok(())
                }
                _ => Err("porta invalida".into()),
            },
            Page::Files => match self.f_max.trim().parse::<u64>() {
                Ok(n) if n > 0 => Ok(()),
                _ => Err("tamanho maximo invalido".into()),
            },
            Page::Intro | Page::Pair | Page::Summary => Ok(()),
        }
    }

    fn port(&self) -> u16 {
        self.port.trim().parse().unwrap_or(5900)
    }

    /// Grava a configuracao, ajusta firewall e tarefa e reinicia o servidor.
    fn apply(&mut self) -> anyhow::Result<()> {
        for p in PAGES {
            self.check(p).map_err(anyhow::Error::msg)?;
        }
        let t = &mut self.table;
        let port = self.port.trim().parse::<u16>().unwrap_or(5900);
        t.insert("listen".into(), format!("0.0.0.0:{port}").into());
        t.insert(
            "native_listen".into(),
            format!("0.0.0.0:{}", port + 1).into(),
        );
        if !self.pw.is_empty() {
            for k in [
                "password",
                "password_env",
                "password_hash",
                "password_protected",
            ] {
                t.remove(k);
            }
            if self.legacy {
                let enc = server(&["protect-password"], Some(&self.pw))?;
                t.insert("password_protected".into(), enc.into());
            } else {
                let h = passhash::hash(&self.pw).map_err(anyhow::Error::msg)?;
                t.insert("password_hash".into(), h.into());
            }
        } else if !self.legacy && t.contains_key("password_protected") {
            anyhow::bail!("para desligar a compatibilidade, digite a senha novamente");
        }
        if !self.admin.is_empty() {
            let h = passhash::hash(&self.admin).map_err(anyhow::Error::msg)?;
            t.insert("admin_password_hash".into(), h.into());
        }
        t.insert("view_only".into(), (!self.control).into());
        t.insert("require_tls".into(), self.tls.into());
        t.insert("tls".into(), self.tls.into());
        t.insert("pairing".into(), self.tls.into());
        t.insert("lan_only".into(), self.lan_only.into());
        t.remove("ask_before_accept");
        t.insert("allow_attended".into(), self.ask.into());
        t.insert("files_receive".into(), self.f_recv.into());
        t.insert("files_send".into(), self.f_send.into());
        if self.f_dir.trim().is_empty() {
            t.remove("files_dir");
        } else {
            t.insert("files_dir".into(), self.f_dir.trim().to_string().into());
        }
        let max: i64 = self.f_max.trim().parse().unwrap_or(4096);
        t.insert("files_max_mb".into(), max.into());
        t.insert("capture".into(), "native".into());
        t.insert("setup_done".into(), true.into());
        if !t.contains_key("state_dir") {
            t.insert(
                "state_dir".into(),
                data_dir()
                    .join("state")
                    .to_string_lossy()
                    .into_owned()
                    .into(),
            );
        }
        let text = format!(
            "# OpenVNC Server. Gerado por OpenVNC Configuracoes.\n{}",
            toml::to_string(t)?
        );
        std::fs::write(config_path(), text)?;
        firewall(port, self.lan_only)?;
        let flag = if self.autostart {
            "/ENABLE"
        } else {
            "/DISABLE"
        };
        run(
            cmd("schtasks.exe").args(["/Change", "/TN", TASK, flag]),
            None,
        )?;
        restart_server()?;
        self.pw.clear();
        self.pw2.clear();
        self.admin.clear();
        self.admin2.clear();
        self.wizard = false;
        Ok(())
    }
}

fn task_enabled() -> Option<bool> {
    let out = run(
        cmd("schtasks.exe").args(["/Query", "/TN", TASK, "/FO", "LIST"]),
        None,
    )
    .ok()?;
    Some(!out.contains("Desabilitad") && !out.contains("Disabled"))
}

/// Regras de entrada: RFB (TCP) e nativo (TCP e UDP para o QUIC).
fn firewall(port: u16, lan_only: bool) -> anyhow::Result<()> {
    let exe = server_exe();
    let (profile, remote) = if lan_only {
        ("Private,Domain", "-RemoteAddress LocalSubnet")
    } else {
        ("Any", "")
    };
    let np = port + 1;
    let script = format!(
        "Get-NetFirewallRule -DisplayName '{RULE}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         New-NetFirewallRule -DisplayName '{RULE}' -Direction Inbound -Action Allow -Protocol TCP \
           -LocalPort {port},{np} -Program '{exe}' -Profile {profile} {remote} | Out-Null; \
         New-NetFirewallRule -DisplayName '{RULE} (QUIC)' -Direction Inbound -Action Allow -Protocol UDP \
           -LocalPort {np} -Program '{exe}' -Profile {profile} {remote} | Out-Null",
        exe = exe.display()
    );
    powershell(&script).map(|_| ())
}

fn strength_bar(ui: &mut egui::Ui, pw: &str) {
    if pw.is_empty() {
        return;
    }
    let s = passhash::strength(pw);
    let (txt, color) = match s {
        0 => ("muito fraca", egui::Color32::from_rgb(200, 60, 60)),
        1 => ("fraca", egui::Color32::from_rgb(220, 120, 50)),
        2 => ("razoavel", egui::Color32::from_rgb(210, 180, 40)),
        3 => ("boa", egui::Color32::from_rgb(120, 180, 60)),
        _ => ("forte", egui::Color32::from_rgb(60, 170, 80)),
    };
    ui.add(
        egui::ProgressBar::new((s as f32 + 1.0) / 5.0)
            .fill(color)
            .text(format!("forca: {txt}")),
    );
}

fn secret(ui: &mut egui::Ui, v: &mut String, show: bool, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(v)
            .password(!show)
            .hint_text(hint)
            .desired_width(320.0),
    )
}

impl App {
    fn page_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.heading(self.page.title());
            tip(ui, self.page.help());
        });
        ui.add_space(8.0);
        match self.page {
            Page::Intro => {
                ui.label(
                    "Este assistente configura o OpenVNC Server, que permite acessar e \
                     controlar este computador a partir de outro, pelo OpenVNC Cliente.",
                );
                ui.add_space(6.0);
                for t in [
                    "Nada aqui e definitivo: tudo pode ser alterado depois, pelo atalho \
                     \"OpenVNC Configuracoes\" no menu Iniciar ou pelo icone na bandeja.",
                    "Os padroes sao os mais seguros: TLS obrigatorio, somente rede local, \
                     acesso so com senha e arquivos sempre com confirmacao de quem recebe.",
                    "Opcoes menos seguras (compatibilidade com VNC antigo sem TLS, acesso \
                     por qualquer rede, conexao sem senha com autorizacao local) existem, \
                     mas ficam desligadas ate voce ativa-las conscientemente.",
                    "Cada etapa e cada opcao tem um (?): passe o mouse por cima para ver o \
                     que ela faz e o que afeta.",
                    "Nada e aplicado ate voce clicar em Concluir na ultima etapa.",
                ] {
                    ui.horizontal_wrapped(|ui| {
                        ui.label("\u{2022}");
                        ui.label(t);
                    });
                    ui.add_space(2.0);
                }
            }
            Page::Password => {
                ui.label("Quem se conectar a este computador precisara desta senha.");
                if self.has_remote_password() {
                    ui.label(
                        egui::RichText::new("Ja existe uma senha. Deixe em branco para mante-la.")
                            .weak(),
                    );
                }
                ui.add_space(6.0);
                secret(ui, &mut self.pw, self.show_pw, "senha");
                secret(ui, &mut self.pw2, self.show_pw, "repita a senha");
                strength_bar(ui, &self.pw);
                ui.horizontal(|ui| {
                    if ui.button("Gerar senha forte").clicked() {
                        self.pw = passhash::generate();
                        self.pw2 = self.pw.clone();
                        self.show_pw = true;
                        self.generated = true;
                    }
                    ui.checkbox(&mut self.show_pw, "Mostrar");
                    if self.generated && !self.pw.is_empty() && ui.button("Copiar").clicked() {
                        ctx.copy_text(self.pw.clone());
                    }
                });
                if self.generated && !self.pw.is_empty() {
                    ui.label(
                        egui::RichText::new(
                            "Anote ou copie agora: a senha nao fica guardada, so o hash dela.",
                        )
                        .color(egui::Color32::from_rgb(210, 160, 40)),
                    );
                }
                ui.add_space(8.0);
                with_tip(
                    ui,
                    "MENOS SEGURO. Permite clientes VNC comuns (TightVNC, RealVNC...) que \
                     nao usam TLS: tela e teclado trafegam sem criptografia. A senha passa \
                     a ser guardada cifrada (DPAPI), nao so como hash, e esses clientes \
                     usam so os 8 primeiros caracteres. Deixe desligado se usar apenas o \
                     OpenVNC Cliente.",
                    |ui| {
                        ui.checkbox(
                            &mut self.legacy,
                            "Compatibilidade com clientes VNC antigos (sem TLS)",
                        )
                    },
                );
                ui.label(
                    egui::RichText::new(
                        "Guarda a senha cifrada com DPAPI em vez de so o hash. Clientes antigos \
                         usam apenas os 8 primeiros caracteres.",
                    )
                    .small()
                    .weak(),
                );
            }
            Page::Admin => {
                ui.label("Opcional. Protege esta tela de ajustes e o comando \"Sair\" da bandeja.");
                ui.add_space(6.0);
                secret(
                    ui,
                    &mut self.admin,
                    false,
                    "senha de administracao (opcional)",
                );
                secret(ui, &mut self.admin2, false, "repita");
                strength_bar(ui, &self.admin);
                if self.table.contains_key("admin_password_hash") {
                    ui.label(
                        egui::RichText::new("Ja existe uma. Deixe em branco para mante-la.").weak(),
                    );
                }
            }
            Page::Access => {
                ui.horizontal(|ui| {
                    ui.label("Porta:");
                    ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(70.0));
                    tip(
                        ui,
                        "Porta TCP onde o servidor escuta (padrao 5900). A seguinte e usada \
                         pelo protocolo nativo (arquivos e video). So mude se a 5900 ja \
                         estiver em uso ou por exigencia da sua rede; o cliente precisa \
                         usar a mesma porta.",
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "(arquivos e protocolo nativo em {})",
                            self.port() as u32 + 1
                        ))
                        .weak(),
                    );
                });
                ui.add_space(4.0);
                with_tip(
                    ui,
                    "Quem conectar pode mover o mouse e digitar neste computador.",
                    |ui| ui.radio_value(&mut self.control, true, "Controlar mouse e teclado"),
                );
                with_tip(
                    ui,
                    "Quem conectar so ve a tela; mouse e teclado remotos sao ignorados. \
                     Bom para demonstracoes e acompanhamento.",
                    |ui| ui.radio_value(&mut self.control, false, "Somente visualizar"),
                );
                ui.add_space(4.0);
                with_tip(
                    ui,
                    "Criptografa toda a conexao (tela, teclado, senha e arquivos) e deixa \
                     o cliente conferir a identidade deste servidor. Desligar so faz \
                     sentido com clientes VNC antigos. Pareamento e transferencia de \
                     arquivos exigem TLS.",
                    |ui| ui.checkbox(&mut self.tls, "Exigir TLS (recomendado)"),
                );
                ui.add_space(4.0);
                with_tip(
                    ui,
                    "Aceita so enderecos da rede interna (casa ou escritorio). Conexoes \
                     vindas da internet sao recusadas mesmo que o roteador as encaminhe.",
                    |ui| ui.radio_value(&mut self.lan_only, true, "Somente a rede local"),
                );
                with_tip(
                    ui,
                    "MENOS SEGURO. Aceita conexoes de qualquer endereco. Necessario para \
                     acesso pela internet (com redirecionamento de porta no roteador ou \
                     VPN). Use senha forte e mantenha o TLS ligado.",
                    |ui| {
                        ui.radio_value(
                            &mut self.lan_only,
                            false,
                            "Qualquer rede (inclusive internet, se houver redirecionamento)",
                        )
                    },
                );
                ui.add_space(4.0);
                with_tip(
                    ui,
                    "Desligado: so entra quem tem a senha (ou um aparelho pareado).\n\n\
                     Ligado: alem disso, quem NAO tem a senha pode pedir acesso. Aparece \
                     uma janela neste computador e so conecta se alguem aqui aceitar, \
                     como no AnyDesk. Quem tem a senha continua entrando direto. Util \
                     para suporte com alguem presente na frente da tela.",
                    |ui| {
                        ui.checkbox(
                            &mut self.ask,
                            "Permitir conexao sem senha, se autorizado aqui",
                        )
                    },
                );
                ui.label(
                    egui::RichText::new(
                        "Quem tem a senha entra direto. Sem senha, aparece um pedido \
                         neste computador e so conecta se alguem aceitar.",
                    )
                    .weak(),
                );
                with_tip(
                    ui,
                    "Inicia o servidor automaticamente quando voce entra no Windows. \
                     Desligado, ele so roda quando aberto manualmente.",
                    |ui| ui.checkbox(&mut self.autostart, "Iniciar com o Windows"),
                );
            }
            Page::Files => {
                with_tip(
                    ui,
                    "Quem estiver conectado pode mandar arquivos para este computador. \
                     Cada um so e salvo depois que alguem aqui aceita, chega na pasta \
                     abaixo com integridade conferida, e nada e executado sozinho.",
                    |ui| ui.checkbox(&mut self.f_recv, "Receber arquivos enviados pelos clientes"),
                );
                with_tip(
                    ui,
                    "Permite mandar arquivos daqui para quem esta conectado, pelo menu do \
                     icone na bandeja. O cliente sempre precisa aceitar antes de receber.",
                    |ui| {
                        ui.checkbox(
                            &mut self.f_send,
                            "Enviar arquivos aos clientes (pela bandeja)",
                        )
                    },
                );
                ui.add_space(6.0);
                with_tip(
                    ui,
                    "Onde os arquivos recebidos sao salvos. Em branco, usa a pasta \
                     OpenVNC dentro de Downloads do usuario. O botao de pasta abre o \
                     Explorer para escolher.",
                    |ui| ui.label("Pasta de recebimento:"),
                );
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.f_dir)
                            .hint_text("padrao: Downloads\\OpenVNC")
                            .desired_width(320.0),
                    );
                    if ui
                        .button("\u{1F4C1}")
                        .on_hover_text("Escolher pasta")
                        .clicked()
                    {
                        if let Some(d) = pick_folder(&self.f_dir) {
                            self.f_dir = d;
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Tamanho maximo por arquivo (MB):");
                    ui.add(egui::TextEdit::singleline(&mut self.f_max).desired_width(80.0));
                    tip(
                        ui,
                        "Ofertas maiores que isso sao recusadas automaticamente, para nao \
                         encher o disco. 1024 MB = 1 GB.",
                    );
                });
            }
            Page::Pair => {
                ui.label(
                    "Opcional, pode pular. Cadastra um aparelho especifico (ex.: o notebook \
                     do suporte) com usuario e token proprios. Ele entra com essas \
                     credenciais em vez da senha de acesso remoto e pode ser bloqueado \
                     sozinho depois, sem trocar a senha de todo mundo.",
                );
                ui.label(
                    egui::RichText::new(
                        "No OpenVNC Cliente do aparelho: usuario no campo Usuario e token no \
                         campo Senha.",
                    )
                    .weak(),
                );
                ui.add_space(4.0);
                if !self.tls {
                    ui.label(egui::RichText::new("O pareamento exige TLS.").weak());
                    return;
                }
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pair_name)
                            .hint_text("nome do dispositivo")
                            .desired_width(240.0),
                    );
                    let ok = !self.pair_name.trim().is_empty();
                    if ui.add_enabled(ok, egui::Button::new("Parear")).clicked() {
                        match server(&["pair", "add", self.pair_name.trim()], None) {
                            Ok(o) => {
                                self.pair_out = Some(o);
                                self.pair_name.clear();
                            }
                            Err(e) => self.msg = Some((false, format!("pareamento: {e}"))),
                        }
                    }
                });
                if let Some(o) = &self.pair_out {
                    ui.add_space(6.0);
                    ui.add(
                        egui::TextEdit::multiline(&mut o.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    );
                    if ui.button("Copiar").clicked() {
                        ctx.copy_text(o.clone());
                    }
                    ui.label(
                        egui::RichText::new("O token aparece so agora; entregue-o ao dispositivo.")
                            .color(egui::Color32::from_rgb(210, 160, 40)),
                    );
                }
            }
            Page::Summary => {
                if self.fingerprint.is_none() {
                    self.fingerprint = Some(
                        server(&["fingerprint"], None).unwrap_or_else(|e| format!("erro: {e}")),
                    );
                }
                let yes = |b: bool| if b { "sim" } else { "nao" };
                egui::Grid::new("sum").num_columns(2).show(ui, |ui| {
                    ui.label("Porta");
                    ui.label(format!(
                        "{} (nativo {})",
                        self.port(),
                        self.port() as u32 + 1
                    ));
                    ui.end_row();
                    ui.label("Modo");
                    ui.label(if self.control {
                        "controle"
                    } else {
                        "so visualizacao"
                    });
                    ui.end_row();
                    ui.label("TLS obrigatorio");
                    ui.label(yes(self.tls));
                    ui.end_row();
                    ui.label("Rede");
                    ui.label(if self.lan_only {
                        "somente local"
                    } else {
                        "qualquer"
                    });
                    ui.end_row();
                    ui.label("Sem senha, se autorizado");
                    ui.label(yes(self.ask));
                    ui.end_row();
                    ui.label("Iniciar com o Windows");
                    ui.label(yes(self.autostart));
                    ui.end_row();
                    ui.label("Arquivos");
                    ui.label(format!(
                        "receber: {}, enviar: {}",
                        yes(self.f_recv),
                        yes(self.f_send)
                    ));
                    ui.end_row();
                });
                ui.add_space(8.0);
                ui.label("Impressao digital do certificado (confira no cliente):");
                if let Some(fp) = &self.fingerprint {
                    ui.horizontal(|ui| {
                        ui.monospace(fp);
                        if ui.small_button("Copiar").clicked() {
                            ctx.copy_text(fp.clone());
                        }
                    });
                }
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.locked {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("OpenVNC Configuracoes");
                ui.label("Digite a senha de administracao.");
                let r = secret(ui, &mut self.unlock, false, "senha de administracao");
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Entrar").clicked() || enter {
                    let h = get_str(&self.table, "admin_password_hash").unwrap_or_default();
                    if passhash::verify(self.unlock.as_bytes(), &h) {
                        self.locked = false;
                    } else {
                        self.msg = Some((false, "senha incorreta".into()));
                    }
                    self.unlock.clear();
                }
                show_msg(ui, &self.msg);
            });
            return;
        }
        if self.done {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Pronto!");
                ui.label("O servidor foi configurado e reiniciado.");
                ui.label("Use o OpenVNC Cliente em outro computador para se conectar.");
                if ui.button("Fechar").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            return;
        }
        egui::SidePanel::left("pages")
            .resizable(false)
            .exact_width(190.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.heading(if self.wizard { "Assistente" } else { "Ajustes" });
                ui.add_space(8.0);
                let cur = PAGES.iter().position(|p| *p == self.page).unwrap_or(0);
                for (i, p) in PAGES.iter().enumerate() {
                    let label = format!("{i}. {}", p.title());
                    // no assistente, so volta ou fica na etapa atual
                    let enabled = !self.wizard || i <= cur;
                    if ui
                        .add_enabled(enabled, egui::SelectableLabel::new(*p == self.page, label))
                        .clicked()
                    {
                        self.page = *p;
                        self.msg = None;
                    }
                }
            });
        egui::TopBottomPanel::bottom("nav").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let cur = PAGES.iter().position(|p| *p == self.page).unwrap_or(0);
                if self.wizard {
                    if cur > 0 && ui.button("Voltar").clicked() {
                        self.page = PAGES[cur - 1];
                        self.msg = None;
                    }
                    if cur + 1 < PAGES.len() {
                        if ui.button("Avancar").clicked() {
                            match self.check(self.page) {
                                Ok(()) => {
                                    self.page = PAGES[cur + 1];
                                    self.msg = None;
                                }
                                Err(e) => self.msg = Some((false, e)),
                            }
                        }
                    } else if ui.button("Concluir").clicked() {
                        match self.apply() {
                            Ok(()) => self.done = true,
                            Err(e) => self.msg = Some((false, format!("{e:#}"))),
                        }
                    }
                } else {
                    if ui.button("Salvar e reiniciar o servidor").clicked() {
                        self.msg = Some(match self.apply() {
                            Ok(()) => (true, "salvo; servidor reiniciado".into()),
                            Err(e) => (false, format!("{e:#}")),
                        });
                    }
                    if ui.button("Reiniciar o servidor").clicked() {
                        self.msg = Some(match restart_server() {
                            Ok(()) => (true, "servidor reiniciado".into()),
                            Err(e) => (false, format!("{e:#}")),
                        });
                    }
                }
                show_msg(ui, &self.msg);
            });
            ui.add_space(6.0);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.page_ui(ui, ctx));
        });
    }
}

fn show_msg(ui: &mut egui::Ui, msg: &Option<(bool, String)>) {
    if let Some((ok, m)) = msg {
        let c = if *ok {
            egui::Color32::from_rgb(80, 170, 90)
        } else {
            egui::Color32::from_rgb(210, 70, 70)
        };
        ui.colored_label(c, m);
    }
}

/// `--stop`: confere a senha de administracao e encerra o servidor.
struct Stop {
    hash: String,
    pw: String,
    msg: Option<(bool, String)>,
}

impl eframe::App for Stop {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Encerrar o OpenVNC Server");
            ui.label("Digite a senha de administracao.");
            let r = secret(ui, &mut self.pw, false, "senha de administracao");
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button("Encerrar").clicked() || enter {
                if passhash::verify(self.pw.as_bytes(), &self.hash) {
                    let _ = stop_server();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                } else {
                    self.msg = Some((false, "senha incorreta".into()));
                }
                self.pw.clear();
            }
            show_msg(ui, &self.msg);
        });
    }
}

fn window(title: &str, size: [f32; 2]) -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(size)
            .with_resizable(true),
        ..Default::default()
    }
}

fn fail(msg: String) -> eframe::Result {
    eframe::run_simple_native(
        "OpenVNC Configuracoes",
        window("OpenVNC", [460.0, 160.0]),
        move |ctx, _| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Nao foi possivel abrir a configuracao");
                ui.label(&msg);
            });
        },
    )
}

fn main() -> eframe::Result {
    if !ensure_elevated() {
        return Ok(());
    }
    let stop = std::env::args().any(|a| a == "--stop");
    let app = match App::load() {
        Ok(a) => a,
        Err(e) => return fail(format!("{}: {e:#}", Path::new(&config_path()).display())),
    };
    if stop {
        let Some(hash) = get_str(&app.table, "admin_password_hash") else {
            let _ = stop_server();
            return Ok(());
        };
        return eframe::run_native(
            "OpenVNC",
            window("OpenVNC: encerrar", [440.0, 210.0]),
            Box::new(|cc| {
                ui_style(&cc.egui_ctx);
                Ok(Box::new(Stop {
                    hash,
                    pw: String::new(),
                    msg: None,
                }))
            }),
        );
    }
    eframe::run_native(
        "OpenVNC Configuracoes",
        window("OpenVNC Configuracoes", [900.0, 640.0]),
        Box::new(|cc| {
            ui_style(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
}

/// Textos e campos maiores, com mais respiro.
fn ui_style(ctx: &egui::Context) {
    use egui::{FontFamily, FontId, TextStyle};
    ctx.all_styles_mut(|s| {
        s.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(26.0, FontFamily::Proportional),
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
        s.spacing.item_spacing = egui::vec2(10.0, 9.0);
        s.spacing.button_padding = egui::vec2(12.0, 7.0);
        s.spacing.interact_size.y = 32.0;
        s.spacing.icon_width = 20.0;
        s.visuals.widgets.inactive.corner_radius = 6.0.into();
        s.visuals.widgets.hovered.corner_radius = 6.0.into();
        s.visuals.widgets.active.corner_radius = 6.0.into();
    });
}

/// Dialogo nativo de selecao de pasta (via PowerShell, sem dependencias).
fn pick_folder(start: &str) -> Option<String> {
    let script = "Add-Type -AssemblyName System.Windows.Forms; \
        $d = New-Object System.Windows.Forms.FolderBrowserDialog; \
        $d.Description = 'Pasta de recebimento do OpenVNC'; \
        $d.SelectedPath = $env:OVNC_START; \
        if ($d.ShowDialog() -eq 'OK') { [Console]::Out.Write($d.SelectedPath) }";
    let mut cmd = std::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-STA", "-Command", script])
        .env("OVNC_START", start);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = cmd.output().ok()?;
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!p.is_empty()).then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(toml: &str) -> App {
        let table: toml::Table = toml.parse().unwrap();
        App {
            wizard: true,
            page: Page::Intro,
            locked: false,
            unlock: String::new(),
            pw: String::new(),
            pw2: String::new(),
            show_pw: false,
            generated: false,
            legacy: false,
            admin: String::new(),
            admin2: String::new(),
            port: "5900".into(),
            control: true,
            tls: true,
            lan_only: true,
            ask: false,
            autostart: true,
            f_recv: true,
            f_send: true,
            f_dir: String::new(),
            f_max: "4096".into(),
            pair_name: String::new(),
            pair_out: None,
            fingerprint: None,
            msg: None,
            done: false,
            table,
        }
    }

    #[test]
    fn validacao_das_etapas() {
        let mut a = app("");
        assert!(a.check(Page::Password).is_err());
        a.pw = "curta".into();
        a.pw2 = "curta".into();
        assert!(a.check(Page::Password).is_err());
        a.pw = passhash::generate();
        a.pw2 = a.pw.clone();
        assert!(a.check(Page::Password).is_ok());
        a.admin = a.pw.clone();
        a.admin2 = a.pw.clone();
        assert!(a.check(Page::Admin).is_err());
        a.port = "70000".into();
        assert!(a.check(Page::Access).is_err());
        a.port = "5900".into();
        a.tls = false;
        assert!(a.check(Page::Access).is_err());
        a.legacy = true;
        assert!(a.check(Page::Access).is_ok());
        // senha ja existente pode ser mantida
        let b = app("password_hash = \"x\"");
        assert!(b.check(Page::Password).is_ok());
    }
}
