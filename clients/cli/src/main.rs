//! `openvnc` — cliente VNC de linha de comando.
//!
//! A senha nunca e aceita como argumento (ficaria no historico do shell e
//! visivel em `ps`): use a variavel `OPENVNC_PASSWORD` ou `--password-stdin`.

use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use openvnc_client::{Command, ConnectOptions, Session, SessionEvent};
use openvnc_core::input::keysym;
use openvnc_core::{KeyEvent, PointerEvent};
use openvnc_rfb::Password;
use openvnc_transport::tls::{load_certs, normalize_fingerprint, ClientTls, KnownHosts, Trust};

#[derive(Parser)]
#[command(name = "openvnc", version, about = "Cliente VNC (RFB 3.3/3.7/3.8)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
struct Conn {
    /// host, host:display (ex.: host:1 = 5901) ou host::porta
    address: String,
    /// Le a senha da primeira linha da entrada padrao
    #[arg(long)]
    password_stdin: bool,
    /// Pede acesso exclusivo (desconecta outros clientes)
    #[arg(long)]
    exclusive: bool,
    /// Timeout total em segundos
    #[arg(long, default_value_t = 15)]
    timeout: u64,
    /// Exige VeNCrypt (TLS 1.3); sem downgrade para texto claro
    #[arg(long)]
    tls: bool,
    /// Fixa a impressao digital SHA-256 do certificado (implica --tls)
    #[arg(long, value_name = "SHA256")]
    pin: Option<String>,
    /// Trust on first use: aceita e grava um servidor ainda desconhecido
    /// em known_hosts (implica --tls; depois exige o mesmo certificado)
    #[arg(long)]
    tofu_accept: bool,
    /// Usa known_hosts sem aceitar hosts novos (implica --tls)
    #[arg(long)]
    tofu: bool,
    /// CA extra em PEM para validar o certificado (implica --tls)
    #[arg(long, value_name = "PEM")]
    ca: Option<PathBuf>,
    /// Usuario / id de dispositivo pareado (VeNCrypt X509Plain)
    #[arg(long)]
    user: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Conecta e salva o framebuffer como PNG
    Screenshot {
        #[command(flatten)]
        conn: Conn,
        /// Arquivo de saida
        #[arg(short, long, default_value = "screenshot.png")]
        output: PathBuf,
    },
    /// Digita um texto no servidor (KeyEvents; quebra de linha vira Return)
    Type {
        #[command(flatten)]
        conn: Conn,
        /// Clica em X,Y antes de digitar (para dar foco a uma janela)
        #[arg(long, value_parser = parse_xy)]
        at: Option<(u16, u16)>,
        /// Texto a digitar
        text: String,
    },
    /// Conecta e mostra informacoes do servidor
    Info {
        #[command(flatten)]
        conn: Conn,
    },
}

fn options(c: &Conn) -> anyhow::Result<ConnectOptions> {
    let addr = openvnc_transport::parse_address(&c.address)?;
    let mut o = ConnectOptions::new(addr);
    o.reconnect = false;
    o.config.shared = !c.exclusive;
    o.tls = tls_options(c)?;
    o.config.username = c.user.clone();
    o.config.password = if c.password_stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Some(Password::new(line.trim_end_matches(['\r', '\n'])))
    } else {
        std::env::var("OPENVNC_PASSWORD").ok().map(Password::new)
    };
    Ok(o)
}

fn tls_options(c: &Conn) -> anyhow::Result<Option<ClientTls>> {
    let modes = [c.pin.is_some(), c.tofu || c.tofu_accept, c.ca.is_some()];
    if modes.iter().filter(|m| **m).count() > 1 {
        bail!("use so um de --pin, --tofu/--tofu-accept, --ca");
    }
    let trust = if let Some(fp) = &c.pin {
        Trust::Pinned(normalize_fingerprint(fp)?)
    } else if c.tofu || c.tofu_accept {
        let path = KnownHosts::default_path()
            .ok_or_else(|| anyhow::anyhow!("sem diretorio para known_hosts"))?;
        Trust::Tofu {
            store: KnownHosts::new(path),
            accept_new: c.tofu_accept,
        }
    } else if let Some(ca) = &c.ca {
        Trust::WebPki {
            extra_roots: load_certs(&std::fs::read(ca)?)?,
        }
    } else if c.tls {
        Trust::default()
    } else {
        if c.user.is_some() {
            bail!("--user exige TLS (--tls, --pin, --tofu ou --ca)");
        }
        return Ok(None);
    };
    Ok(Some(ClientTls { trust }))
}

fn connect(
    c: &Conn,
    rt: &tokio::runtime::Runtime,
) -> anyhow::Result<(Session, SessionEvent, Instant)> {
    let deadline = Instant::now() + Duration::from_secs(c.timeout);
    let sess = Session::spawn(rt.handle(), options(c)?, Arc::new(|| {}));
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match sess.wait_event(left) {
            Some(e @ SessionEvent::Connected { .. }) => {
                if let SessionEvent::Connected {
                    legacy_auth,
                    encrypted,
                    ..
                } = &e
                {
                    if *encrypted {
                        eprintln!("conexao criptografada (VeNCrypt, TLS 1.3)");
                    } else {
                        eprintln!(
                            "aviso: conexao SEM criptografia; use --tls ou um tunel SSH em redes nao confiaveis"
                        );
                    }
                    if *legacy_auth && !*encrypted {
                        eprintln!("aviso: VNC Auth (DES) e fraca e nao protege a sessao");
                    }
                }
                return Ok((sess, e, deadline));
            }
            Some(SessionEvent::Disconnected { reason, .. }) => bail!("falha ao conectar: {reason}"),
            Some(_) => {}
            None => bail!("timeout ao conectar"),
        }
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new()?;
    match cli.cmd {
        Cmd::Info { conn } => {
            let (_s, e, _) = connect(&conn, &rt)?;
            if let SessionEvent::Connected {
                width,
                height,
                name,
                version,
                legacy_auth,
                encrypted,
            } = e
            {
                println!("nome:       {name}");
                println!("tamanho:    {width}x{height}");
                println!("protocolo:  {version:?}");
                println!(
                    "auth:       {}",
                    match (legacy_auth, encrypted, conn.user.is_some()) {
                        (true, true, _) => "VNC Auth dentro do TLS (X509Vnc)",
                        (true, false, _) => "VNC Auth (DES)",
                        (false, true, true) => "usuario/dispositivo (X509Plain)",
                        (false, true, false) => "nenhuma (X509None)",
                        (false, false, _) => "None",
                    }
                );
                println!(
                    "criptografia: {}",
                    if encrypted {
                        "TLS 1.3 (VeNCrypt)"
                    } else {
                        "nao"
                    }
                );
            }
        }
        Cmd::Type { conn, at, text } => {
            let (sess, _, _) = connect(&conn, &rt)?;
            if let Some((x, y)) = at {
                for buttons in [0, 1, 0] {
                    sess.send(Command::Pointer(PointerEvent { buttons, x, y }));
                }
            }
            for c in text.chars() {
                let ks = if c == '\n' {
                    keysym::RETURN
                } else {
                    keysym::from_char(c)
                };
                sess.send(Command::Key(KeyEvent {
                    down: true,
                    keysym: ks,
                }));
                sess.send(Command::Key(KeyEvent {
                    down: false,
                    keysym: ks,
                }));
            }
            // da tempo para a task de rede escrever antes de fechar
            std::thread::sleep(Duration::from_millis(300));
            println!("{} caracteres enviados", text.chars().count());
        }
        Cmd::Screenshot { conn, output } => {
            let (sess, _, deadline) = connect(&conn, &rt)?;
            // apos um resize o quadro e descartado; espera o update completo seguinte
            let mut resized = false;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match sess.wait_event(left) {
                    Some(SessionEvent::Resized { .. }) => resized = true,
                    Some(SessionEvent::Updated) if resized => resized = false,
                    Some(SessionEvent::Updated) => break,
                    Some(SessionEvent::Disconnected { reason, .. }) => {
                        bail!("desconectado: {reason}")
                    }
                    Some(_) => {}
                    None => bail!("timeout esperando o primeiro quadro"),
                }
            }
            let f = sess.frame().lock().expect("mutex");
            let fb = f.fb.as_ref().context("sem framebuffer")?;
            write_png(
                &output,
                u32::from(fb.width()),
                u32::from(fb.height()),
                fb.data(),
            )?;
            println!(
                "{}x{} salvo em {}",
                fb.width(),
                fb.height(),
                output.display()
            );
        }
    }
    Ok(())
}

fn write_png(path: &std::path::Path, w: u32, h: u32, rgba: &[u8]) -> anyhow::Result<()> {
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut enc = png::Encoder::new(file, w, h);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(rgba)?;
    Ok(())
}

fn parse_xy(s: &str) -> Result<(u16, u16), String> {
    let (x, y) = s.split_once(',').ok_or("formato esperado: X,Y")?;
    let n = |v: &str| v.trim().parse::<u16>().map_err(|e| e.to_string());
    Ok((n(x)?, n(y)?))
}
