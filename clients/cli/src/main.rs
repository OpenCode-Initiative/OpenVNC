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
    o.config.password = if c.password_stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Some(Password::new(line.trim_end_matches(['\r', '\n'])))
    } else {
        std::env::var("OPENVNC_PASSWORD").ok().map(Password::new)
    };
    Ok(o)
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
                if let SessionEvent::Connected { legacy_auth, .. } = &e {
                    eprintln!(
                        "aviso: conexao SEM criptografia; use um tunel SSH em redes nao confiaveis"
                    );
                    if *legacy_auth {
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
                ..
            } = e
            {
                println!("nome:       {name}");
                println!("tamanho:    {width}x{height}");
                println!("protocolo:  {version:?}");
                println!(
                    "auth:       {}",
                    if legacy_auth {
                        "VNC Auth (DES)"
                    } else {
                        "None"
                    }
                );
                println!("criptografia: nao");
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
