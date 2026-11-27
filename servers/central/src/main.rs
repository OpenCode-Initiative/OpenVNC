//! Servidor central OpenVNC (on-premises).
//!
//! Guarda usuarios, grupos, maquinas e concessoes, autentica usuarios e
//! emite tickets curtos (JWT ES256) que os servidores OpenVNC conferem como
//! tokens OIDC. So fala HTTPS, com CA propria.

mod api;
mod config;
mod http;
mod pki;
mod store;
mod token;

use std::io::BufRead;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use openvnc_security::audit::AuditLog;
use openvnc_security::passhash;

use crate::config::Config;
use crate::store::{parse_perms, sha256_hex, valid_name, Store, User};

/// Variavel de ambiente com a senha (evita digitar; nunca use argv).
const PASSWORD_ENV: &str = "OPENVNC_CENTRAL_PASSWORD";
/// Tamanho minimo de senha.
const MIN_PASSWORD: usize = 8;

#[derive(Parser)]
#[command(name = "openvnc-central", version, about = "Servidor central OpenVNC")]
struct Cli {
    /// Arquivo de configuracao TOML.
    #[arg(short, long, default_value = "central.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Cria CA, chaves e banco vazio.
    Init,
    /// Sobe o servidor HTTPS.
    Serve,
    /// Exporta a CA (PEM) para instalar nos clientes e servidores.
    ExportCa {
        /// Arquivo de saida (padrao: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Usuarios.
    #[command(subcommand)]
    User(UserCmd),
    /// Grupos.
    #[command(subcommand)]
    Group(GroupCmd),
    /// Maquinas.
    #[command(subcommand)]
    Machine(MachineCmd),
    /// Concede acesso (substitui a concessao anterior do mesmo sujeito).
    Grant(GrantArgs),
    /// Remove a concessao.
    Revoke(SubjectArgs),
    /// Lista concessoes.
    Grants,
    /// Mostra o fim do log de auditoria.
    Audit {
        /// Linhas.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Cria usuario (senha por OPENVNC_CENTRAL_PASSWORD ou stdin).
    Add {
        /// Nome.
        name: String,
        /// Administrador (le a auditoria central).
        #[arg(long)]
        admin: bool,
        /// Grupos.
        #[arg(long = "group")]
        groups: Vec<String>,
    },
    /// Troca a senha.
    Passwd {
        /// Nome.
        name: String,
    },
    /// Desativa.
    Disable {
        /// Nome.
        name: String,
    },
    /// Reativa.
    Enable {
        /// Nome.
        name: String,
    },
    /// Remove (e as concessoes dele).
    Del {
        /// Nome.
        name: String,
    },
    /// Lista.
    List,
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Cria.
    Add {
        /// Nome.
        name: String,
    },
    /// Remove (e as concessoes dele).
    Del {
        /// Nome.
        name: String,
    },
    /// Lista.
    List,
    /// Poe usuario no grupo.
    AddUser {
        /// Grupo.
        group: String,
        /// Usuario.
        user: String,
    },
    /// Tira usuario do grupo.
    RemoveUser {
        /// Grupo.
        group: String,
        /// Usuario.
        user: String,
    },
}

#[derive(Subcommand)]
enum MachineCmd {
    /// Cadastra e mostra o segredo (uma unica vez).
    Add {
        /// Id (vai em `central_machine_id` do servidor).
        id: String,
        /// Nome para exibir.
        #[arg(long)]
        name: Option<String>,
        /// Host ou IP.
        #[arg(long)]
        address: String,
        /// Porta do protocolo nativo.
        #[arg(long, default_value_t = 5901)]
        port: u16,
        /// Impressao digital do certificado do servidor.
        #[arg(long)]
        fingerprint: Option<String>,
    },
    /// Remove (e as concessoes dela).
    Del {
        /// Id.
        id: String,
    },
    /// Lista.
    List,
    /// Gera novo segredo (o antigo deixa de valer).
    ResetSecret {
        /// Id.
        id: String,
    },
}

#[derive(Args)]
struct SubjectArgs {
    /// Usuario.
    #[arg(long, conflicts_with = "group", required_unless_present = "group")]
    user: Option<String>,
    /// Grupo.
    #[arg(long)]
    group: Option<String>,
    /// Maquina.
    #[arg(long)]
    machine: String,
}

impl SubjectArgs {
    fn subject(&self) -> String {
        match (&self.user, &self.group) {
            (Some(u), _) => format!("user:{u}"),
            (_, Some(g)) => format!("group:{g}"),
            _ => unreachable!("clap exige --user ou --group"),
        }
    }
}

#[derive(Args)]
struct GrantArgs {
    #[command(flatten)]
    who: SubjectArgs,
    /// Permissoes: view,control,files,clipboard.
    #[arg(long, default_value = "view")]
    perms: String,
    /// Sobrepoe a aprovacao local (true exige, false dispensa).
    #[arg(long)]
    ask: Option<bool>,
}

fn read_password(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var(PASSWORD_ENV) {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    eprint!("{prompt}: ");
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    let p = s.trim_end_matches(['\r', '\n']).to_owned();
    if p.chars().count() < MIN_PASSWORD {
        bail!("senha precisa ter ao menos {MIN_PASSWORD} caracteres");
    }
    Ok(p)
}

fn check_pw(p: &str) -> Result<()> {
    if p.chars().count() < MIN_PASSWORD {
        bail!("senha precisa ter ao menos {MIN_PASSWORD} caracteres");
    }
    Ok(())
}

fn name_ok(kind: &str, n: &str) -> Result<()> {
    if !valid_name(n) {
        bail!("{kind} invalido: use letras, numeros, - _ . @ (ate 64)");
    }
    Ok(())
}

fn audit(cfg: &Config) -> AuditLog {
    AuditLog::open(&cfg.audit_path()).unwrap_or_else(|e| {
        eprintln!("aviso: auditoria indisponivel: {e}");
        AuditLog::disabled()
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cfg = Config::load(&cli.config)?;
    let sp = cfg.store_path();
    match cli.cmd {
        Cmd::Init => {
            let p = pki::ensure(&cfg.state_dir, &cfg.tls_names)?;
            if !sp.exists() {
                Store::default().save(&sp)?;
            }
            let id = openvnc_transport::tls::ServerIdentity::from_pem(
                p.tls_chain_pem.as_bytes(),
                p.tls_key_pem.as_bytes(),
            )?;
            println!("estado em {}", cfg.state_dir.display());
            println!("emissor: {}", cfg.issuer);
            println!("certificado HTTPS: {}", id.fingerprint());
            println!("exporte a CA com: openvnc-central export-ca --out central-ca.pem");
        }
        Cmd::Serve => serve(cfg)?,
        Cmd::ExportCa { out } => {
            let p = pki::ensure(&cfg.state_dir, &cfg.tls_names)?;
            match out {
                Some(o) => {
                    std::fs::write(&o, &p.ca_pem)?;
                    eprintln!("CA gravada em {}", o.display());
                }
                None => print!("{}", p.ca_pem),
            }
        }
        Cmd::User(c) => user_cmd(&cfg, &sp, c)?,
        Cmd::Group(c) => group_cmd(&cfg, &sp, c)?,
        Cmd::Machine(c) => machine_cmd(&cfg, &sp, c)?,
        Cmd::Grant(g) => {
            let mut st = Store::load(&sp)?;
            let perms = parse_perms(&g.perms)?;
            let subj = g.who.subject();
            st.grant(&subj, &g.who.machine, perms.clone(), g.ask)?;
            st.save(&sp)?;
            let ps = perms.into_iter().collect::<Vec<_>>().join(",");
            let ask = g.ask.map(|a| a.to_string()).unwrap_or_default();
            audit(&cfg).record(
                "admin_grant",
                &[("subject", &subj), ("machine", &g.who.machine), ("perms", &ps), ("ask", &ask)],
            );
            println!("concedido: {subj} -> {} [{ps}]", g.who.machine);
        }
        Cmd::Revoke(s) => {
            let mut st = Store::load(&sp)?;
            let subj = s.subject();
            let n = st.grants.len();
            st.grants.retain(|g| !(g.subject == subj && g.machine == s.machine));
            if st.grants.len() == n {
                bail!("concessao inexistente");
            }
            st.save(&sp)?;
            audit(&cfg).record("admin_revoke", &[("subject", &subj), ("machine", &s.machine)]);
            println!("revogado: {subj} -> {}", s.machine);
        }
        Cmd::Grants => {
            for g in Store::load(&sp)?.grants {
                let ask = g.ask.map(|a| format!(" ask={a}")).unwrap_or_default();
                println!(
                    "{} -> {} [{}]{ask}",
                    g.subject,
                    g.machine,
                    g.perms.into_iter().collect::<Vec<_>>().join(",")
                );
            }
        }
        Cmd::Audit { limit } => {
            let t = std::fs::read_to_string(cfg.audit_path()).unwrap_or_default();
            let l: Vec<&str> = t.lines().collect();
            for x in &l[l.len().saturating_sub(limit)..] {
                println!("{x}");
            }
        }
    }
    Ok(())
}

fn user_cmd(cfg: &Config, sp: &Path, c: UserCmd) -> Result<()> {
    let mut st = Store::load(sp)?;
    let log = audit(cfg);
    match c {
        UserCmd::Add { name, admin, groups } => {
            name_ok("usuario", &name)?;
            if st.users.contains_key(&name) {
                bail!("usuario ja existe");
            }
            for g in &groups {
                if !st.groups.contains(g) {
                    bail!("grupo inexistente: {g} (crie com: group add {g})");
                }
            }
            let pw = read_password("senha")?;
            check_pw(&pw)?;
            st.users.insert(
                name.clone(),
                User {
                    hash: passhash::hash(&pw).map_err(anyhow::Error::msg)?,
                    groups: groups.into_iter().collect(),
                    disabled: false,
                    admin,
                },
            );
            st.save(sp)?;
            log.record("admin_user_add", &[("user", &name), ("admin", &admin.to_string())]);
            println!("usuario criado: {name}");
        }
        UserCmd::Passwd { name } => {
            let pw = read_password("nova senha")?;
            check_pw(&pw)?;
            let u = st.users.get_mut(&name).context("usuario inexistente")?;
            u.hash = passhash::hash(&pw).map_err(anyhow::Error::msg)?;
            st.save(sp)?;
            log.record("admin_user_passwd", &[("user", &name)]);
            println!("senha trocada: {name}");
        }
        UserCmd::Disable { name } => {
            st.users.get_mut(&name).context("usuario inexistente")?.disabled = true;
            st.save(sp)?;
            log.record("admin_user_disable", &[("user", &name)]);
            println!("usuario desativado: {name}");
        }
        UserCmd::Enable { name } => {
            st.users.get_mut(&name).context("usuario inexistente")?.disabled = false;
            st.save(sp)?;
            log.record("admin_user_enable", &[("user", &name)]);
            println!("usuario reativado: {name}");
        }
        UserCmd::Del { name } => {
            st.users.remove(&name).context("usuario inexistente")?;
            let s = format!("user:{name}");
            st.grants.retain(|g| g.subject != s);
            st.save(sp)?;
            log.record("admin_user_del", &[("user", &name)]);
            println!("usuario removido: {name}");
        }
        UserCmd::List => {
            for (n, u) in &st.users {
                let g: Vec<_> = u.groups.iter().cloned().collect();
                println!(
                    "{n}{}{} grupos=[{}]",
                    if u.admin { " (admin)" } else { "" },
                    if u.disabled { " (desativado)" } else { "" },
                    g.join(",")
                );
            }
        }
    }
    Ok(())
}

fn group_cmd(cfg: &Config, sp: &Path, c: GroupCmd) -> Result<()> {
    let mut st = Store::load(sp)?;
    let log = audit(cfg);
    match c {
        GroupCmd::Add { name } => {
            name_ok("grupo", &name)?;
            if !st.groups.insert(name.clone()) {
                bail!("grupo ja existe");
            }
            st.save(sp)?;
            log.record("admin_group_add", &[("group", &name)]);
            println!("grupo criado: {name}");
        }
        GroupCmd::Del { name } => {
            if !st.groups.remove(&name) {
                bail!("grupo inexistente");
            }
            for u in st.users.values_mut() {
                u.groups.remove(&name);
            }
            let s = format!("group:{name}");
            st.grants.retain(|g| g.subject != s);
            st.save(sp)?;
            log.record("admin_group_del", &[("group", &name)]);
            println!("grupo removido: {name}");
        }
        GroupCmd::List => {
            for g in &st.groups {
                let m: Vec<_> = st
                    .users
                    .iter()
                    .filter(|(_, u)| u.groups.contains(g))
                    .map(|(n, _)| n.as_str())
                    .collect();
                println!("{g}: {}", m.join(","));
            }
        }
        GroupCmd::AddUser { group, user } => {
            if !st.groups.contains(&group) {
                bail!("grupo inexistente");
            }
            st.users
                .get_mut(&user)
                .context("usuario inexistente")?
                .groups
                .insert(group.clone());
            st.save(sp)?;
            log.record("admin_group_add_user", &[("group", &group), ("user", &user)]);
            println!("{user} entrou em {group}");
        }
        GroupCmd::RemoveUser { group, user } => {
            st.users
                .get_mut(&user)
                .context("usuario inexistente")?
                .groups
                .remove(&group);
            st.save(sp)?;
            log.record("admin_group_remove_user", &[("group", &group), ("user", &user)]);
            println!("{user} saiu de {group}");
        }
    }
    Ok(())
}

fn new_secret() -> String {
    token::random_token(32)
}

fn machine_cmd(cfg: &Config, sp: &Path, c: MachineCmd) -> Result<()> {
    let mut st = Store::load(sp)?;
    let log = audit(cfg);
    match c {
        MachineCmd::Add {
            id,
            name,
            address,
            port,
            fingerprint,
        } => {
            name_ok("id de maquina", &id)?;
            if st.machines.contains_key(&id) {
                bail!("maquina ja existe");
            }
            if address.is_empty() || address.len() > 253 || address.contains(char::is_whitespace) {
                bail!("endereco invalido");
            }
            let fingerprint = match fingerprint {
                Some(f) => Some(
                    openvnc_transport::tls::normalize_fingerprint(&f)
                        .map_err(|e| anyhow::anyhow!("fingerprint invalida: {e}"))?,
                ),
                None => None,
            };
            let secret = new_secret();
            st.machines.insert(
                id.clone(),
                store::Machine {
                    name: name.unwrap_or_else(|| id.clone()),
                    address: address.clone(),
                    port,
                    fingerprint,
                    secret_sha256: sha256_hex(secret.as_bytes()),
                },
            );
            st.save(sp)?;
            log.record("admin_machine_add", &[("machine", &id), ("address", &address), ("port", &port.to_string())]);
            println!("maquina cadastrada: {id}");
            println!("segredo (mostrado uma unica vez, guarde em central_secret do servidor):");
            println!("{secret}");
        }
        MachineCmd::Del { id } => {
            st.machines.remove(&id).context("maquina inexistente")?;
            st.grants.retain(|g| g.machine != id);
            st.save(sp)?;
            log.record("admin_machine_del", &[("machine", &id)]);
            println!("maquina removida: {id}");
        }
        MachineCmd::List => {
            for (id, m) in &st.machines {
                println!(
                    "{id}: {} {}:{} {}",
                    m.name,
                    m.address,
                    m.port,
                    m.fingerprint.as_deref().unwrap_or("(sem fingerprint)")
                );
            }
        }
        MachineCmd::ResetSecret { id } => {
            let secret = new_secret();
            st.machines.get_mut(&id).context("maquina inexistente")?.secret_sha256 =
                sha256_hex(secret.as_bytes());
            st.save(sp)?;
            log.record("admin_machine_reset_secret", &[("machine", &id)]);
            println!("novo segredo de {id} (mostrado uma unica vez):");
            println!("{secret}");
        }
    }
    Ok(())
}

fn serve(cfg: Config) -> Result<()> {
    let p = pki::ensure(&cfg.state_dir, &cfg.tls_names)?;
    let ident = openvnc_transport::tls::ServerIdentity::from_pem(
        p.tls_chain_pem.as_bytes(),
        p.tls_key_pem.as_bytes(),
    )?;
    let acceptor = ident.acceptor()?;
    let addr: SocketAddr = cfg.listen.parse().context("listen invalido")?;
    let log = Arc::new(AuditLog::open(&cfg.audit_path())?);
    let max = cfg.max_connections;
    let app = Arc::new(api::App::new(cfg, &p.signing_pkcs8, p.ca_pem, log.clone())?);
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let l = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(
            "servidor central em https://{} (emissor {}, certificado {})",
            l.local_addr()?,
            app.cfg.issuer,
            ident.fingerprint()
        );
        log.record("central_start", &[("listen", &l.local_addr()?.to_string())]);
        let sem = Arc::new(tokio::sync::Semaphore::new(max));
        loop {
            let (tcp, peer) = match l.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("accept: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                drop(tcp);
                continue;
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let fut = async {
                    let mut s = acceptor.accept(tcp).await.ok()?;
                    let resp = match http::read_request(&mut s, peer.ip()).await {
                        Ok(req) => {
                            let app = app.clone();
                            tokio::task::spawn_blocking(move || {
                                let r = app.handle(&req);
                                tracing::debug!("{} {} -> {}", req.method, req.path, r.status);
                                r
                            })
                            .await
                            .ok()?
                        }
                        Err(code) => http::Response::error(code, "requisicao invalida"),
                    };
                    http::write_response(&mut s, &resp).await.ok()
                };
                let _ = tokio::time::timeout(Duration::from_secs(10), fut).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    })
}
