//! Transferencia de arquivos do desktop.
//!
//! A tela continua no RFB; os arquivos vao por uma segunda conexao, no
//! protocolo nativo, aberta em modo "so arquivos" (quadros descartados sem
//! confirmacao, entao o servidor para de mandar video). A tarefa de rede roda
//! no runtime tokio e publica o estado num `Mutex` lido pela UI.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui;
use openvnc_client::native::{
    NativeAuth, NativeClient, NativeEvent, NativeOptions, NativeTransport,
};
use openvnc_protocol::{FsOp, FsReply};
use openvnc_transport::tls::ClientTls;
use tokio::sync::{mpsc, oneshot};

/// Tamanho maximo aceito por arquivo recebido.
const MAX_DOWNLOAD: u64 = 16 * 1024 * 1024 * 1024;

/// Sentido da transferencia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Deste computador para o servidor.
    Up,
    /// Do servidor para este computador.
    Down,
}

/// Linha da lista de transferencias.
#[derive(Debug, Clone)]
pub struct Item {
    pub id: u32,
    pub dir: Dir,
    pub name: String,
    pub size: u64,
    pub done: u64,
    /// Texto de estado ("aguardando", "enviado", motivo da falha...).
    pub state: String,
    /// Terminou (com sucesso ou nao)?
    pub finished: bool,
    /// Caminho final de um arquivo recebido.
    pub path: Option<PathBuf>,
}

/// Estado lido pela UI.
#[derive(Debug, Default)]
pub struct Shared {
    pub status: String,
    pub connected: bool,
    pub items: Vec<Item>,
    /// Ofertas do servidor aguardando decisao: (id, nome, tamanho).
    pub offers: Vec<(u32, String, u64)>,
    /// Mouse e teclado do computador remoto bloqueados (confirmado pelo
    /// servidor).
    pub lock_on: bool,
    /// Ultimo motivo informado pelo servidor sobre o bloqueio.
    pub lock_msg: String,
}

enum Cmd {
    Offer(PathBuf),
    Accept(u32),
    Reject(u32),
    Fs(FsOp, oneshot::Sender<FsReply>),
    Lock(bool),
}

/// Acesso ao explorador remoto pela conexao de arquivos (clonavel, usado
/// pelas tarefas de transferencia).
#[derive(Clone)]
pub struct FsClient(mpsc::UnboundedSender<Cmd>);

impl FsClient {
    /// Executa uma operacao e espera a resposta.
    pub async fn call(&self, op: FsOp) -> FsReply {
        let (tx, rx) = oneshot::channel();
        if self.0.send(Cmd::Fs(op, tx)).is_err() {
            return closed();
        }
        rx.await.unwrap_or_else(|_| closed())
    }
}

fn closed() -> FsReply {
    FsReply::Error {
        message: "conexao de arquivos encerrada".into(),
    }
}

/// Conexao de arquivos em segundo plano.
pub struct FileLink {
    tx: mpsc::UnboundedSender<Cmd>,
    pub shared: Arc<Mutex<Shared>>,
    pub download_dir: PathBuf,
}

/// Pasta padrao de recebimento: `Downloads\OpenVNC` do usuario.
pub fn default_download_dir() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join("Downloads").join("OpenVNC")
}

impl FileLink {
    /// Inicia a conexao em `address` (host:porta do protocolo nativo).
    pub fn spawn(
        rt: &tokio::runtime::Handle,
        address: String,
        tls: ClientTls,
        auth: NativeAuth,
        ctx: egui::Context,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Mutex::new(Shared {
            status: format!("conectando a {address}..."),
            ..Default::default()
        }));
        let download_dir = default_download_dir();
        let opts = NativeOptions {
            address,
            tls,
            transport: NativeTransport::Auto,
            auth,
            timeout: Duration::from_secs(45),
        };
        rt.spawn(run(opts, download_dir.clone(), rx, shared.clone(), ctx));
        FileLink {
            tx,
            shared,
            download_dir,
        }
    }

    /// Oferece um arquivo ao servidor.
    pub fn offer(&self, path: PathBuf) {
        let _ = self.tx.send(Cmd::Offer(path));
    }

    /// Aceita uma oferta do servidor.
    pub fn accept(&self, id: u32) {
        let _ = self.tx.send(Cmd::Accept(id));
    }

    /// Recusa uma oferta do servidor.
    pub fn reject(&self, id: u32) {
        let _ = self.tx.send(Cmd::Reject(id));
    }

    /// Cliente do explorador remoto.
    pub fn fs(&self) -> FsClient {
        FsClient(self.tx.clone())
    }

    /// Pede para bloquear (ou liberar) mouse e teclado do computador remoto.
    pub fn lock(&self, on: bool) {
        let _ = self.tx.send(Cmd::Lock(on));
    }
}

fn with(shared: &Mutex<Shared>, ctx: &egui::Context, f: impl FnOnce(&mut Shared)) {
    if let Ok(mut s) = shared.lock() {
        f(&mut s);
    }
    ctx.request_repaint();
}

fn item(s: &mut Shared, dir: Dir, id: u32) -> Option<&mut Item> {
    s.items
        .iter_mut()
        .rev()
        .find(|i| i.dir == dir && i.id == id && !i.finished)
}

async fn run(
    opts: NativeOptions,
    dir: PathBuf,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    shared: Arc<Mutex<Shared>>,
    ctx: egui::Context,
) {
    let mut c = match NativeClient::connect(&opts).await {
        Ok(c) => c,
        Err(e) => {
            with(&shared, &ctx, |s| {
                s.status = format!("arquivos indisponiveis: {e}");
            });
            return;
        }
    };
    c.set_files_only(true);
    c.set_download_dir(dir, MAX_DOWNLOAD);
    with(&shared, &ctx, |s| {
        s.connected = true;
        s.status = format!("pronto ({})", c.transport());
    });
    let sender = c.sender();
    let mut waiting: std::collections::HashMap<u32, oneshot::Sender<FsReply>> =
        std::collections::HashMap::new();
    let mut next_fs = 0u32;
    let mut locked = false;
    // sinal de vida: com o bloqueio ligado o servidor solta tudo apos 10 s
    // sem trafego, entao uma conexao travada nunca prende o usuario remoto
    let mut beat = tokio::time::interval(Duration::from_secs(3));
    let mut nonce = 0u64;
    loop {
        tokio::select! {
            _ = beat.tick(), if locked => {
                nonce += 1;
                let _ = sender.ping(nonce);
            }
            ev = c.next_event() => match ev {
                Ok(NativeEvent::FsResponse { id, reply }) => {
                    if let Some(w) = waiting.remove(&id) {
                        let _ = w.send(reply);
                    }
                }
                Ok(NativeEvent::InputLockState { on, reason }) => {
                    locked = on;
                    with(&shared, &ctx, |s| {
                        s.lock_on = on;
                        s.lock_msg = reason;
                    });
                }
                Ok(ev) => on_event(&shared, &ctx, ev),
                Err(e) => {
                    with(&shared, &ctx, |s| {
                        s.connected = false;
                        s.lock_on = false;
                        s.status = format!("conexao de arquivos encerrada: {e}");
                        s.offers.clear();
                        for i in s.items.iter_mut().filter(|i| !i.finished) {
                            i.finished = true;
                            i.state = "interrompido".into();
                        }
                    });
                    return;
                }
            },
            cmd = rx.recv() => match cmd {
                None => {
                    c.close().await;
                    return;
                }
                Some(Cmd::Offer(path)) => {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    let r = c.offer_file(path);
                    with(&shared, &ctx, |s| match r {
                        Ok(id) => s.items.push(Item {
                            id,
                            dir: Dir::Up,
                            name,
                            size,
                            done: 0,
                            state: "aguardando o servidor".into(),
                            finished: false,
                            path: None,
                        }),
                        Err(e) => s.status = format!("nao foi possivel enviar {name}: {e}"),
                    });
                }
                Some(Cmd::Accept(id)) => {
                    let r = c.accept_file(id);
                    with(&shared, &ctx, |s| {
                        let Some(pos) = s.offers.iter().position(|o| o.0 == id) else {
                            return;
                        };
                        let (_, name, size) = s.offers.remove(pos);
                        s.items.push(Item {
                            id,
                            dir: Dir::Down,
                            name,
                            size,
                            done: 0,
                            finished: r.is_err(),
                            state: match &r {
                                Ok(_) => "recebendo".into(),
                                Err(e) => e.to_string(),
                            },
                            path: None,
                        });
                    });
                }
                Some(Cmd::Fs(op, w)) => {
                    next_fs = next_fs.wrapping_add(1);
                    if sender.fs(next_fs, op).is_ok() {
                        waiting.insert(next_fs, w);
                    } else {
                        let _ = w.send(closed());
                    }
                }
                Some(Cmd::Lock(on)) => {
                    // liga o sinal de vida antes da confirmacao chegar
                    locked = locked || on;
                    let _ = sender.input_lock(on);
                }
                Some(Cmd::Reject(id)) => {
                    let _ = c.reject_file(id);
                    with(&shared, &ctx, |s| s.offers.retain(|o| o.0 != id));
                }
            },
        }
    }
}

fn on_event(shared: &Mutex<Shared>, ctx: &egui::Context, ev: NativeEvent) {
    match ev {
        NativeEvent::FileOffer { id, name, size } => {
            with(shared, ctx, |s| s.offers.push((id, name, size)));
        }
        NativeEvent::FileProgress { id, done, .. } => with(shared, ctx, |s| {
            if let Some(i) = item(s, Dir::Down, id) {
                i.done = done;
            }
        }),
        NativeEvent::FileReceived { id, path, size } => with(shared, ctx, |s| {
            if let Some(i) = item(s, Dir::Down, id) {
                i.done = size;
                i.finished = true;
                i.state = "recebido".into();
                i.name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| i.name.clone());
                i.path = Some(path);
            }
        }),
        NativeEvent::FileAnswer { id, accepted } => with(shared, ctx, |s| {
            if let Some(i) = item(s, Dir::Up, id) {
                if accepted {
                    i.state = "enviando".into();
                } else {
                    i.finished = true;
                    i.state = "recusado pelo servidor".into();
                }
            }
        }),
        NativeEvent::FileSent { id, bytes } => with(shared, ctx, |s| {
            if let Some(i) = item(s, Dir::Up, id) {
                i.done = bytes;
                i.finished = true;
                i.state = "enviado".into();
            }
        }),
        NativeEvent::FileFailed { id, reason } => with(shared, ctx, |s| {
            // o id pode ser de qualquer sentido: marca o que estiver ativo
            let target = s.items.iter_mut().rev().find(|i| i.id == id && !i.finished);
            if let Some(i) = target {
                i.finished = true;
                i.state = format!("falhou: {reason}");
            }
        }),
        _ => {}
    }
}

/// Formata bytes para leitura humana.
pub fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < U.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[u])
    }
}

/// Host e porta do protocolo nativo a partir do endereco RFB `host:porta`.
pub fn native_address(rfb: &str, port: u16) -> String {
    let host = rfb.rsplit_once(':').map_or(rfb, |(h, _)| h);
    format!("{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endereco_nativo() {
        assert_eq!(native_address("pc:5900", 5901), "pc:5901");
        assert_eq!(native_address("[::1]:5900", 5901), "[::1]:5901");
        assert_eq!(human(1536), "1.5 KB");
        assert_eq!(human(10), "10 B");
    }
}
