//! Transferencia de arquivos no servidor nativo.
//!
//! O recebimento usa [`openvnc_client::files::Inbound`]. Para enviar, a
//! bandeja publica o caminho escolhido em um canal global; cada sessao com
//! envio habilitado oferece o arquivo ao seu cliente e, no aceite, transmite
//! em blocos pelo canal de controle.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use openvnc_client::files::stream;
use openvnc_protocol::Message;
use tokio::sync::{broadcast, mpsc};

static SEND_ENABLED: AtomicBool = AtomicBool::new(false);
static OFFERS: OnceLock<broadcast::Sender<PathBuf>> = OnceLock::new();

fn offers() -> &'static broadcast::Sender<PathBuf> {
    OFFERS.get_or_init(|| broadcast::channel(8).0)
}

/// Liga ou desliga o envio de arquivos aos clientes.
pub fn set_sending(on: bool) {
    SEND_ENABLED.store(on, Ordering::Relaxed);
}

/// O envio esta habilitado?
pub fn sending_enabled() -> bool {
    SEND_ENABLED.load(Ordering::Relaxed)
}

/// Oferece `path` a todas as sessoes que aceitam envio. Retorna quantas.
pub fn offer_file(path: PathBuf) -> usize {
    if !sending_enabled() {
        return 0;
    }
    offers().send(path).unwrap_or(0)
}

/// Assina as ofertas da bandeja.
pub fn subscribe() -> broadcast::Receiver<PathBuf> {
    offers().subscribe()
}

/// Estado de envio de uma sessao.
#[derive(Default)]
pub struct Outbound {
    next: u32,
    pending: HashMap<u32, PathBuf>,
}

impl Outbound {
    /// Monta a oferta de `path` (ou `None` se o arquivo nao serve).
    pub fn offer(&mut self, path: PathBuf) -> Option<Message> {
        let meta = std::fs::metadata(&path).ok().filter(|m| m.is_file())?;
        let name = path.file_name()?.to_string_lossy().into_owned();
        let name = openvnc_protocol::sanitize_file_name(&name).ok()?;
        self.next = self.next.wrapping_add(1);
        let id = self.next;
        if self.pending.len() >= 16 {
            return None;
        }
        self.pending.insert(id, path);
        Some(Message::FileOffer {
            id,
            name,
            size: meta.len(),
        })
    }

    /// Resposta do cliente: se aceitou, transmite em segundo plano.
    pub fn answer(&mut self, id: u32, accept: bool, tx: mpsc::Sender<Message>) {
        let Some(path) = self.pending.remove(&id) else {
            return;
        };
        if !accept {
            tracing::info!("cliente recusou {}", path.display());
            return;
        }
        tokio::spawn(async move {
            match stream(id, &path, &tx).await {
                Ok(n) => tracing::info!("enviado {} ({n} bytes)", path.display()),
                Err(e) => tracing::warn!("envio de {} falhou: {e}", path.display()),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvnc_client::files::{Inbound, CHUNK};

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("openvnc-srvfiles-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[tokio::test]
    async fn envia_em_blocos() {
        let d = tmp("send");
        std::fs::create_dir_all(&d).unwrap();
        let src = d.join("s.bin");
        let data: Vec<u8> = (0..(CHUNK * 2 + 10)).map(|i| i as u8).collect();
        std::fs::write(&src, &data).unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let mut out = Outbound::default();
        let Some(Message::FileOffer { id, size, .. }) = out.offer(src.clone()) else {
            panic!("sem oferta");
        };
        assert_eq!(size, data.len() as u64);
        let dst = d.join("in");
        let mut inb = Inbound::new(dst.clone(), u64::MAX);
        inb.offer(id, "s.bin", size).unwrap();
        out.answer(id, true, tx);
        let got = loop {
            match rx.recv().await.unwrap() {
                Message::FileChunk { id, offset, data } => inb.chunk(id, offset, &data).unwrap(),
                Message::FileEnd { id, sha256 } => break inb.end(id, &sha256).unwrap(),
                m => panic!("{m:?}"),
            }
        };
        assert_eq!(std::fs::read(got.path).unwrap(), data);
        let _ = std::fs::remove_dir_all(&d);
    }
}
