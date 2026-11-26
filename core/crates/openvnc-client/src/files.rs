//! Transferencia de arquivos do protocolo nativo (FILE_OFFER, FILE_ACCEPT,
//! FILE_CHUNK, FILE_END), comum ao servidor e ao cliente.
//!
//! Recebimento ([`Inbound`]): cada oferta aceita vira um `.part` na pasta de
//! destino; os blocos precisam chegar em ordem, o total nao passa do
//! anunciado nem do limite, e no FILE_END o SHA-256 e conferido antes de
//! renomear. Qualquer falha apaga o `.part`.
//!
//! Envio ([`stream`]): le o arquivo em blocos de [`CHUNK`] e termina com
//! FILE_END.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use openvnc_protocol::Message;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

/// Tamanho dos blocos enviados.
pub const CHUNK: usize = 64 * 1024;
/// Recebimentos simultaneos por sessao.
const MAX_ACTIVE: usize = 4;

/// Nome seguro para gravar no Windows e no Unix (a sanitizacao do protocolo
/// ja recusou separadores e controles).
pub fn safe_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | '"' | '|' | '?' | '*' | '/' | '\\' | ':' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() {
        s = "arquivo".into();
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        s.insert(0, '_');
    }
    s.chars().take(200).collect()
}

/// Caminho livre em `dir` para `name` (acrescenta " (n)" se preciso).
fn unique(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (1..10_000)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap_or_else(|| dir.join(format!("{stem}-{}{ext}", std::process::id())))
}

struct Incoming {
    file: std::fs::File,
    part: PathBuf,
    dest: PathBuf,
    size: u64,
    written: u64,
    hash: Sha256,
}

/// Arquivo recebido com sucesso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// Onde foi salvo.
    pub path: PathBuf,
    /// Tamanho.
    pub size: u64,
}

/// Estado de recebimento de uma sessao.
pub struct Inbound {
    dir: PathBuf,
    max: u64,
    active: HashMap<u32, Incoming>,
}

impl Inbound {
    /// `max_bytes` e o tamanho maximo por arquivo.
    pub fn new(dir: PathBuf, max_bytes: u64) -> Self {
        Inbound {
            dir,
            max: max_bytes,
            active: HashMap::new(),
        }
    }

    /// Tamanho anunciado de um recebimento em andamento.
    pub fn size_of(&self, id: u32) -> Option<u64> {
        self.active.get(&id).map(|i| i.size)
    }

    /// Decide a oferta. `Err` traz o motivo da recusa.
    pub fn offer(&mut self, id: u32, name: &str, size: u64) -> Result<PathBuf, String> {
        if size > self.max {
            return Err(format!("arquivo maior que o limite ({} bytes)", self.max));
        }
        if self.active.contains_key(&id) {
            return Err("id de transferencia repetido".into());
        }
        if self.active.len() >= MAX_ACTIVE {
            return Err("transferencias demais ao mesmo tempo".into());
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("pasta: {e}"))?;
        let dest = unique(&self.dir, &safe_name(name));
        let part = dest.with_file_name(format!(
            "{}.{id}.part",
            dest.file_name().unwrap_or_default().to_string_lossy()
        ));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .map_err(|e| format!("criar {}: {e}", part.display()))?;
        self.active.insert(
            id,
            Incoming {
                file,
                part,
                dest: dest.clone(),
                size,
                written: 0,
                hash: Sha256::new(),
            },
        );
        Ok(dest)
    }

    /// Grava um bloco. Em erro a transferencia e descartada.
    pub fn chunk(&mut self, id: u32, offset: u64, data: &[u8]) -> Result<(), String> {
        let r = {
            let Some(t) = self.active.get_mut(&id) else {
                return Err("bloco de transferencia desconhecida".into());
            };
            if offset != t.written {
                Err("bloco fora de ordem".to_string())
            } else if t.written + data.len() as u64 > t.size {
                Err("dados alem do tamanho anunciado".to_string())
            } else {
                t.file
                    .write_all(data)
                    .map(|()| {
                        t.written += data.len() as u64;
                        t.hash.update(data);
                    })
                    .map_err(|e| format!("gravar: {e}"))
            }
        };
        if r.is_err() {
            self.abort(id);
        }
        r
    }

    /// Conclui: confere tamanho e SHA-256 e renomeia.
    pub fn end(&mut self, id: u32, sha256: &[u8; 32]) -> Result<Received, String> {
        let Some(mut t) = self.active.remove(&id) else {
            return Err("fim de transferencia desconhecida".into());
        };
        let fail = |t: Incoming, e: String| {
            drop(t.file);
            let _ = std::fs::remove_file(&t.part);
            Err(e)
        };
        if t.written != t.size {
            return fail(t, "arquivo incompleto".into());
        }
        let digest: [u8; 32] = t.hash.clone().finalize().into();
        if &digest != sha256 {
            return fail(t, "SHA-256 nao confere".into());
        }
        if let Err(e) = t.file.flush().and_then(|()| t.file.sync_all()) {
            return fail(t, format!("gravar: {e}"));
        }
        drop(t.file);
        // o destino pode ter sido ocupado durante a transferencia
        let dest = if t.dest.exists() {
            unique(
                t.dest.parent().unwrap_or(&self.dir),
                &t.dest.file_name().unwrap_or_default().to_string_lossy(),
            )
        } else {
            t.dest
        };
        if let Err(e) = std::fs::rename(&t.part, &dest) {
            let _ = std::fs::remove_file(&t.part);
            return Err(format!("renomear: {e}"));
        }
        Ok(Received {
            path: dest,
            size: t.size,
        })
    }

    /// Descarta uma transferencia.
    pub fn abort(&mut self, id: u32) {
        if let Some(t) = self.active.remove(&id) {
            drop(t.file);
            let _ = std::fs::remove_file(&t.part);
        }
    }
}

impl Drop for Inbound {
    fn drop(&mut self) {
        let ids: Vec<u32> = self.active.keys().copied().collect();
        for id in ids {
            self.abort(id);
        }
    }
}

/// Le e envia o arquivo em blocos, terminando com FILE_END.
pub async fn stream(id: u32, path: &Path, tx: &mpsc::Sender<Message>) -> Result<u64, String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut offset = 0u64;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        tx.send(Message::FileChunk {
            id,
            offset,
            data: buf[..n].to_vec(),
        })
        .await
        .map_err(|_| "conexao encerrada".to_string())?;
        offset += n as u64;
    }
    tx.send(Message::FileEnd {
        id,
        sha256: hash.finalize().into(),
    })
    .await
    .map_err(|_| "conexao encerrada".to_string())?;
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("openvnc-files-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn nomes_seguros() {
        assert_eq!(safe_name("a.txt"), "a.txt");
        assert_eq!(safe_name("CON.txt"), "_CON.txt");
        assert_eq!(safe_name("com1"), "_com1");
        assert_eq!(safe_name("x?.txt. "), "x_.txt");
        assert_eq!(safe_name("..."), "arquivo");
    }

    #[test]
    fn recebe_confere_e_renomeia() {
        let d = tmp("ok");
        let mut r = Inbound::new(d.clone(), 1024);
        r.offer(7, "a.txt", 6).unwrap();
        r.chunk(7, 0, b"abc").unwrap();
        r.chunk(7, 3, b"def").unwrap();
        let sha: [u8; 32] = Sha256::digest(b"abcdef").into();
        let got = r.end(7, &sha).unwrap();
        assert_eq!(std::fs::read(&got.path).unwrap(), b"abcdef");
        // segundo arquivo com o mesmo nome nao sobrescreve
        r.offer(8, "a.txt", 0).unwrap();
        let sha0: [u8; 32] = Sha256::digest(b"").into();
        let b = r.end(8, &sha0).unwrap();
        assert_ne!(b.path, got.path);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn recusa_e_limpa() {
        let d = tmp("bad");
        let mut r = Inbound::new(d.clone(), 4);
        assert!(r.offer(1, "big", 5).is_err());
        r.offer(2, "b", 4).unwrap();
        assert!(r.chunk(2, 1, b"x").is_err(), "fora de ordem");
        assert!(r.chunk(2, 0, b"x").is_err(), "ja descartado");
        r.offer(3, "c", 2).unwrap();
        assert!(r.chunk(3, 0, b"xyz").is_err(), "alem do tamanho");
        r.offer(4, "d", 1).unwrap();
        r.chunk(4, 0, b"x").unwrap();
        assert!(r.end(4, &[0; 32]).is_err(), "sha errado");
        let left: Vec<_> = std::fs::read_dir(&d).unwrap().collect();
        assert!(left.is_empty(), "sobrou {left:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
