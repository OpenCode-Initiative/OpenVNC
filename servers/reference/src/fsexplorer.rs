//! Explorador de arquivos remoto (FS_REQUEST/FS_RESPONSE).
//!
//! Cada pedido traz um caminho absoluto escolhido pelo cliente, entao todo
//! caminho e tratado como hostil:
//!
//! - precisa ser absoluto, sem `..`, sem NUL e sem caminho de rede (UNC);
//! - e canonicalizado (resolve links simbolicos e juncoes) antes do uso;
//! - com `files_root`, o caminho canonico precisa ficar dentro da raiz
//!   canonica (um link que aponte para fora e recusado);
//! - criacoes (mkdir, upload, destino de rename) canonicalizam o **pai** e
//!   validam o nome final; destinos que ja sao links nao sao seguidos;
//! - apagar nunca segue links: remove o proprio link.
//! - sem `files_root`, a raiz padrao e a pasta do usuario (USERPROFILE/HOME),
//!   nunca o disco todo;
//! - escrita/apagar e sempre negada em pastas do sistema (ProgramData\OpenVNC,
//!   Program Files, Windows, pasta de instalacao), mesmo que a raiz as inclua.
//!
//! Permissoes: listar e baixar exigem `files_send`; enviar, criar pasta,
//! renomear e apagar exigem `files_receive`. Ambos so valem se a sessao
//! tem a permissao `files`.

use openvnc_protocol::{FsEntry, FsOp, FsReply, MAX_FILE_CHUNK, MAX_FS_ENTRIES};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

/// Estado do explorador numa sessao.
pub struct Explorer {
    /// Raiz canonica (None = disco todo; so acontece sem pasta do usuario).
    root: Option<PathBuf>,
    /// Pastas canonicas onde escrita/apagar sao sempre negados.
    protected: Vec<PathBuf>,
    read_ok: bool,
    write_ok: bool,
    /// Tamanho maximo de arquivo enviado pelo cliente.
    max_file: u64,
}

type Res<T> = Result<T, String>;

impl Explorer {
    /// Cria a partir da configuracao. `allowed` = capability negociada e
    /// permissao `files` da sessao.
    pub fn new(cfg: &crate::Config, allowed: bool) -> Self {
        Explorer::with(
            cfg.files_root.as_deref(),
            allowed && cfg.files_send,
            allowed && cfg.files_receive,
            cfg.files_max_mb.saturating_mul(1024 * 1024),
        )
    }

    /// Construtor explicito (testes).
    pub fn with(root: Option<&Path>, read_ok: bool, write_ok: bool, max_file: u64) -> Self {
        Explorer::with_protected(root, read_ok, write_ok, max_file, protected_dirs())
    }

    /// Construtor com lista explicita de pastas protegidas (testes).
    pub fn with_protected(
        root: Option<&Path>,
        read_ok: bool,
        write_ok: bool,
        max_file: u64,
        protected: Vec<PathBuf>,
    ) -> Self {
        // sem raiz configurada, usa a pasta do usuario em vez do disco todo
        let home = if root.is_none() { home_dir() } else { None };
        let root = root.or(home.as_deref());
        // raiz invalida (inexistente) desliga o explorador: nunca cai para
        // o disco todo por engano
        let (root, ok) = match root {
            Some(r) => match fs::canonicalize(r) {
                Ok(c) if c.is_dir() => (Some(c), true),
                _ => (None, false),
            },
            None => (None, true),
        };
        let protected = protected
            .into_iter()
            .filter_map(|p| fs::canonicalize(p).ok())
            .collect();
        Explorer {
            root,
            protected,
            read_ok: read_ok && ok,
            write_ok: write_ok && ok,
            max_file,
        }
    }

    /// Algum acesso habilitado.
    #[cfg(test)]
    pub fn enabled(&self) -> bool {
        self.read_ok || self.write_ok
    }

    /// Executa uma operacao.
    pub fn handle(&self, op: &FsOp) -> FsReply {
        let r = match op {
            FsOp::Roots => self.need_read().map(|_| FsReply::Roots {
                roots: self.roots(),
            }),
            FsOp::List { path } => self.need_read().and_then(|_| self.list(path)),
            FsOp::Read { path, offset, len } => self
                .need_read()
                .and_then(|_| self.read(path, *offset, *len)),
            FsOp::Mkdir { path } => self.need_write().and_then(|_| self.mkdir(path)),
            FsOp::Rename { from, to } => self.need_write().and_then(|_| self.rename(from, to)),
            FsOp::Delete { path } => self.need_write().and_then(|_| self.delete(path)),
            FsOp::Write {
                path,
                offset,
                overwrite,
                data,
            } => self
                .need_write()
                .and_then(|_| self.write(path, *offset, *overwrite, data)),
        };
        r.unwrap_or_else(|message| FsReply::Error { message })
    }

    fn need_read(&self) -> Res<()> {
        if self.read_ok {
            Ok(())
        } else {
            Err("o servidor nao permite listar ou baixar arquivos".into())
        }
    }

    fn need_write(&self) -> Res<()> {
        if self.write_ok {
            Ok(())
        } else {
            Err("o servidor nao permite enviar ou alterar arquivos".into())
        }
    }

    fn roots(&self) -> Vec<String> {
        if let Some(r) = &self.root {
            return vec![display(r)];
        }
        let mut out = Vec::new();
        if let Some(h) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
            if let Ok(c) = fs::canonicalize(h) {
                out.push(display(&c));
            }
        }
        #[cfg(windows)]
        for l in b'C'..=b'Z' {
            let d = format!("{}:\\", l as char);
            if Path::new(&d).is_dir() {
                out.push(d);
            }
        }
        #[cfg(not(windows))]
        out.push("/".into());
        out
    }

    /// Caminho existente, canonico e dentro da raiz.
    pub fn resolve_existing(&self, raw: &str) -> Res<PathBuf> {
        let p = check_syntax(raw)?;
        let c = fs::canonicalize(&p).map_err(|e| format!("{raw}: {e}"))?;
        self.confine(&c)?;
        Ok(c)
    }

    /// Caminho a criar: pai canonico dentro da raiz + nome valido. O alvo
    /// pode ou nao existir; se existir e for link, e devolvido sem seguir.
    pub fn resolve_new(&self, raw: &str) -> Res<PathBuf> {
        let p = check_syntax(raw)?;
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{raw}: sem nome de arquivo"))?;
        openvnc_protocol::sanitize_file_name(name).map_err(|_| format!("nome invalido: {name}"))?;
        let parent = p.parent().ok_or_else(|| format!("{raw}: sem pasta"))?;
        let cp = fs::canonicalize(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        self.confine(&cp)?;
        if !cp.is_dir() {
            return Err(format!("{}: nao e uma pasta", parent.display()));
        }
        Ok(cp.join(name))
    }

    fn confine(&self, canonical: &Path) -> Res<()> {
        match &self.root {
            Some(r) if !canonical.starts_with(r) => {
                Err("caminho fora da pasta permitida pelo servidor".into())
            }
            _ => Ok(()),
        }
    }

    /// Nega escrita/apagar em pastas do sistema, qualquer que seja a raiz.
    fn writable(&self, canonical: &Path) -> Res<()> {
        if self.protected.iter().any(|b| path_under(canonical, b)) {
            return Err("pasta protegida pelo servidor: escrita negada".into());
        }
        Ok(())
    }

    fn is_root(&self, p: &Path) -> bool {
        self.root.as_deref() == Some(p) || p.parent().is_none()
    }

    fn list(&self, raw: &str) -> Res<FsReply> {
        let dir = self.resolve_existing(raw)?;
        if !dir.is_dir() {
            return Err(format!("{raw}: nao e uma pasta"));
        }
        let mut entries = Vec::new();
        for e in fs::read_dir(&dir).map_err(|e| format!("{raw}: {e}"))? {
            let Ok(e) = e else { continue };
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue; // nome nao UTF-8: nao representavel no protocolo
            };
            if name.len() > 1024 || name.chars().any(char::is_control) {
                continue;
            }
            // segue links para saber o tipo; link quebrado aparece como arquivo
            let md = fs::metadata(e.path()).or_else(|_| e.metadata());
            let (is_dir, size, modified) = match md {
                Ok(m) => (m.is_dir(), if m.is_dir() { 0 } else { m.len() }, mtime(&m)),
                Err(_) => (false, 0, 0),
            };
            entries.push(FsEntry {
                name,
                is_dir,
                size,
                modified,
            });
            if entries.len() >= MAX_FS_ENTRIES {
                break;
            }
        }
        Ok(FsReply::Entries {
            path: display(&dir),
            entries,
        })
    }

    fn read(&self, raw: &str, offset: u64, len: u32) -> Res<FsReply> {
        let p = self.resolve_existing(raw)?;
        let mut f = fs::File::open(&p).map_err(|e| format!("{raw}: {e}"))?;
        let md = f.metadata().map_err(|e| e.to_string())?;
        if !md.is_file() {
            return Err(format!("{raw}: nao e um arquivo"));
        }
        let n = (len as usize).min(MAX_FILE_CHUNK);
        f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        let mut data = vec![0u8; n];
        let mut got = 0;
        while got < n {
            match f.read(&mut data[got..]) {
                Ok(0) => break,
                Ok(k) => got += k,
                Err(e) => return Err(e.to_string()),
            }
        }
        data.truncate(got);
        let eof = offset.saturating_add(got as u64) >= md.len();
        Ok(FsReply::Data { data, eof })
    }

    fn mkdir(&self, raw: &str) -> Res<FsReply> {
        let p = self.resolve_new(raw)?;
        self.writable(&p)?;
        fs::create_dir(&p).map_err(|e| format!("{raw}: {e}"))?;
        Ok(FsReply::Ok)
    }

    fn rename(&self, from: &str, to: &str) -> Res<FsReply> {
        // a origem nao e seguida: renomear um link renomeia o link
        let src = self.resolve_new(from)?;
        self.writable(&src)?;
        if fs::symlink_metadata(&src).is_err() {
            return Err(format!("{from}: nao existe"));
        }
        if self.is_root(&src) {
            return Err("nao e permitido renomear a raiz".into());
        }
        let dst = self.resolve_new(to)?;
        self.writable(&dst)?;
        if fs::symlink_metadata(&dst).is_ok() {
            return Err(format!("{to}: ja existe"));
        }
        // mover uma pasta para dentro dela mesma
        if dst.starts_with(&src) {
            return Err("destino dentro da origem".into());
        }
        fs::rename(&src, &dst).map_err(|e| format!("{from}: {e}"))?;
        Ok(FsReply::Ok)
    }

    fn delete(&self, raw: &str) -> Res<FsReply> {
        let p = self.resolve_new(raw)?;
        self.writable(&p)?;
        if self.is_root(&p) {
            return Err("nao e permitido apagar a raiz".into());
        }
        let md = fs::symlink_metadata(&p).map_err(|e| format!("{raw}: {e}"))?;
        let r = if md.file_type().is_symlink() {
            // remove so o link; no Windows link de pasta sai com remove_dir
            fs::remove_file(&p).or_else(|_| fs::remove_dir(&p))
        } else if md.is_dir() {
            // remove_dir_all nao segue links dentro da arvore
            fs::remove_dir_all(&p)
        } else {
            fs::remove_file(&p)
        };
        r.map_err(|e| format!("{raw}: {e}"))?;
        Ok(FsReply::Ok)
    }

    fn write(&self, raw: &str, offset: u64, overwrite: bool, data: &[u8]) -> Res<FsReply> {
        let end = offset.saturating_add(data.len() as u64);
        if end > self.max_file {
            return Err(format!(
                "arquivo maior que o limite do servidor ({} MiB)",
                self.max_file / (1024 * 1024)
            ));
        }
        let p = self.resolve_new(raw)?;
        self.writable(&p)?;
        if let Ok(m) = fs::symlink_metadata(&p) {
            if m.file_type().is_symlink() {
                return Err(format!("{raw}: e um link; nao sera seguido"));
            }
            if m.is_dir() {
                return Err(format!("{raw}: e uma pasta"));
            }
        }
        let mut f = if offset == 0 {
            let mut o = fs::OpenOptions::new();
            o.write(true);
            if overwrite {
                o.create(true).truncate(true);
            } else {
                o.create_new(true);
            }
            o.open(&p).map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => format!("{raw}: ja existe"),
                _ => format!("{raw}: {e}"),
            })?
        } else {
            let f = fs::OpenOptions::new()
                .write(true)
                .open(&p)
                .map_err(|e| format!("{raw}: {e}"))?;
            let len = f.metadata().map_err(|e| e.to_string())?.len();
            if len != offset {
                return Err(format!("{raw}: bloco fora de ordem"));
            }
            f
        };
        f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        f.write_all(data).map_err(|e| format!("{raw}: {e}"))?;
        Ok(FsReply::Ok)
    }
}

/// Pasta do usuario canonica (USERPROFILE no Windows, HOME nos demais).
fn home_dir() -> Option<PathBuf> {
    let h = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    fs::canonicalize(h).ok().filter(|c| c.is_dir())
}

/// Pastas do sistema onde o explorador nunca escreve.
fn protected_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(pd) = std::env::var_os("ProgramData") {
        v.push(PathBuf::from(pd).join("OpenVNC"));
    }
    for k in [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "WINDIR",
        "SystemRoot",
    ] {
        if let Some(d) = std::env::var_os(k) {
            v.push(PathBuf::from(d));
        }
    }
    // pasta de instalacao (onde esta o executavel)
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        v.push(dir);
    }
    v
}

/// `p` esta dentro de `base` (ambos canonicos). No Windows a comparacao
/// ignora maiusculas/minusculas.
fn path_under(p: &Path, base: &Path) -> bool {
    #[cfg(windows)]
    {
        let mut pc = p.components();
        for b in base.components() {
            match pc.next() {
                Some(c)
                    if c.as_os_str().to_string_lossy().to_lowercase()
                        == b.as_os_str().to_string_lossy().to_lowercase() => {}
                _ => return false,
            }
        }
        true
    }
    #[cfg(not(windows))]
    {
        p.starts_with(base)
    }
}

/// Validacao sintatica: absoluto, sem `..`, sem NUL, sem UNC.
pub fn check_syntax(raw: &str) -> Res<PathBuf> {
    if raw.is_empty() || raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err("caminho invalido".into());
    }
    let p = PathBuf::from(raw);
    if !p.is_absolute() {
        return Err(format!("{raw}: caminho precisa ser absoluto"));
    }
    for c in p.components() {
        match c {
            Component::ParentDir => return Err(format!("{raw}: '..' nao e permitido")),
            Component::Prefix(px) => {
                use std::path::Prefix::*;
                match px.kind() {
                    Disk(_) | VerbatimDisk(_) => {}
                    _ => return Err(format!("{raw}: caminho de rede ou de dispositivo")),
                }
            }
            _ => {}
        }
    }
    Ok(p)
}

/// Caminho para exibir (sem o prefixo `\\?\` do Windows).
pub fn display(p: &Path) -> String {
    let s = p.display().to_string();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => rest.to_string(),
        _ => s,
    }
}

fn mtime(m: &fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Registra na auditoria. Leituras e escritas so no primeiro bloco (inicio
/// de cada download/upload); falhas sempre.
pub fn audit(
    audit: &openvnc_security::audit::AuditLog,
    peer: &str,
    user: &str,
    op: &FsOp,
    reply: &FsReply,
) {
    let (event, path, extra): (&str, &str, String) = match op {
        FsOp::Roots => return,
        FsOp::List { path } => ("fs_list", path, String::new()),
        FsOp::Read { path, offset, .. } => {
            if *offset != 0 && !matches!(reply, FsReply::Error { .. }) {
                return;
            }
            ("fs_download", path, String::new())
        }
        FsOp::Write {
            path,
            offset,
            overwrite,
            ..
        } => {
            if *offset != 0 && !matches!(reply, FsReply::Error { .. }) {
                return;
            }
            ("fs_upload", path, format!("overwrite={overwrite}"))
        }
        FsOp::Mkdir { path } => ("fs_mkdir", path, String::new()),
        FsOp::Rename { from, to } => ("fs_rename", from, format!("to={to}")),
        FsOp::Delete { path } => ("fs_delete", path, String::new()),
    };
    let result = match reply {
        FsReply::Error { message } => message.as_str(),
        _ => "ok",
    };
    audit.record(
        event,
        &[
            ("peer", peer),
            ("user", user),
            ("path", path),
            ("extra", &extra),
            ("result", result),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(p: &Path) -> String {
        p.display().to_string()
    }

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let out = t.path().join("fora");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(root.join("a.txt"), b"conteudo").unwrap();
        fs::write(out.join("segredo.txt"), b"x").unwrap();
        (t, root, out)
    }

    fn err(r: FsReply) -> String {
        match r {
            FsReply::Error { message } => message,
            o => panic!("esperava erro, veio {o:?}"),
        }
    }

    #[test]
    fn sintaxe() {
        assert!(check_syntax("").is_err());
        assert!(check_syntax("relativo/x").is_err());
        assert!(check_syntax("a\0b").is_err());
        #[cfg(windows)]
        {
            assert!(check_syntax(r"C:\a\..\b").is_err());
            assert!(check_syntax(r"\\servidor\share\x").is_err());
            assert!(check_syntax(r"\\.\PhysicalDrive0").is_err());
            assert!(check_syntax(r"C:relativo").is_err());
            assert!(check_syntax(r"C:\ok\x").is_ok());
        }
        #[cfg(not(windows))]
        {
            assert!(check_syntax("/a/../b").is_err());
            assert!(check_syntax("/ok/x").is_ok());
        }
    }

    #[test]
    fn confinado_na_raiz() {
        let (_t, root, out) = setup();
        let x = Explorer::with(Some(&root), true, true, 1 << 20);
        // dentro
        assert!(matches!(
            x.handle(&FsOp::List { path: s(&root) }),
            FsReply::Entries { .. }
        ));
        // fora (absoluto)
        err(x.handle(&FsOp::List { path: s(&out) }));
        err(x.handle(&FsOp::Read {
            path: s(&out.join("segredo.txt")),
            offset: 0,
            len: 10,
        }));
        // travessia
        let trav = format!(
            "{}{}..{}fora",
            s(&root),
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR
        );
        err(x.handle(&FsOp::List { path: trav }));
        // criar fora
        err(x.handle(&FsOp::Mkdir {
            path: s(&out.join("nova")),
        }));
        err(x.handle(&FsOp::Write {
            path: s(&out.join("w.txt")),
            offset: 0,
            overwrite: true,
            data: b"x".to_vec(),
        }));
        // mover para fora
        err(x.handle(&FsOp::Rename {
            from: s(&root.join("a.txt")),
            to: s(&out.join("a.txt")),
        }));
        // apagar a raiz
        err(x.handle(&FsOp::Delete { path: s(&root) }));
        assert!(root.exists() && out.join("segredo.txt").exists());
        // raizes = so a raiz configurada
        match x.handle(&FsOp::Roots) {
            FsReply::Roots { roots } => {
                assert_eq!(roots, vec![display(&fs::canonicalize(&root).unwrap())])
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn raiz_inexistente_desliga() {
        let x = Explorer::with(Some(Path::new("/nao/existe/openvnc")), true, true, 1);
        assert!(!x.enabled());
    }

    #[test]
    fn operacoes_basicas() {
        let (_t, root, _out) = setup();
        let x = Explorer::with(Some(&root), true, true, 1 << 20);
        let f = root.join("sub").join("novo.bin");
        assert_eq!(
            x.handle(&FsOp::Write {
                path: s(&f),
                offset: 0,
                overwrite: false,
                data: b"abc".to_vec()
            }),
            FsReply::Ok
        );
        assert_eq!(
            x.handle(&FsOp::Write {
                path: s(&f),
                offset: 3,
                overwrite: false,
                data: b"def".to_vec()
            }),
            FsReply::Ok
        );
        // fora de ordem e sem sobrescrever
        err(x.handle(&FsOp::Write {
            path: s(&f),
            offset: 99,
            overwrite: false,
            data: b"z".to_vec(),
        }));
        assert!(err(x.handle(&FsOp::Write {
            path: s(&f),
            offset: 0,
            overwrite: false,
            data: b"z".to_vec(),
        }))
        .contains("ja existe"));
        assert_eq!(fs::read(&f).unwrap(), b"abcdef");
        match x.handle(&FsOp::Read {
            path: s(&f),
            offset: 2,
            len: 100,
        }) {
            FsReply::Data { data, eof } => {
                assert_eq!(data, b"cdef");
                assert!(eof);
            }
            o => panic!("{o:?}"),
        }
        assert_eq!(
            x.handle(&FsOp::Mkdir {
                path: s(&root.join("p"))
            }),
            FsReply::Ok
        );
        assert_eq!(
            x.handle(&FsOp::Rename {
                from: s(&f),
                to: s(&root.join("p").join("r.bin"))
            }),
            FsReply::Ok
        );
        // pasta para dentro dela mesma
        err(x.handle(&FsOp::Rename {
            from: s(&root.join("p")),
            to: s(&root.join("p").join("q")),
        }));
        match x.handle(&FsOp::List {
            path: s(&root.join("p")),
        }) {
            FsReply::Entries { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "r.bin");
                assert_eq!(entries[0].size, 6);
            }
            o => panic!("{o:?}"),
        }
        assert_eq!(
            x.handle(&FsOp::Delete {
                path: s(&root.join("p"))
            }),
            FsReply::Ok
        );
        assert!(!root.join("p").exists());
        // limite de tamanho
        let small = Explorer::with(Some(&root), true, true, 4);
        err(small.handle(&FsOp::Write {
            path: s(&root.join("g.bin")),
            offset: 0,
            overwrite: true,
            data: vec![0; 5],
        }));
    }

    #[test]
    fn permissoes() {
        let (_t, root, _out) = setup();
        let ro = Explorer::with(Some(&root), true, false, 1 << 20);
        assert!(matches!(
            ro.handle(&FsOp::List { path: s(&root) }),
            FsReply::Entries { .. }
        ));
        err(ro.handle(&FsOp::Delete {
            path: s(&root.join("a.txt")),
        }));
        err(ro.handle(&FsOp::Mkdir {
            path: s(&root.join("m")),
        }));
        let wo = Explorer::with(Some(&root), false, true, 1 << 20);
        err(wo.handle(&FsOp::List { path: s(&root) }));
        err(wo.handle(&FsOp::Read {
            path: s(&root.join("a.txt")),
            offset: 0,
            len: 1,
        }));
        let none = Explorer::with(None, false, false, 1);
        assert!(!none.enabled());
        err(none.handle(&FsOp::Roots));
        assert!(root.join("a.txt").exists());
    }

    /// Links simbolicos (no Windows exigem privilegio ou modo desenvolvedor;
    /// sem eles o teste so confere o que der).
    #[test]
    fn link_para_fora_e_recusado() {
        let (_t, root, out) = setup();
        let link = root.join("atalho");
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_dir(&out, &link).is_ok();
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&out, &link).is_ok();
        if !made {
            eprintln!("sem permissao para criar links; teste parcial");
            return;
        }
        let x = Explorer::with(Some(&root), true, true, 1 << 20);
        err(x.handle(&FsOp::List { path: s(&link) }));
        err(x.handle(&FsOp::Read {
            path: s(&link.join("segredo.txt")),
            offset: 0,
            len: 1,
        }));
        err(x.handle(&FsOp::Write {
            path: s(&link.join("w.txt")),
            offset: 0,
            overwrite: true,
            data: b"x".to_vec(),
        }));
        err(x.handle(&FsOp::Write {
            path: s(&link),
            offset: 0,
            overwrite: true,
            data: b"x".to_vec(),
        }));
        // apagar o link remove so o link
        assert_eq!(x.handle(&FsOp::Delete { path: s(&link) }), FsReply::Ok);
        assert!(out.join("segredo.txt").exists());
        assert!(fs::symlink_metadata(&link).is_err());
    }

    #[test]
    fn pasta_protegida_nega_escrita() {
        let (_t, root, _out) = setup();
        let prot = root.join("sub");
        let x = Explorer::with_protected(Some(&root), true, true, 1 << 20, vec![prot.clone()]);
        // leitura continua permitida
        assert!(matches!(
            x.handle(&FsOp::List { path: s(&prot) }),
            FsReply::Entries { .. }
        ));
        err(x.handle(&FsOp::Write {
            path: s(&prot.join("x.bin")),
            offset: 0,
            overwrite: true,
            data: b"x".to_vec(),
        }));
        err(x.handle(&FsOp::Mkdir {
            path: s(&prot.join("d")),
        }));
        err(x.handle(&FsOp::Delete { path: s(&prot) }));
        err(x.handle(&FsOp::Rename {
            from: s(&root.join("a.txt")),
            to: s(&prot.join("a.txt")),
        }));
        assert!(root.join("a.txt").exists());
        assert!(!prot.join("x.bin").exists());
        // fora da pasta protegida segue normal
        assert_eq!(
            x.handle(&FsOp::Mkdir {
                path: s(&root.join("livre"))
            }),
            FsReply::Ok
        );
    }

    #[cfg(windows)]
    #[test]
    fn pasta_protegida_ignora_caixa() {
        let (_t, root, _out) = setup();
        let up = PathBuf::from(s(&root.join("sub")).to_uppercase());
        let x = Explorer::with_protected(Some(&root), true, true, 1 << 20, vec![up]);
        err(x.handle(&FsOp::Mkdir {
            path: s(&root.join("sub").join("d")),
        }));
        assert!(path_under(
            Path::new(r"C:\Windows\System32"),
            Path::new(r"c:\windows")
        ));
        assert!(!path_under(
            Path::new(r"C:\Windows2"),
            Path::new(r"C:\Windows")
        ));
    }

    #[test]
    fn sem_raiz_usa_pasta_do_usuario() {
        let x = Explorer::with(None, true, false, 1);
        if let Some(h) = home_dir() {
            assert_eq!(x.root.as_deref(), Some(h.as_path()));
            assert_eq!(x.roots(), vec![display(&h)]);
        }
    }
}
