//! Explorador de arquivos em dois paineis (local a esquerda, remoto a
//! direita), no estilo do WinSCP.
//!
//! O painel remoto conversa com o servidor por [`transfer::FsClient`] (a
//! mesma conexao nativa "so arquivos"). As transferencias recursivas rodam
//! numa fila em segundo plano, uma de cada vez, com progresso e
//! cancelamento. No celular aparece um painel so, com seletor
//! local/remoto.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui;
use openvnc_protocol::{FsEntry, FsOp, FsReply};
use tokio::sync::mpsc;

use crate::transfer::{self, FsClient};

/// Tamanho de cada bloco transferido.
const CHUNK: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sort {
    Name,
    Size,
    Date,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    name: String,
    is_dir: bool,
    size: u64,
    modified: u64,
}

impl From<FsEntry> for Entry {
    fn from(e: FsEntry) -> Self {
        Entry {
            name: e.name,
            is_dir: e.is_dir,
            size: e.size,
            modified: e.modified,
        }
    }
}

#[derive(Default)]
struct Pane {
    path: String,
    edit: String,
    entries: Vec<Entry>,
    selected: Option<String>,
    error: String,
    loading: bool,
}

/// Item arrastado entre paineis.
#[derive(Clone)]
struct Drag {
    remote: bool,
    name: String,
}

/// Uma transferencia pedida (arquivo ou pasta).
#[derive(Clone)]
struct Spec {
    up: bool,
    /// Caminho completo da origem.
    src: String,
    /// Pasta de destino.
    dst_dir: String,
    name: String,
    is_dir: bool,
    overwrite: bool,
}

/// Linha da fila.
pub struct Job {
    id: u32,
    up: bool,
    name: String,
    total: u64,
    done: u64,
    state: String,
    finished: bool,
    cancel: Arc<AtomicBool>,
}

/// Estado alterado pelas tarefas em segundo plano.
/// Resultado de uma listagem remota: (caminho, entradas) ou erro.
type Listing = Result<(String, Vec<Entry>), String>;
/// Acao adiada de um dialogo.
type Deferred = Box<dyn FnOnce(&mut Explorer)>;

#[derive(Default)]
struct Async {
    remote_list: Option<(u64, Listing)>,
    roots: Option<Vec<String>>,
    jobs: Vec<Job>,
    refresh_local: bool,
    refresh_remote: bool,
    message: String,
}

enum Dialog {
    Mkdir {
        remote: bool,
        name: String,
    },
    Rename {
        remote: bool,
        old: String,
        name: String,
    },
    Delete {
        remote: bool,
        name: String,
        is_dir: bool,
    },
    Overwrite(Vec<Spec>),
}

enum Act {
    Go(String),
    Up,
    Refresh,
    Open(String),
    Transfer(String),
    Mkdir,
    Rename(String),
    Delete(String),
    Dropped(Drag),
}

/// Explorador de uma aba.
pub struct Explorer {
    fs: FsClient,
    rt: tokio::runtime::Handle,
    ctx: egui::Context,
    local: Pane,
    remote: Pane,
    local_roots: Vec<String>,
    remote_roots: Vec<String>,
    sort: Sort,
    asc: bool,
    st: Arc<Mutex<Async>>,
    queue: mpsc::UnboundedSender<(u32, Spec, Arc<AtomicBool>)>,
    next_job: u32,
    list_seq: u64,
    dialog: Option<Dialog>,
    /// Celular: qual painel aparece.
    show_remote: bool,
}

impl Explorer {
    /// Cria o explorador e a fila de transferencias.
    pub fn new(
        link: &transfer::FileLink,
        rt: &tokio::runtime::Handle,
        ctx: &egui::Context,
    ) -> Self {
        let st = Arc::new(Mutex::new(Async::default()));
        let (queue, rx) = mpsc::unbounded_channel();
        rt.spawn(worker(link.fs(), rx, st.clone(), ctx.clone()));
        let local_roots = local_roots();
        let mut x = Explorer {
            fs: link.fs(),
            rt: rt.clone(),
            ctx: ctx.clone(),
            local: Pane::default(),
            remote: Pane::default(),
            local_roots,
            remote_roots: Vec::new(),
            sort: Sort::Name,
            asc: true,
            st,
            queue,
            next_job: 0,
            list_seq: 0,
            dialog: None,
            show_remote: true,
        };
        let start = x.local_roots.first().cloned().unwrap_or_else(|| "/".into());
        x.local_go(start);
        x.remote_roots_load();
        x
    }

    // ------------------------------------------------------------ painel local

    fn local_go(&mut self, path: String) {
        let p = PathBuf::from(&path);
        match std::fs::read_dir(&p) {
            Ok(rd) => {
                let mut v = Vec::new();
                for e in rd.flatten() {
                    let Some(name) = e.file_name().to_str().map(str::to_string) else {
                        continue;
                    };
                    let md = std::fs::metadata(e.path()).or_else(|_| e.metadata());
                    let (is_dir, size, modified) = match md {
                        Ok(m) => (
                            m.is_dir(),
                            if m.is_dir() { 0 } else { m.len() },
                            m.modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map_or(0, |d| d.as_secs()),
                        ),
                        Err(_) => (false, 0, 0),
                    };
                    v.push(Entry {
                        name,
                        is_dir,
                        size,
                        modified,
                    });
                }
                let shown = p.display().to_string();
                if self.local.path != shown {
                    self.local.selected = None;
                }
                self.local.path = shown.clone();
                self.local.edit = shown;
                self.local.entries = v;
                self.local.error.clear();
            }
            Err(e) => self.local.error = format!("{path}: {e}"),
        }
    }

    fn local_full(&self, name: &str) -> PathBuf {
        Path::new(&self.local.path).join(name)
    }

    // ----------------------------------------------------------- painel remoto

    fn remote_roots_load(&mut self) {
        let fs = self.fs.clone();
        let st = self.st.clone();
        let ctx = self.ctx.clone();
        self.remote.loading = true;
        self.rt.spawn(async move {
            let r = fs.call(FsOp::Roots).await;
            if let Ok(mut s) = st.lock() {
                match r {
                    FsReply::Roots { roots } => s.roots = Some(roots),
                    FsReply::Error { message } => {
                        s.roots = Some(Vec::new());
                        s.message = message;
                    }
                    _ => s.roots = Some(Vec::new()),
                }
            }
            ctx.request_repaint();
        });
    }

    fn remote_go(&mut self, path: String) {
        self.list_seq += 1;
        let seq = self.list_seq;
        let fs = self.fs.clone();
        let st = self.st.clone();
        let ctx = self.ctx.clone();
        self.remote.loading = true;
        self.rt.spawn(async move {
            let r = match fs.call(FsOp::List { path }).await {
                FsReply::Entries { path, entries } => {
                    Ok((path, entries.into_iter().map(Entry::from).collect()))
                }
                FsReply::Error { message } => Err(message),
                _ => Err("resposta inesperada".into()),
            };
            if let Ok(mut s) = st.lock() {
                s.remote_list = Some((seq, r));
            }
            ctx.request_repaint();
        });
    }

    fn remote_op(&mut self, op: FsOp) {
        let fs = self.fs.clone();
        let st = self.st.clone();
        let ctx = self.ctx.clone();
        self.rt.spawn(async move {
            let r = fs.call(op).await;
            if let Ok(mut s) = st.lock() {
                if let FsReply::Error { message } = r {
                    s.message = message;
                }
                s.refresh_remote = true;
            }
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let (list, roots, rl, rr, msg) = {
            let Ok(mut s) = self.st.lock() else { return };
            (
                s.remote_list.take(),
                s.roots.take(),
                std::mem::take(&mut s.refresh_local),
                std::mem::take(&mut s.refresh_remote),
                std::mem::take(&mut s.message),
            )
        };
        if !msg.is_empty() {
            self.remote.error = msg;
        }
        if let Some(roots) = roots {
            self.remote.loading = false;
            self.remote_roots = roots;
            if self.remote.path.is_empty() {
                if let Some(r) = self.remote_roots.first().cloned() {
                    self.remote_go(r);
                }
            }
        }
        if let Some((seq, r)) = list {
            if seq == self.list_seq {
                self.remote.loading = false;
                match r {
                    Ok((path, entries)) => {
                        if self.remote.path != path {
                            self.remote.selected = None;
                        }
                        self.remote.edit = path.clone();
                        self.remote.path = path;
                        self.remote.entries = entries;
                        self.remote.error.clear();
                    }
                    Err(e) => {
                        self.remote.error = e;
                        self.remote.edit = self.remote.path.clone();
                    }
                }
            }
        }
        if rl {
            let p = self.local.path.clone();
            self.local_go(p);
        }
        if rr && !self.remote.path.is_empty() {
            let p = self.remote.path.clone();
            self.remote_go(p);
        }
    }

    // ------------------------------------------------------------ transferencia

    /// Prepara a copia de `name` do painel `from_remote` para o outro lado.
    fn transfer(&mut self, from_remote: bool, name: &str) {
        let (src_pane, dst_pane) = if from_remote {
            (&self.remote, &self.local)
        } else {
            (&self.local, &self.remote)
        };
        let Some(e) = src_pane.entries.iter().find(|e| e.name == name).cloned() else {
            return;
        };
        if dst_pane.path.is_empty() {
            return;
        }
        let spec = Spec {
            up: !from_remote,
            src: if from_remote {
                rjoin(&self.remote.path, name)
            } else {
                self.local_full(name).display().to_string()
            },
            dst_dir: dst_pane.path.clone(),
            name: e.name.clone(),
            is_dir: e.is_dir,
            overwrite: false,
        };
        let exists = if from_remote {
            self.local_full(name).exists()
        } else {
            self.remote.entries.iter().any(|x| x.name == name)
        };
        if exists {
            self.dialog = Some(Dialog::Overwrite(vec![spec]));
        } else {
            self.enqueue(spec);
        }
    }

    fn enqueue(&mut self, spec: Spec) {
        self.next_job += 1;
        let cancel = Arc::new(AtomicBool::new(false));
        if let Ok(mut s) = self.st.lock() {
            s.jobs.push(Job {
                id: self.next_job,
                up: spec.up,
                name: spec.name.clone(),
                total: 0,
                done: 0,
                state: "na fila".into(),
                finished: false,
                cancel: cancel.clone(),
            });
        }
        let _ = self.queue.send((self.next_job, spec, cancel));
    }

    // -------------------------------------------------------------------- UI

    /// Desenha o explorador. `mobile`: um painel por vez.
    pub fn ui(&mut self, ui: &mut egui::Ui, mobile: bool) {
        self.poll();
        let mut acts: Vec<(bool, Act)> = Vec::new();
        if mobile {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.show_remote, false, "Este aparelho");
                ui.selectable_value(&mut self.show_remote, true, "Remoto");
            });
            let remote = self.show_remote;
            let h = (ui.available_height() - 150.0).max(160.0);
            self.pane_ui(ui, remote, h, true, &mut acts);
        } else {
            let h = (ui.available_height() - 150.0).max(200.0);
            ui.columns(2, |cols| {
                cols[0].strong("Este computador");
                self.pane_ui(&mut cols[0], false, h, false, &mut acts);
                cols[1].strong("Computador remoto");
                self.pane_ui(&mut cols[1], true, h, false, &mut acts);
            });
        }
        for (remote, a) in acts {
            self.act(remote, a);
        }
        ui.separator();
        self.queue_ui(ui);
        self.dialog_ui(ui.ctx());
    }

    fn act(&mut self, remote: bool, a: Act) {
        match a {
            Act::Go(p) => {
                if remote {
                    self.remote_go(p)
                } else {
                    self.local_go(p)
                }
            }
            Act::Up => {
                if remote {
                    if let Some(p) = rparent(&self.remote.path) {
                        self.remote_go(p);
                    }
                } else if let Some(p) = Path::new(&self.local.path).parent() {
                    let p = p.display().to_string();
                    self.local_go(p);
                }
            }
            Act::Refresh => {
                if remote {
                    if self.remote.path.is_empty() {
                        self.remote_roots_load();
                    } else {
                        let p = self.remote.path.clone();
                        self.remote_go(p);
                    }
                } else {
                    let p = self.local.path.clone();
                    self.local_go(p);
                }
            }
            Act::Open(name) => {
                if remote {
                    let p = rjoin(&self.remote.path, &name);
                    self.remote_go(p);
                } else {
                    let p = self.local_full(&name).display().to_string();
                    self.local_go(p);
                }
            }
            Act::Transfer(name) => self.transfer(remote, &name),
            Act::Dropped(d) => {
                // soltou no painel oposto ao de origem
                if d.remote != remote {
                    self.transfer(d.remote, &d.name);
                }
            }
            Act::Mkdir => {
                self.dialog = Some(Dialog::Mkdir {
                    remote,
                    name: String::new(),
                })
            }
            Act::Rename(old) => {
                self.dialog = Some(Dialog::Rename {
                    remote,
                    name: old.clone(),
                    old,
                })
            }
            Act::Delete(name) => {
                let p = if remote { &self.remote } else { &self.local };
                let is_dir = p.entries.iter().any(|e| e.name == name && e.is_dir);
                self.dialog = Some(Dialog::Delete {
                    remote,
                    name,
                    is_dir,
                });
            }
        }
    }

    fn pane_ui(
        &mut self,
        ui: &mut egui::Ui,
        remote: bool,
        height: f32,
        mobile: bool,
        acts: &mut Vec<(bool, Act)>,
    ) {
        let roots = if remote {
            self.remote_roots.clone()
        } else {
            self.local_roots.clone()
        };
        let (sort, asc) = (self.sort, self.asc);
        let mut new_sort = None;
        let p = if remote {
            &mut self.remote
        } else {
            &mut self.local
        };
        ui.horizontal(|ui| {
            if ui.button("^").on_hover_text("Subir um nivel").clicked() {
                acts.push((remote, Act::Up));
            }
            if ui.button("Atualizar").clicked() {
                acts.push((remote, Act::Refresh));
            }
            if !roots.is_empty() {
                egui::ComboBox::from_id_salt(("roots", remote))
                    .selected_text("Unidades")
                    .show_ui(ui, |ui| {
                        for r in &roots {
                            if ui.selectable_label(false, r).clicked() {
                                acts.push((remote, Act::Go(r.clone())));
                            }
                        }
                    });
            }
        });
        let r = ui.add(egui::TextEdit::singleline(&mut p.edit).desired_width(f32::INFINITY));
        if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            acts.push((remote, Act::Go(p.edit.trim().to_string())));
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("Nova pasta").clicked() {
                acts.push((remote, Act::Mkdir));
            }
            let sel = p.selected.clone();
            ui.add_enabled_ui(sel.is_some(), |ui| {
                let label = if remote { "Baixar" } else { "Enviar" };
                let label = if mobile {
                    if remote {
                        "Baixar para o aparelho"
                    } else {
                        "Enviar para o remoto"
                    }
                } else {
                    label
                };
                if ui.button(label).clicked() {
                    if let Some(s) = &sel {
                        acts.push((remote, Act::Transfer(s.clone())));
                    }
                }
                if ui.button("Renomear").clicked() {
                    if let Some(s) = &sel {
                        acts.push((remote, Act::Rename(s.clone())));
                    }
                }
                if ui.button("Apagar").clicked() {
                    if let Some(s) = &sel {
                        acts.push((remote, Act::Delete(s.clone())));
                    }
                }
            });
            if p.loading {
                ui.spinner();
            }
        });
        if !p.error.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(220, 90, 90), &p.error);
        }
        let mut entries = p.entries.clone();
        sort_entries(&mut entries, sort, asc);
        let frame = egui::Frame::group(ui.style());
        let w = ui.available_width();
        let inner = frame.show(ui, |ui| {
            // painel nunca passa da coluna (senao invade o painel vizinho)
            ui.set_max_width(w - 8.0);
            ui.set_min_height(height);
            ui.horizontal(|ui| {
                for (s, t) in [
                    (Sort::Name, "Nome"),
                    (Sort::Size, "Tamanho"),
                    (Sort::Date, "Modificado"),
                ] {
                    let mark = if sort == s {
                        if asc {
                            " ^"
                        } else {
                            " v"
                        }
                    } else {
                        ""
                    };
                    if ui
                        .selectable_label(sort == s, format!("{t}{mark}"))
                        .clicked()
                    {
                        new_sort = Some(s);
                    }
                }
            });
            egui::ScrollArea::both()
                .id_salt(("pane", remote))
                .max_height(height)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new(("grid", remote))
                        .striped(true)
                        .num_columns(3)
                        .show(ui, |ui| {
                            for e in &entries {
                                let icon = if e.is_dir { "[D] " } else { "" };
                                let sel = p.selected.as_deref() == Some(e.name.as_str());
                                // clique seleciona, duplo clique abre/transfere e
                                // arrastar leva o item ao outro painel (dnd_drag_source
                                // engolia o clique e impedia a selecao)
                                let r = ui
                                    .selectable_label(sel, format!("{icon}{}", e.name))
                                    .interact(egui::Sense::click_and_drag());
                                r.dnd_set_drag_payload(Drag {
                                    remote,
                                    name: e.name.clone(),
                                });
                                let clicked = r.clicked();
                                let dbl = r.double_clicked();
                                if clicked {
                                    p.selected = Some(e.name.clone());
                                }
                                if dbl {
                                    if e.is_dir {
                                        acts.push((remote, Act::Open(e.name.clone())));
                                    } else {
                                        acts.push((remote, Act::Transfer(e.name.clone())));
                                    }
                                }
                                ui.label(if e.is_dir {
                                    String::new()
                                } else {
                                    transfer::human(e.size)
                                });
                                ui.label(fmt_time(e.modified));
                                ui.end_row();
                            }
                        });
                });
        });
        let zone = ui.interact(
            inner.response.rect,
            egui::Id::new(("drop", remote)),
            egui::Sense::hover(),
        );
        if let Some(d) = zone.dnd_release_payload::<Drag>() {
            acts.push((remote, Act::Dropped((*d).clone())));
        }
        if let Some(s) = new_sort {
            if self.sort == s {
                self.asc = !self.asc;
            } else {
                self.sort = s;
                self.asc = true;
            }
        }
    }

    fn queue_ui(&mut self, ui: &mut egui::Ui) {
        let Ok(mut s) = self.st.lock() else { return };
        ui.horizontal(|ui| {
            ui.strong("Fila de transferencias");
            if s.jobs.iter().any(|j| j.finished) && ui.small_button("Limpar concluidas").clicked() {
                s.jobs.retain(|j| !j.finished);
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("fila")
            .max_height(110.0)
            .show(ui, |ui| {
                if s.jobs.is_empty() {
                    ui.weak("Arraste itens de um painel para o outro, ou use Enviar e Baixar.");
                }
                for j in s.jobs.iter().rev() {
                    ui.horizontal(|ui| {
                        ui.label(if j.up { "Enviar" } else { "Baixar" });
                        ui.label(&j.name);
                        let f = if j.total > 0 {
                            (j.done as f32 / j.total as f32).clamp(0.0, 1.0)
                        } else if j.finished {
                            1.0
                        } else {
                            0.0
                        };
                        ui.add(egui::ProgressBar::new(f).desired_width(140.0).text(format!(
                            "{} / {}",
                            transfer::human(j.done),
                            transfer::human(j.total)
                        )));
                        ui.label(&j.state);
                        if !j.finished && ui.small_button("Cancelar").clicked() {
                            j.cancel.store(true, Ordering::SeqCst);
                        }
                    });
                }
            });
    }

    fn dialog_ui(&mut self, ctx: &egui::Context) {
        let Some(d) = self.dialog.as_mut() else {
            return;
        };
        let mut close = false;
        let mut run: Option<Deferred> = None;
        egui::Window::new("Confirmar")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| match d {
                Dialog::Mkdir { remote, name } => {
                    ui.label("Nome da nova pasta:");
                    ui.text_edit_singleline(name);
                    ui.horizontal(|ui| {
                        if ui.button("Criar").clicked() && valid_name(name) {
                            let (remote, name) = (*remote, name.clone());
                            run = Some(Box::new(move |x: &mut Explorer| {
                                if remote {
                                    let p = rjoin(&x.remote.path, &name);
                                    x.remote_op(FsOp::Mkdir { path: p });
                                } else {
                                    if let Err(e) = std::fs::create_dir(x.local_full(&name)) {
                                        x.local.error = e.to_string();
                                    }
                                    let p = x.local.path.clone();
                                    x.local_go(p);
                                }
                            }));
                        }
                        if ui.button("Cancelar").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Rename { remote, old, name } => {
                    ui.label(format!("Novo nome para {old}:"));
                    ui.text_edit_singleline(name);
                    ui.horizontal(|ui| {
                        if ui.button("Renomear").clicked() && valid_name(name) && name != old {
                            let (remote, old, name) = (*remote, old.clone(), name.clone());
                            run = Some(Box::new(move |x: &mut Explorer| {
                                if remote {
                                    let from = rjoin(&x.remote.path, &old);
                                    let to = rjoin(&x.remote.path, &name);
                                    x.remote_op(FsOp::Rename { from, to });
                                } else {
                                    let to = x.local_full(&name);
                                    if to.exists() {
                                        x.local.error = format!("{name}: ja existe");
                                    } else if let Err(e) = std::fs::rename(x.local_full(&old), to) {
                                        x.local.error = e.to_string();
                                    }
                                    let p = x.local.path.clone();
                                    x.local_go(p);
                                }
                            }));
                        }
                        if ui.button("Cancelar").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Delete {
                    remote,
                    name,
                    is_dir,
                } => {
                    let lado = if *remote {
                        "no computador remoto"
                    } else {
                        "neste computador"
                    };
                    if *is_dir {
                        ui.label(format!(
                            "Apagar a pasta {name} e todo o seu conteudo {lado}?"
                        ));
                    } else {
                        ui.label(format!("Apagar {name} {lado}?"));
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Apagar").clicked() {
                            let (remote, name, is_dir) = (*remote, name.clone(), *is_dir);
                            run = Some(Box::new(move |x: &mut Explorer| {
                                if remote {
                                    let p = rjoin(&x.remote.path, &name);
                                    x.remote_op(FsOp::Delete { path: p });
                                } else {
                                    let p = x.local_full(&name);
                                    // symlink_metadata: apaga o link, nunca o alvo
                                    let link = std::fs::symlink_metadata(&p)
                                        .map(|m| m.file_type().is_symlink())
                                        .unwrap_or(false);
                                    let r = if is_dir && !link {
                                        std::fs::remove_dir_all(&p)
                                    } else {
                                        std::fs::remove_file(&p)
                                            .or_else(|_| std::fs::remove_dir(&p))
                                    };
                                    if let Err(e) = r {
                                        x.local.error = e.to_string();
                                    }
                                    let p = x.local.path.clone();
                                    x.local_go(p);
                                }
                            }));
                        }
                        if ui.button("Cancelar").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Overwrite(specs) => {
                    let names: Vec<_> = specs.iter().map(|s| s.name.as_str()).collect();
                    ui.label(format!(
                        "{} ja existe no destino. Substituir?",
                        names.join(", ")
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Substituir").clicked() {
                            let specs = specs.clone();
                            run = Some(Box::new(move |x: &mut Explorer| {
                                for mut s in specs {
                                    s.overwrite = true;
                                    x.enqueue(s);
                                }
                            }));
                        }
                        if ui.button("Cancelar").clicked() {
                            close = true;
                        }
                    });
                }
            });
        if let Some(f) = run {
            self.dialog = None;
            f(self);
        } else if close {
            self.dialog = None;
        }
    }
}

/// Botao "Bloquear mouse e teclado do computador remoto" (precisa da
/// conexao de arquivos e da permissao de controle no servidor).
pub fn lock_toggle(ui: &mut egui::Ui, link: &transfer::FileLink, short: bool) {
    let (connected, on, msg) = match link.shared.lock() {
        Ok(s) => (s.connected, s.lock_on, s.lock_msg.clone()),
        Err(_) => return,
    };
    let text = if short {
        "Bloquear remoto"
    } else {
        "Bloquear mouse e teclado do computador remoto"
    };
    let mut want = on;
    let r = ui.add_enabled(connected, egui::Checkbox::new(&mut want, text));
    let tip = if msg.is_empty() {
        "Impede o uso local do mouse e do teclado enquanto voce controla. Ctrl+Alt+Del sempre funciona na maquina remota.".to_string()
    } else {
        msg
    };
    let r = r.on_hover_text(tip);
    if r.changed() {
        link.lock(want);
    }
}

/// Mostra o explorador (janela no desktop, tela inteira no celular).
pub fn show(
    ctx: &egui::Context,
    rt: &tokio::runtime::Handle,
    link: &transfer::FileLink,
    slot: &mut Option<Explorer>,
    open: &mut bool,
    mobile: bool,
) {
    if !*open {
        return;
    }
    let x = slot.get_or_insert_with(|| Explorer::new(link, rt, ctx));
    if mobile {
        // cobre a imagem remota inteira (sem disputar o painel central)
        egui::Window::new("Arquivos")
            .id(egui::Id::new("explorador_movel"))
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .fixed_rect(ctx.available_rect())
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Arquivos");
                    if ui.button("Fechar").clicked() {
                        *open = false;
                    }
                });
                x.ui(ui, true);
            });
    } else {
        egui::Window::new("Explorador de arquivos")
            .open(open)
            .default_size([900.0, 560.0])
            .resizable(true)
            .show(ctx, |ui| x.ui(ui, false));
    }
}

fn valid_name(n: &str) -> bool {
    openvnc_protocol::sanitize_file_name(n.trim()).is_ok() && n.trim() == n
}

fn sort_entries(v: &mut [Entry], sort: Sort, asc: bool) {
    v.sort_by(|a, b| {
        // pastas sempre primeiro
        let o = b.is_dir.cmp(&a.is_dir).then_with(|| {
            let k = match sort {
                Sort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                Sort::Size => a.size.cmp(&b.size),
                Sort::Date => a.modified.cmp(&b.modified),
            };
            if asc {
                k
            } else {
                k.reverse()
            }
        });
        o.then_with(|| a.name.cmp(&b.name))
    });
}

/// Unidades locais (Windows) ou `/`, mais a pasta do usuario.
fn local_roots() -> Vec<String> {
    let mut v = Vec::new();
    if let Some(h) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        v.push(PathBuf::from(h).display().to_string());
    }
    if cfg!(windows) {
        for l in b'C'..=b'Z' {
            let d = format!("{}:\\", l as char);
            if Path::new(&d).is_dir() {
                v.push(d);
            }
        }
    } else {
        v.push("/".into());
    }
    v
}

/// Separador usado pelo servidor (deduzido do caminho).
fn rsep(p: &str) -> char {
    if p.contains('\\') || p.as_bytes().get(1) == Some(&b':') {
        '\\'
    } else {
        '/'
    }
}

/// Junta pasta remota e nome.
fn rjoin(dir: &str, name: &str) -> String {
    let s = rsep(dir);
    if dir.ends_with(s) {
        format!("{dir}{name}")
    } else {
        format!("{dir}{s}{name}")
    }
}

/// Pasta pai remota (None na raiz).
fn rparent(p: &str) -> Option<String> {
    let s = rsep(p);
    let t = p.trim_end_matches(s);
    let i = t.rfind(s)?;
    let head = &t[..i];
    if head.is_empty() {
        return Some(s.to_string());
    }
    // "C:" -> "C:\"
    if head.len() == 2 && head.ends_with(':') {
        return Some(format!("{head}{s}"));
    }
    Some(head.to_string())
}

/// Data em UTC, `aaaa-mm-dd hh:mm`.
fn fmt_time(secs: u64) -> String {
    if secs == 0 {
        return String::new();
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // algoritmo civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60
    )
}

// ------------------------------------------------------------------ fila

fn update(st: &Mutex<Async>, ctx: &egui::Context, id: u32, f: impl FnOnce(&mut Job)) {
    if let Ok(mut s) = st.lock() {
        if let Some(j) = s.jobs.iter_mut().find(|j| j.id == id) {
            f(j);
        }
    }
    ctx.request_repaint();
}

async fn worker(
    fs: FsClient,
    mut rx: mpsc::UnboundedReceiver<(u32, Spec, Arc<AtomicBool>)>,
    st: Arc<Mutex<Async>>,
    ctx: egui::Context,
) {
    while let Some((id, spec, cancel)) = rx.recv().await {
        if cancel.load(Ordering::SeqCst) {
            update(&st, &ctx, id, |j| {
                j.finished = true;
                j.state = "cancelado".into();
            });
            continue;
        }
        update(&st, &ctx, id, |j| j.state = "transferindo".into());
        let prog = |add_total: u64, add_done: u64| {
            update(&st, &ctx, id, |j| {
                j.total += add_total;
                j.done += add_done;
            })
        };
        let r = if spec.up {
            upload(&fs, &spec, &cancel, &prog).await
        } else {
            download(&fs, &spec, &cancel, &prog).await
        };
        update(&st, &ctx, id, |j| {
            j.finished = true;
            j.state = match r {
                _ if cancel.load(Ordering::SeqCst) => "cancelado".into(),
                Ok(0) => "concluido".into(),
                Ok(n) => format!("concluido com {n} falha(s)"),
                Err(e) => format!("falhou: {e}"),
            };
        });
        if let Ok(mut s) = st.lock() {
            if spec.up {
                s.refresh_remote = true;
            } else {
                s.refresh_local = true;
            }
        }
        ctx.request_repaint();
    }
}

fn walk_size(p: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(md) = std::fs::symlink_metadata(&d) else {
            continue;
        };
        if md.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&d) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
        } else if md.is_file() {
            total += md.len();
        }
    }
    total
}

/// Envia arquivo ou pasta. Devolve quantos itens falharam (pastas).
async fn upload(
    fs: &FsClient,
    spec: &Spec,
    cancel: &AtomicBool,
    prog: &impl Fn(u64, u64),
) -> Result<usize, String> {
    let src = PathBuf::from(&spec.src);
    prog(walk_size(&src), 0);
    let mut failed = 0;
    let mut first_err = String::new();
    let mut stack = vec![(src, rjoin(&spec.dst_dir, &spec.name))];
    while let Some((local, remote)) = stack.pop() {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelado".into());
        }
        // links locais nao sao seguidos (evita lacos e vazamentos)
        let md = std::fs::symlink_metadata(&local).map_err(|e| e.to_string())?;
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir() {
            let exists = matches!(
                fs.call(FsOp::List {
                    path: remote.clone()
                })
                .await,
                FsReply::Entries { .. }
            );
            if !exists {
                if let FsReply::Error { message } = fs
                    .call(FsOp::Mkdir {
                        path: remote.clone(),
                    })
                    .await
                {
                    if !spec.is_dir
                        || stack.is_empty()
                            && failed == 0
                            && first_err.is_empty()
                            && remote == rjoin(&spec.dst_dir, &spec.name)
                    {
                        return Err(message);
                    }
                    failed += 1;
                    continue;
                }
            }
            let rd = std::fs::read_dir(&local).map_err(|e| e.to_string())?;
            for e in rd.flatten() {
                if let Some(n) = e.file_name().to_str() {
                    stack.push((e.path(), rjoin(&remote, n)));
                }
            }
            continue;
        }
        if let Err(e) = upload_file(fs, &local, &remote, spec.overwrite, cancel, prog).await {
            if !spec.is_dir {
                return Err(e);
            }
            if e == "cancelado" {
                return Err(e);
            }
            failed += 1;
            if first_err.is_empty() {
                first_err = e;
            }
        }
    }
    Ok(failed)
}

async fn upload_file(
    fs: &FsClient,
    local: &Path,
    remote: &str,
    overwrite: bool,
    cancel: &AtomicBool,
    prog: &impl Fn(u64, u64),
) -> Result<(), String> {
    let mut f = std::fs::File::open(local).map_err(|e| format!("{}: {e}", local.display()))?;
    let mut buf = vec![0u8; CHUNK];
    let mut offset = 0u64;
    loop {
        if cancel.load(Ordering::SeqCst) {
            if offset > 0 {
                let _ = fs
                    .call(FsOp::Delete {
                        path: remote.into(),
                    })
                    .await;
            }
            return Err("cancelado".into());
        }
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 && offset > 0 {
            return Ok(());
        }
        let r = fs
            .call(FsOp::Write {
                path: remote.into(),
                offset,
                overwrite,
                data: buf[..n].to_vec(),
            })
            .await;
        if let FsReply::Error { message } = r {
            if offset > 0 {
                let _ = fs
                    .call(FsOp::Delete {
                        path: remote.into(),
                    })
                    .await;
            }
            return Err(message);
        }
        offset += n as u64;
        prog(0, n as u64);
        if n == 0 {
            return Ok(());
        }
    }
}

/// Baixa arquivo ou pasta. Devolve quantos itens falharam (pastas).
async fn download(
    fs: &FsClient,
    spec: &Spec,
    cancel: &AtomicBool,
    prog: &impl Fn(u64, u64),
) -> Result<usize, String> {
    let mut failed = 0;
    let mut stack = vec![(
        spec.src.clone(),
        Path::new(&spec.dst_dir).join(&spec.name),
        spec.is_dir,
        0u64,
    )];
    let mut top = true;
    while let Some((remote, local, is_dir, _size)) = stack.pop() {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelado".into());
        }
        if is_dir {
            if let Err(e) = std::fs::create_dir_all(&local) {
                if top {
                    return Err(e.to_string());
                }
                failed += 1;
                continue;
            }
            match fs
                .call(FsOp::List {
                    path: remote.clone(),
                })
                .await
            {
                FsReply::Entries { entries, .. } => {
                    for e in entries {
                        if !e.is_dir {
                            prog(e.size, 0);
                        }
                        // nomes ja validados pelo protocolo (sem separador nem ..)
                        stack.push((
                            rjoin(&remote, &e.name),
                            local.join(&e.name),
                            e.is_dir,
                            e.size,
                        ));
                    }
                }
                FsReply::Error { message } => {
                    if top {
                        return Err(message);
                    }
                    failed += 1;
                }
                _ => failed += 1,
            }
            top = false;
            continue;
        }
        let r = download_file(fs, &remote, &local, spec.overwrite, cancel, prog, top).await;
        if let Err(e) = r {
            if top || e == "cancelado" {
                return Err(e);
            }
            failed += 1;
        }
        top = false;
    }
    Ok(failed)
}

async fn download_file(
    fs: &FsClient,
    remote: &str,
    local: &Path,
    overwrite: bool,
    cancel: &AtomicBool,
    prog: &impl Fn(u64, u64),
    count_total: bool,
) -> Result<(), String> {
    if local.exists() && !overwrite {
        return Err(format!("{}: ja existe", local.display()));
    }
    if std::fs::symlink_metadata(local).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!("{}: e um link; nao sera seguido", local.display()));
    }
    let mut f = std::fs::File::create(local).map_err(|e| format!("{}: {e}", local.display()))?;
    let mut offset = 0u64;
    let fail = |local: &Path, e: String| {
        let _ = std::fs::remove_file(local);
        Err(e)
    };
    loop {
        if cancel.load(Ordering::SeqCst) {
            drop(f);
            return fail(local, "cancelado".into());
        }
        match fs
            .call(FsOp::Read {
                path: remote.into(),
                offset,
                len: CHUNK as u32,
            })
            .await
        {
            FsReply::Data { data, eof } => {
                if let Err(e) = f.write_all(&data) {
                    drop(f);
                    return fail(local, e.to_string());
                }
                offset += data.len() as u64;
                if count_total {
                    prog(data.len() as u64, data.len() as u64);
                } else {
                    prog(0, data.len() as u64);
                }
                if eof || data.is_empty() {
                    return Ok(());
                }
            }
            FsReply::Error { message } => {
                drop(f);
                return fail(local, message);
            }
            _ => {
                drop(f);
                return fail(local, "resposta inesperada".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caminhos_remotos() {
        assert_eq!(rjoin(r"C:\", "a"), r"C:\a");
        assert_eq!(rjoin(r"C:\x", "a"), r"C:\x\a");
        assert_eq!(rjoin("/", "a"), "/a");
        assert_eq!(rjoin("/home", "a"), "/home/a");
        assert_eq!(rparent(r"C:\x\y").as_deref(), Some(r"C:\x"));
        assert_eq!(rparent(r"C:\x").as_deref(), Some(r"C:\"));
        assert_eq!(rparent(r"C:\"), None);
        assert_eq!(rparent("/home/a").as_deref(), Some("/home"));
        assert_eq!(rparent("/home").as_deref(), Some("/"));
        assert_eq!(rparent("/"), None);
    }

    #[test]
    fn datas_e_ordem() {
        assert_eq!(fmt_time(0), "");
        assert_eq!(fmt_time(1_700_000_000), "2023-11-14 22:13");
        let mut v = vec![
            Entry {
                name: "b".into(),
                is_dir: false,
                size: 1,
                modified: 2,
            },
            Entry {
                name: "A".into(),
                is_dir: false,
                size: 9,
                modified: 1,
            },
            Entry {
                name: "z".into(),
                is_dir: true,
                size: 0,
                modified: 0,
            },
        ];
        sort_entries(&mut v, Sort::Name, true);
        assert_eq!(
            v.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["z", "A", "b"]
        );
        sort_entries(&mut v, Sort::Size, false);
        assert_eq!(v[1].name, "A");
        assert!(valid_name("ok.txt"));
        assert!(!valid_name("../x"));
        assert!(!valid_name(" x"));
    }
}
