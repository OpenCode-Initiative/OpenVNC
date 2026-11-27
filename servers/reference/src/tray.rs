//! Icone na bandeja do Windows (`--tray`): mostra porta e clientes
//! conectados e oferece atalhos para o cliente, as configuracoes, o envio de
//! arquivos e parar o servidor. Tambem pergunta ao usuario local se aceita
//! uma conexao (`ask_before_accept`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

/// Clientes conectados (atualizado pelos lacos de aceite).
pub static CLIENTS: AtomicUsize = AtomicUsize::new(0);

struct Info {
    port: u16,
    name: String,
    /// Ha senha de administracao: parar exige o app de configuracoes.
    #[cfg_attr(not(windows), allow(dead_code))]
    admin: bool,
}
static INFO: OnceLock<Info> = OnceLock::new();

/// Tempo para o usuario local responder; sem resposta, a conexao e negada.
const ASK_TIMEOUT: Duration = Duration::from_secs(30);

/// Sobe a thread da bandeja.
pub fn spawn(port: u16, name: String, admin: bool) {
    let _ = INFO.set(Info { port, name, admin });
    std::thread::Builder::new()
        .name("tray".into())
        .spawn(|| {
            if let Err(e) = imp::run() {
                tracing::warn!("bandeja indisponivel: {e}");
            }
        })
        .ok();
}

fn tooltip() -> String {
    let (name, port) = INFO
        .get()
        .map(|i| (i.name.as_str(), i.port))
        .unwrap_or(("", 0));
    let c = match CLIENTS.load(Ordering::Relaxed) {
        0 => "nenhum cliente".to_string(),
        1 => "1 cliente conectado".to_string(),
        n => format!("{n} clientes conectados"),
    };
    format!("OpenVNC Server ({name}), porta {port}: {c}")
}

/// Texto de quem pede acesso: `usuario de ip:porta`, ou so o peer quando
/// nao ha usuario nomeado (senha unica ou dispositivo sem nome).
pub fn who_label(user: &str, peer: &str) -> String {
    let u = user.trim();
    if u.is_empty() || u == crate::config::REMOTE_USER {
        peer.to_string()
    } else {
        // limita e remove controles (texto vem do cliente)
        let u: String = u.chars().filter(|c| !c.is_control()).take(64).collect();
        format!("{u} de {peer}")
    }
}

/// Pergunta ao usuario local se aceita a conexao de `peer`. Nega se ninguem
/// responder em 30 s ou se nao houver como perguntar.
pub async fn ask_accept(peer: &str) -> bool {
    let peer = peer.to_string();
    let task = tokio::task::spawn_blocking(move || imp::ask(&peer, ASK_TIMEOUT));
    matches!(task.await, Ok(true))
}

/// Sessoes aprovadas em andamento, por IP e identidade autenticada. O
/// cliente abre duas conexoes (tela RFB e canal nativo de arquivos); com
/// isto o usuario local aprova uma vez so: a segunda conexao do mesmo IP e
/// da mesma identidade aproveita a aprovacao enquanto a primeira estiver
/// aberta. Sessoes sem autenticacao nunca entram aqui nem aproveitam nada.
static APPROVED: std::sync::Mutex<Vec<(std::net::IpAddr, String, usize)>> =
    std::sync::Mutex::new(Vec::new());
/// IPs com pergunta aberta na tela (no maximo uma por IP).
static PENDING: std::sync::Mutex<Vec<std::net::IpAddr>> = std::sync::Mutex::new(Vec::new());
/// Perguntas abertas ao mesmo tempo; acima disso recusa na hora.
const MAX_PENDING: usize = 3;

/// Aprovacao valida enquanto a sessao existir.
pub struct Approval(Option<(std::net::IpAddr, String)>);

impl Drop for Approval {
    fn drop(&mut self) {
        if let (Some((ip, id)), Ok(mut v)) = (self.0.take(), APPROVED.lock()) {
            if let Some(i) = v.iter().position(|(a, u, _)| *a == ip && *u == id) {
                v[i].2 -= 1;
                if v[i].2 == 0 {
                    v.remove(i);
                }
            }
        }
    }
}

fn hold(ip: std::net::IpAddr, id: String) -> Approval {
    if let Ok(mut v) = APPROVED.lock() {
        match v.iter_mut().find(|(a, u, _)| *a == ip && *u == id) {
            Some(e) => e.2 += 1,
            None => v.push((ip, id.clone(), 1)),
        }
    }
    Approval(Some((ip, id)))
}

/// Identidade usada para casar sessoes: usuario sem espacos; senha unica
/// (sem usuario nomeado) vira "".
fn identity(user: &str) -> String {
    let u = user.trim();
    if u == crate::config::REMOTE_USER {
        String::new()
    } else {
        u.to_string()
    }
}

fn approved(ip: std::net::IpAddr, id: &str) -> bool {
    APPROVED
        .lock()
        .map(|v| v.iter().any(|(a, u, n)| *a == ip && u == id && *n > 0))
        .unwrap_or(false)
}

/// Reserva a vaga de pergunta do IP; libera no drop.
struct PendingSlot(std::net::IpAddr);

impl Drop for PendingSlot {
    fn drop(&mut self) {
        if let Ok(mut v) = PENDING.lock() {
            if let Some(i) = v.iter().position(|a| *a == self.0) {
                v.remove(i);
            }
        }
    }
}

enum Reserve {
    Ok(PendingSlot),
    /// Ja ha pergunta aberta para este IP.
    Busy,
    /// Perguntas demais abertas.
    Full,
}

fn reserve(ip: std::net::IpAddr) -> Reserve {
    let Ok(mut v) = PENDING.lock() else {
        return Reserve::Full;
    };
    if v.contains(&ip) {
        return Reserve::Busy;
    }
    if v.len() >= MAX_PENDING {
        return Reserve::Full;
    }
    v.push(ip);
    Reserve::Ok(PendingSlot(ip))
}

/// Texto da pergunta: sempre mostra o endereco e o usuario (ou a falta
/// dele).
fn prompt_label(user: &str, peer: &str, authenticated: bool) -> String {
    let base = who_label(user, peer);
    if !authenticated {
        format!("{base} (SEM autenticacao)")
    } else if identity(user).is_empty() {
        format!("{base} (senha do servidor, sem usuario)")
    } else {
        base
    }
}

/// Como `ask_accept`, mas sem perguntar de novo se ja ha sessao aprovada
/// do mesmo IP e da mesma identidade autenticada. `None` = recusado.
pub async fn ask_once(user: &str, peer: &str, authenticated: bool) -> Option<Approval> {
    let label = prompt_label(user, peer, authenticated);
    let Some(ip) = crate::lockout::peer_ip(peer) else {
        return ask_accept(&label).await.then_some(Approval(None));
    };
    let id = identity(user);
    let deadline = tokio::time::Instant::now() + ASK_TIMEOUT + Duration::from_secs(5);
    let slot = loop {
        if authenticated && approved(ip, &id) {
            return Some(hold(ip, id));
        }
        match reserve(ip) {
            Reserve::Ok(s) => break s,
            Reserve::Full => {
                tracing::warn!(peer, "perguntas pendentes demais; recusado");
                return None;
            }
            // outra conexao do mesmo IP esta perguntando: espera a resposta
            // e so entao decide (aproveita se for a mesma identidade)
            Reserve::Busy => {
                if tokio::time::Instant::now() >= deadline {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    };
    let ok = ask_accept(&label).await;
    drop(slot);
    match (ok, authenticated) {
        (true, true) => Some(hold(ip, id)),
        (true, false) => Some(Approval(None)),
        (false, _) => None,
    }
}

// FFI Win32 (Shell_NotifyIcon, menus, MessageBox e dialogo de arquivo)
#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use super::{tooltip, INFO};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
        NIM_MODIFY, NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    const WM_TRAY: u32 = WM_APP + 1;
    const ID_CLIENT: usize = 1;
    const ID_CONFIG: usize = 2;
    const ID_SEND: usize = 3;
    const ID_EXIT: usize = 4;
    static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
    static ASK_SEQ: AtomicU64 = AtomicU64::new(0);

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// Icone desenhado em codigo (32x32 BGRA): quadrado azul arredondado com
    /// um monitor branco. Criado uma vez e reaproveitado.
    fn tray_icon() -> HICON {
        static ICON: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let cached = ICON.load(Ordering::Relaxed);
        if cached != 0 {
            return cached as HICON;
        }
        const N: usize = 32;
        let mut px = [0u8; N * N * 4];
        let mut mask = [0u8; N * N / 8];
        for y in 0..N {
            for x in 0..N {
                let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
                // quadrado arredondado (raio 7) com borda suavizada
                let r = 7.0;
                let dx = (fx - fx.clamp(r, N as f32 - r)).abs();
                let dy = (fy - fy.clamp(r, N as f32 - r)).abs();
                let d = (dx * dx + dy * dy).sqrt() - r;
                let a = (0.5 - d).clamp(0.0, 1.0);
                // monitor: moldura 6..26 x 7..21, tela interna, pe e base
                let frame = (6..26).contains(&x) && (7..21).contains(&y);
                let inner = (8..24).contains(&x) && (9..19).contains(&y);
                let stand = (14..18).contains(&x) && (21..24).contains(&y);
                let base = (10..22).contains(&x) && (24..26).contains(&y);
                let white = (frame && !inner) || stand || base;
                let (b, g, rr) = if white {
                    (255, 255, 255)
                } else if inner {
                    (0xC8, 0x8E, 0x1F) // azul mais escuro na tela
                } else {
                    (0xEB, 0x6F, 0x2F) // #2F6FEB
                };
                let i = (y * N + x) * 4;
                let al = a;
                px[i] = b;
                px[i + 1] = g;
                px[i + 2] = rr;
                px[i + 3] = (al * 255.0) as u8;
                if al == 0.0 {
                    mask[y * N / 8 + x / 8] |= 0x80 >> (x % 8);
                }
            }
        }
        // icone embutido no .exe (recurso 1, ver build.rs)
        let res = unsafe { LoadIconW(GetModuleHandleW(null()), 1 as _) };
        if !res.is_null() {
            ICON.store(res as usize, Ordering::Relaxed);
            return res;
        }
        let h = unsafe {
            CreateIcon(
                GetModuleHandleW(null()),
                N as i32,
                N as i32,
                1,
                32,
                mask.as_ptr(),
                px.as_ptr(),
            )
        };
        if h.is_null() {
            return unsafe { LoadIconW(null_mut(), IDI_APPLICATION) };
        }
        ICON.store(h as usize, Ordering::Relaxed);
        h
    }

    fn notify(hwnd: HWND, op: u32) {
        unsafe {
            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_TRAY;
            nid.hIcon = tray_icon();
            let tip: Vec<u16> = tooltip().encode_utf16().take(127).collect();
            nid.szTip[..tip.len()].copy_from_slice(&tip);
            Shell_NotifyIconW(op, &nid);
        }
    }

    fn open(file: &std::path::Path, args: &str) {
        let f = w(&file.to_string_lossy());
        let a = w(args);
        let verb = w("open");
        unsafe {
            ShellExecuteW(
                null_mut(),
                verb.as_ptr(),
                f.as_ptr(),
                if args.is_empty() { null() } else { a.as_ptr() },
                null(),
                SW_SHOWNORMAL,
            );
        }
    }

    fn sibling(name: &str) -> Option<std::path::PathBuf> {
        std::env::current_exe().ok().map(|e| e.with_file_name(name))
    }

    /// Dialogo "Abrir" para escolher o arquivo a enviar.
    fn pick_file(hwnd: HWND) -> Option<std::path::PathBuf> {
        let mut buf = vec![0u16; 32 * 1024];
        let title = w("Enviar arquivo aos clientes conectados");
        unsafe {
            let mut ofn: OPENFILENAMEW = std::mem::zeroed();
            ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = buf.as_mut_ptr();
            ofn.nMaxFile = buf.len() as u32;
            ofn.lpstrTitle = title.as_ptr();
            ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if GetOpenFileNameW(&mut ofn) == 0 {
                return None;
            }
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
        Some(String::from_utf16_lossy(&buf[..n]).into())
    }

    fn info(hwnd: HWND, text: &str) {
        let t = w(text);
        let c = w("OpenVNC");
        unsafe {
            MessageBoxW(hwnd, t.as_ptr(), c.as_ptr(), MB_OK | MB_ICONINFORMATION);
        }
    }

    unsafe extern "system" fn proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        match msg {
            WM_TRAY if matches!(lp as u32, WM_RBUTTONUP | WM_LBUTTONUP | WM_CONTEXTMENU) => {
                let menu = CreatePopupMenu();
                let title = w(&tooltip());
                AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, title.as_ptr());
                AppendMenuW(menu, MF_SEPARATOR, 0, null());
                let a = w("Abrir cliente OpenVNC");
                AppendMenuW(menu, MF_STRING, ID_CLIENT, a.as_ptr());
                let b = w("Configuracoes...");
                AppendMenuW(menu, MF_STRING, ID_CONFIG, b.as_ptr());
                let s = w("Enviar arquivo ao cliente...");
                let flags = if crate::files::sending_enabled() {
                    MF_STRING
                } else {
                    MF_STRING | MF_GRAYED
                };
                AppendMenuW(menu, flags, ID_SEND, s.as_ptr());
                AppendMenuW(menu, MF_SEPARATOR, 0, null());
                let c = w("Parar o servidor");
                AppendMenuW(menu, MF_STRING, ID_EXIT, c.as_ptr());
                let mut pt = POINT { x: 0, y: 0 };
                GetCursorPos(&mut pt);
                SetForegroundWindow(hwnd);
                let cmd = TrackPopupMenu(
                    menu,
                    TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                    pt.x,
                    pt.y,
                    0,
                    hwnd,
                    null(),
                ) as usize;
                DestroyMenu(menu);
                match cmd {
                    ID_CLIENT => {
                        if let Some(p) = sibling("openvnc-desktop.exe") {
                            open(&p, "");
                        }
                    }
                    ID_CONFIG => {
                        if let Some(p) = sibling("openvnc-config.exe") {
                            open(&p, "");
                        }
                    }
                    ID_SEND => {
                        if let Some(f) = pick_file(hwnd) {
                            let n = crate::files::offer_file(f);
                            if n == 0 {
                                info(hwnd, "Nenhum cliente conectado recebe arquivos agora.");
                            }
                        }
                    }
                    ID_EXIT => {
                        if INFO.get().is_some_and(|i| i.admin) {
                            // a senha de administracao e conferida pelo app
                            if let Some(p) = sibling("openvnc-config.exe") {
                                open(&p, "--stop");
                            }
                        } else {
                            notify(hwnd, NIM_DELETE);
                            tracing::info!("encerrado pela bandeja");
                            std::process::exit(0);
                        }
                    }
                    _ => {}
                }
                0
            }
            WM_TIMER => {
                notify(hwnd, NIM_MODIFY);
                0
            }
            // Explorer reiniciado: o icone precisa ser recriado
            m if m != 0 && m == TASKBAR_CREATED.load(Ordering::Relaxed) => {
                notify(hwnd, NIM_ADD);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }

    /// Caixa Sim/Nao; um vigia fecha a caixa (negando) apos `timeout`.
    pub fn ask(peer: &str, timeout: Duration) -> bool {
        let seq = ASK_SEQ.fetch_add(1, Ordering::Relaxed);
        let caption = format!("OpenVNC: pedido de conexao #{seq}");
        let text = format!(
            "{peer} quer acessar este computador.\n\nPermitir? (sem resposta em {} s, a conexao e negada)",
            timeout.as_secs()
        );
        let cap_w = w(&caption);
        let watcher = {
            let cap_w = cap_w.clone();
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let h = std::thread::spawn(move || {
                if rx.recv_timeout(timeout).is_err() {
                    unsafe {
                        let wnd = FindWindowW(null(), cap_w.as_ptr());
                        if !wnd.is_null() {
                            // MB_YESNO nao tem Cancelar e ignora WM_CLOSE:
                            // responde "Nao" pelo proprio botao
                            PostMessageW(wnd, WM_COMMAND, IDNO as WPARAM, 0);
                        }
                    }
                }
            });
            (tx, h)
        };
        let t = w(&text);
        let r = unsafe {
            MessageBoxW(
                null_mut(),
                t.as_ptr(),
                cap_w.as_ptr(),
                MB_YESNO
                    | MB_ICONQUESTION
                    | MB_DEFBUTTON2
                    | MB_TOPMOST
                    | MB_SETFOREGROUND
                    | MB_SYSTEMMODAL,
            )
        };
        let _ = watcher.0.send(());
        let _ = watcher.1.join();
        r == IDYES
    }

    pub fn run() -> Result<(), String> {
        unsafe {
            let inst = GetModuleHandleW(null());
            let class = w("OpenVNCServerTray");
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(proc);
            wc.hInstance = inst;
            wc.lpszClassName = class.as_ptr();
            if RegisterClassW(&wc) == 0 {
                return Err("RegisterClassW falhou".into());
            }
            TASKBAR_CREATED.store(
                RegisterWindowMessageW(w("TaskbarCreated").as_ptr()),
                Ordering::Relaxed,
            );
            let hwnd = CreateWindowExW(
                0,
                class.as_ptr(),
                class.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                null_mut(),
                null_mut(),
                inst,
                null(),
            );
            if hwnd.is_null() {
                return Err("CreateWindowExW falhou".into());
            }
            notify(hwnd, NIM_ADD);
            SetTimer(hwnd, 1, 2000, None);
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            Ok(())
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::time::Duration;

    use std::process::{Command, Stdio};
    use std::time::Instant;

    /// Pergunta a quem esta na maquina (macOS: osascript; Linux: zenity ou
    /// kdialog). Sem dialogo disponivel, sem resposta ou no tempo limite,
    /// recusa.
    pub fn ask(peer: &str, timeout: Duration) -> bool {
        // texto vem da rede (usuario e endereco): so letras/digitos ASCII e
        // `.:[]@_-() `; nada de aspas, barra invertida ou `$` (vai para o
        // osascript/zenity)
        let peer: String = peer
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || ".:[]@_-() ".contains(*c))
            .take(128)
            .collect();
        let msg = format!("{peer} quer acessar este computador pelo OpenVNC. Permitir?");
        let secs = timeout.as_secs().max(1);
        let tries: Vec<Vec<String>> = if cfg!(target_os = "macos") {
            vec![vec![
                "osascript".into(),
                "-e".into(),
                format!(
                    "display dialog \"{msg}\" with title \"OpenVNC\" buttons {{\"Recusar\", \"Permitir\"}} default button \"Recusar\" giving up after {secs}"
                ),
            ]]
        } else {
            vec![
                vec![
                    "zenity".into(),
                    "--question".into(),
                    "--title=OpenVNC".into(),
                    format!("--text={msg}"),
                    format!("--timeout={secs}"),
                ],
                vec![
                    "kdialog".into(),
                    "--title".into(),
                    "OpenVNC".into(),
                    "--yesno".into(),
                    msg.clone(),
                ],
            ]
        };
        for t in tries {
            let Ok(mut c) = Command::new(&t[0])
                .args(&t[1..])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            else {
                continue;
            };
            let start = Instant::now();
            loop {
                match c.try_wait() {
                    Ok(Some(st)) => {
                        if !st.success() {
                            return false;
                        }
                        let mut out = String::new();
                        if let Some(mut o) = c.stdout.take() {
                            let _ = std::io::Read::read_to_string(&mut o, &mut out);
                        }
                        // osascript imprime o botao; zenity/kdialog: codigo 0 = sim
                        return !cfg!(target_os = "macos")
                            || (out.contains("Permitir") && !out.contains("gave up:true"));
                    }
                    Ok(None) if start.elapsed() > timeout + Duration::from_secs(2) => {
                        let _ = c.kill();
                        let _ = c.wait();
                        return false;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => return false,
                }
            }
        }
        false
    }

    pub fn run() -> Result<(), String> {
        let _ = super::tooltip;
        Err("so no Windows".into())
    }
}

#[cfg(test)]
mod who_tests {
    use super::who_label;

    #[test]
    fn mostra_usuario_e_origem() {
        assert_eq!(
            who_label("joao.silva", "10.1.2.3:5"),
            "joao.silva de 10.1.2.3:5"
        );
        assert_eq!(who_label("  ", "10.1.2.3:5"), "10.1.2.3:5");
        assert_eq!(who_label(crate::config::REMOTE_USER, "p"), "p");
        assert_eq!(who_label("a\nb", "p"), "ab de p");
        assert_eq!(who_label(&"x".repeat(200), "p").len(), 64 + " de p".len());
    }

    #[test]
    fn rotulo_da_pergunta() {
        assert!(super::prompt_label("", "1.2.3.4:5", false).contains("SEM autenticacao"));
        assert!(super::prompt_label("", "1.2.3.4:5", true).contains("1.2.3.4:5"));
        assert_eq!(
            super::prompt_label("ana", "1.2.3.4:5", true),
            "ana de 1.2.3.4:5"
        );
    }

    #[test]
    fn aprovacao_so_para_mesma_identidade() {
        let ip: std::net::IpAddr = "10.9.8.7".parse().unwrap();
        let a = super::hold(ip, super::identity("ana"));
        assert!(super::approved(ip, "ana"));
        assert!(!super::approved(ip, "bob"));
        assert!(!super::approved(ip, ""));
        assert_eq!(super::identity(crate::config::REMOTE_USER), "");
        drop(a);
        assert!(!super::approved(ip, "ana"));
    }

    #[test]
    fn uma_pergunta_por_ip_e_limite_total() {
        let ips: Vec<std::net::IpAddr> = (1..=4)
            .map(|i| format!("10.77.0.{i}").parse().unwrap())
            .collect();
        let s0 = super::reserve(ips[0]);
        assert!(matches!(s0, super::Reserve::Ok(_)));
        assert!(matches!(super::reserve(ips[0]), super::Reserve::Busy));
        let s1 = super::reserve(ips[1]);
        let s2 = super::reserve(ips[2]);
        assert!(matches!(super::reserve(ips[3]), super::Reserve::Full));
        drop((s0, s1, s2));
        assert!(matches!(super::reserve(ips[3]), super::Reserve::Ok(_)));
    }
}
