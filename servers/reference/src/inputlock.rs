//! Bloqueio do mouse e teclado locais durante o acesso remoto.
//!
//! No Windows usa ganchos de baixo nivel (WH_KEYBOARD_LL e WH_MOUSE_LL) que
//! descartam eventos fisicos e deixam passar so os injetados (os do proprio
//! OpenVNC via SendInput). Nao usa BlockInput, que bloquearia a injecao.
//! Ctrl+Alt+Del (Secure Attention Sequence) nunca e bloqueado pelo sistema,
//! entao o usuario local sempre consegue recuperar a maquina.
//!
//! A liberacao e garantida por [`Hold`]: ao ser descartado (fim da sessao,
//! queda da conexao, panico ou saida do processo pelo caminho normal) o
//! contador cai e, chegando a zero, os ganchos saem. Se o processo morrer,
//! o sistema remove os ganchos junto com a thread.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Sem trafego do cliente por este tempo, o bloqueio e liberado.
pub const IDLE_RELEASE: Duration = Duration::from_secs(10);

/// Implementacao do bloqueio (trocavel nos testes).
pub trait LockBackend: Send {
    /// Liga o bloqueio.
    fn engage(&mut self) -> Result<(), String>;
    /// Desliga o bloqueio (idempotente).
    fn release(&mut self);
}

struct State {
    backend: Box<dyn LockBackend>,
    holders: usize,
}

/// Contagem de sessoes que pediram o bloqueio.
pub struct Manager {
    st: Mutex<State>,
}

impl Manager {
    /// Cria com um backend.
    pub fn new(backend: Box<dyn LockBackend>) -> Arc<Self> {
        Arc::new(Manager {
            st: Mutex::new(State {
                backend,
                holders: 0,
            }),
        })
    }

    /// Pede o bloqueio; liberado quando o `Hold` cair.
    pub fn acquire(this: &Arc<Self>) -> Result<Hold, String> {
        let mut st = this.st.lock().unwrap_or_else(|e| e.into_inner());
        if st.holders == 0 {
            st.backend.engage()?;
        }
        st.holders += 1;
        Ok(Hold { m: this.clone() })
    }

    /// Quantas sessoes seguram o bloqueio.
    #[cfg(test)]
    pub fn holders(&self) -> usize {
        self.st.lock().unwrap_or_else(|e| e.into_inner()).holders
    }
}

/// Posse do bloqueio por uma sessao.
pub struct Hold {
    m: Arc<Manager>,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut st = self.m.st.lock().unwrap_or_else(|e| e.into_inner());
        st.holders = st.holders.saturating_sub(1);
        if st.holders == 0 {
            st.backend.release();
        }
    }
}

/// Gerenciador global com o backend da plataforma.
pub fn global() -> &'static Arc<Manager> {
    static G: OnceLock<Arc<Manager>> = OnceLock::new();
    G.get_or_init(|| Manager::new(platform()))
}

/// Prazo da liberacao por inatividade.
pub fn idle_deadline(last_seen: Instant) -> Instant {
    last_seen + IDLE_RELEASE
}

/// Inatividade expirou.
#[cfg(test)]
pub fn idle_expired(last_seen: Instant, now: Instant) -> bool {
    now >= idle_deadline(last_seen)
}

#[cfg(not(windows))]
fn platform() -> Box<dyn LockBackend> {
    struct Unsupported;
    impl LockBackend for Unsupported {
        fn engage(&mut self) -> Result<(), String> {
            Err("nao suportado neste sistema".into())
        }
        fn release(&mut self) {}
    }
    Box::new(Unsupported)
}

#[cfg(windows)]
fn platform() -> Box<dyn LockBackend> {
    Box::new(win::Hooks::default())
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod win {
    use super::LockBackend;
    use std::sync::mpsc;
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    #[derive(Default)]
    pub struct Hooks {
        th: Option<(isize, std::thread::JoinHandle<()>)>,
    }

    unsafe extern "system" fn kb(code: i32, w: WPARAM, l: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 {
            let k = &*(l as *const KBDLLHOOKSTRUCT);
            if k.flags & LLKHF_INJECTED == 0 {
                return 1;
            }
        }
        CallNextHookEx(std::ptr::null_mut(), code, w, l)
    }

    unsafe extern "system" fn ms(code: i32, w: WPARAM, l: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 {
            let m = &*(l as *const MSLLHOOKSTRUCT);
            if m.flags & LLMHF_INJECTED == 0 {
                return 1;
            }
        }
        CallNextHookEx(std::ptr::null_mut(), code, w, l)
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    impl LockBackend for Hooks {
        fn engage(&mut self) -> Result<(), String> {
            if self.th.is_some() {
                return Ok(());
            }
            let (tx, rx) = mpsc::channel::<Result<isize, String>>();
            let th = std::thread::spawn(move || unsafe {
                let hk = SetWindowsHookExW(WH_KEYBOARD_LL, Some(kb), std::ptr::null_mut(), 0);
                let hm = SetWindowsHookExW(WH_MOUSE_LL, Some(ms), std::ptr::null_mut(), 0);
                if hk.is_null() || hm.is_null() {
                    if !hk.is_null() {
                        UnhookWindowsHookEx(hk);
                    }
                    if !hm.is_null() {
                        UnhookWindowsHookEx(hm);
                    }
                    let _ = tx.send(Err("falha ao instalar os ganchos de entrada".into()));
                    return;
                }
                // aviso na tela da maquina remota
                let cls = wide("STATIC");
                let txt = wide(
                    "  Mouse e teclado bloqueados pelo acesso remoto (OpenVNC).  \
                     Ctrl+Alt+Del sempre funciona.",
                );
                let hwnd: HWND = CreateWindowExW(
                    WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                    cls.as_ptr(),
                    txt.as_ptr(),
                    WS_POPUP | WS_VISIBLE | WS_BORDER | 0x0001 | 0x0200, /* SS_CENTER | SS_CENTERIMAGE */
                    20,
                    20,
                    640,
                    40,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                );
                let _ = tx.send(Ok(hwnd as isize));
                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                    if msg.message == WM_APP {
                        break;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                UnhookWindowsHookEx(hk);
                UnhookWindowsHookEx(hm);
                if !hwnd.is_null() {
                    DestroyWindow(hwnd);
                }
            });
            match rx.recv() {
                Ok(Ok(h)) => {
                    self.th = Some((h, th));
                    Ok(())
                }
                Ok(Err(e)) => {
                    let _ = th.join();
                    Err(e)
                }
                Err(_) => Err("thread de bloqueio terminou".into()),
            }
        }

        fn release(&mut self) {
            if let Some((h, th)) = self.th.take() {
                let tid = unsafe { GetWindowThreadProcessId(h as HWND, std::ptr::null_mut()) };
                // sem janela, o id vem 0: usa o id da thread pelo handle
                let tid = if tid != 0 {
                    tid
                } else {
                    use std::os::windows::io::AsRawHandle;
                    unsafe { thread_id(th.as_raw_handle()) }
                };
                unsafe {
                    PostThreadMessageW(tid, WM_APP, 0, 0);
                }
                let _ = th.join();
            }
        }
    }

    impl Drop for Hooks {
        fn drop(&mut self) {
            self.release();
        }
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetThreadId(h: *mut core::ffi::c_void) -> u32;
    }

    unsafe fn thread_id(h: *mut core::ffi::c_void) -> u32 {
        GetThreadId(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Count {
        on: AtomicUsize,
        off: AtomicUsize,
    }

    struct Mock(Arc<Count>, bool);

    impl LockBackend for Mock {
        fn engage(&mut self) -> Result<(), String> {
            if self.1 {
                return Err("falhou".into());
            }
            self.0.on.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn release(&mut self) {
            self.0.off.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn libera_ao_descartar() {
        let c = Arc::new(Count::default());
        let m = Manager::new(Box::new(Mock(c.clone(), false)));
        let a = Manager::acquire(&m).unwrap();
        let b = Manager::acquire(&m).unwrap();
        assert_eq!(c.on.load(Ordering::SeqCst), 1);
        assert_eq!(m.holders(), 2);
        drop(a);
        assert_eq!(c.off.load(Ordering::SeqCst), 0);
        drop(b);
        assert_eq!(c.off.load(Ordering::SeqCst), 1);
        assert_eq!(m.holders(), 0);
    }

    #[test]
    fn libera_em_panico() {
        let c = Arc::new(Count::default());
        let m = Manager::new(Box::new(Mock(c.clone(), false)));
        let m2 = m.clone();
        let r = std::thread::spawn(move || {
            let _h = Manager::acquire(&m2).unwrap();
            panic!("sessao caiu");
        })
        .join();
        assert!(r.is_err());
        assert_eq!(c.off.load(Ordering::SeqCst), 1);
        assert_eq!(m.holders(), 0);
    }

    #[test]
    fn falha_nao_conta() {
        let c = Arc::new(Count::default());
        let m = Manager::new(Box::new(Mock(c, true)));
        assert!(Manager::acquire(&m).is_err());
        assert_eq!(m.holders(), 0);
    }

    #[test]
    fn inatividade() {
        let t = Instant::now();
        assert!(!idle_expired(t, t + Duration::from_secs(9)));
        assert!(idle_expired(t, t + IDLE_RELEASE));
        // simula o laco da sessao: sem trafego, o bloqueio cai no prazo
        let c = Arc::new(Count::default());
        let m = Manager::new(Box::new(Mock(c.clone(), false)));
        let mut hold = Some(Manager::acquire(&m).unwrap());
        let now = t + Duration::from_secs(11);
        if idle_expired(t, now) {
            hold.take();
        }
        assert!(hold.is_none());
        assert_eq!(c.off.load(Ordering::SeqCst), 1);
    }
}
