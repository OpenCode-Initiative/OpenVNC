//! Autenticacao externa (`auth_command`): delega usuario e senha a um
//! programa da empresa (LDAP/Active Directory, RADIUS, PAM, ponte para SSO).
//!
//! Contrato do programa:
//! - recebe a senha na entrada padrao (sem `\n` no fim) e nunca na linha de
//!   comando, para nao aparecer na lista de processos;
//! - recebe `OPENVNC_USER` e `OPENVNC_PEER` no ambiente;
//! - sai com codigo 0 para aceitar; qualquer outro codigo, falha ao iniciar
//!   ou estouro do tempo limite recusa;
//! - a saida padrao e ignorada; a de erro vai para o log de diagnostico
//!   (nunca para o de auditoria).

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Limite de usuario aceito (evita abuso do ambiente do processo filho).
const MAX_USER: usize = 256;

/// Roda `cmd` e devolve `Ok(())` se aceitou, `Err(motivo)` se nao.
pub fn check(
    cmd: &[String],
    timeout: Duration,
    user: &str,
    peer: &str,
    secret: &[u8],
) -> Result<(), String> {
    let Some((prog, args)) = cmd.split_first() else {
        return Err("auth_command vazio".into());
    };
    if user.is_empty() || user.len() > MAX_USER || user.chars().any(char::is_control) {
        return Err("usuario invalido".into());
    }
    let mut child = Command::new(prog)
        .args(args)
        .env("OPENVNC_USER", user)
        .env("OPENVNC_PEER", peer)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("auth_command nao iniciou: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        // erro de escrita (programa saiu cedo) cai no codigo de saida
        let _ = si.write_all(secret);
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                if let Some(mut e) = child.stderr.take() {
                    let mut s = String::new();
                    let _ = std::io::Read::read_to_string(&mut e, &mut s);
                    if !s.trim().is_empty() {
                        tracing::debug!(user, "auth_command: {}", s.trim());
                    }
                }
                return if st.success() {
                    Ok(())
                } else {
                    Err(format!("recusado pelo auth_command ({st})"))
                };
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("auth_command excedeu o tempo limite".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("auth_command: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd".into(), "/C".into(), script.into()]
        } else {
            vec!["sh".into(), "-c".into(), script.into()]
        }
    }

    #[test]
    fn aceita_e_recusa_pelo_codigo_de_saida() {
        let t = Duration::from_secs(10);
        assert!(check(&sh("exit 0"), t, "ana", "1.2.3.4", b"x").is_ok());
        assert!(check(&sh("exit 1"), t, "ana", "1.2.3.4", b"x").is_err());
    }

    #[test]
    fn usuario_invalido_nem_chama() {
        let t = Duration::from_secs(10);
        assert!(check(&sh("exit 0"), t, "", "p", b"x").is_err());
        assert!(check(&sh("exit 0"), t, "a\nb", "p", b"x").is_err());
    }

    #[test]
    fn programa_inexistente_recusa() {
        let cmd = vec!["openvnc-programa-que-nao-existe".to_string()];
        assert!(check(&cmd, Duration::from_secs(5), "ana", "p", b"x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn senha_vai_pelo_stdin() {
        let cmd = sh(r#"read -r p; [ "$OPENVNC_USER" = ana ] && [ "$p" = segredo ]"#);
        let t = Duration::from_secs(10);
        assert!(check(&cmd, t, "ana", "p", b"segredo\n").is_ok());
        assert!(check(&cmd, t, "ana", "p", b"outra\n").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn tempo_limite() {
        let r = check(&sh("sleep 5"), Duration::from_millis(200), "ana", "p", b"x");
        assert!(r.unwrap_err().contains("tempo"));
    }
}
