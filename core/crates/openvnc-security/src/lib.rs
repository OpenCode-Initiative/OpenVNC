//! Autenticacao RFB.
//!
//! **VNC Authentication (tipo 2) e insegura**: DES com chave de 56 bits
//! derivada de no maximo 8 caracteres e trafego sem criptografia. Existe
//! apenas por compatibilidade e a UI deve sinalizar isso ao usuario.

use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use zeroize::{Zeroize, Zeroizing};

/// Versao do crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Senha mantida em memoria e zerada ao ser descartada. Nunca e logada.
#[derive(Clone, Default)]
pub struct Password(Zeroizing<String>);

impl Password {
    /// Cria a partir de uma string.
    pub fn new(s: impl Into<String>) -> Self {
        Password(Zeroizing::new(s.into()))
    }
    /// Acesso ao conteudo.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(***)")
    }
}

/// Resposta ao desafio de 16 bytes da VNC Authentication.
///
/// A chave e a senha (truncada/preenchida com zeros ate 8 bytes) com os
/// bits de cada byte invertidos, conforme implementacoes historicas.
pub fn vnc_auth_response(password: &Password, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (k, b) in key.iter_mut().zip(password.expose().bytes()) {
        *k = b.reverse_bits();
    }
    let cipher = Des::new(&key.into());
    key.zeroize();
    let mut out = *challenge;
    for block in out.chunks_exact_mut(8) {
        cipher.encrypt_block(block.into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des_known_vector() {
        // Vetor classico FIPS: chave 0123456789ABCDEF, "Now is t" -> 3FA40E8A984D4815.
        // A senha e escolhida para que reverse_bits produza essa chave.
        let key = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let bytes: Vec<u8> = key.iter().map(|b| b.reverse_bits()).collect();
        assert_eq!(bytes, [0x80, 0xC4, 0xA2, 0xE6, 0x91, 0xD5, 0xB3, 0xF7]);
        let cipher = Des::new(&key.into());
        let mut block = *b"Now is t";
        cipher.encrypt_block((&mut block).into());
        assert_eq!(block, [0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15]);
    }

    #[test]
    fn response_is_deterministic_and_password_sensitive() {
        let ch = [7u8; 16];
        let a = vnc_auth_response(&Password::new("secret"), &ch);
        assert_eq!(a, vnc_auth_response(&Password::new("secret"), &ch));
        assert_ne!(a, vnc_auth_response(&Password::new("secreT"), &ch));
        // apenas 8 primeiros caracteres contam
        assert_eq!(
            vnc_auth_response(&Password::new("12345678"), &ch),
            vnc_auth_response(&Password::new("123456789"), &ch)
        );
        assert!(!format!("{:?}", Password::new("x")).contains('x'));
    }
}
