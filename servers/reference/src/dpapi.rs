//! Senha legada cifrada com DPAPI da maquina (so Windows). Usada apenas
//! quando a compatibilidade com clientes VNC antigos esta ligada.

/// Cifra `plain` com a chave da maquina e devolve em hex.
pub fn protect(plain: &[u8]) -> anyhow::Result<String> {
    imp::crypt(plain, true).map(|b| b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Decifra o hex gerado por [`protect`].
pub fn unprotect(hex: &str) -> anyhow::Result<String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        anyhow::bail!("password_protected invalido");
    }
    let raw = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(String::from_utf8(imp::crypt(&raw, false)?)?)
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub fn crypt(data: &[u8], enc: bool) -> anyhow::Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;
        // SAFETY: blobs validos; a saida e liberada com LocalFree
        unsafe {
            let ok = if enc {
                CryptProtectData(
                    &input,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    flags,
                    &mut out,
                )
            } else {
                CryptUnprotectData(
                    &input,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    flags,
                    &mut out,
                )
            };
            if ok == 0 {
                anyhow::bail!("DPAPI falhou: {}", std::io::Error::last_os_error());
            }
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData as _);
            Ok(v)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn crypt(_: &[u8], _: bool) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("password_protected so e suportado no Windows")
    }
}
