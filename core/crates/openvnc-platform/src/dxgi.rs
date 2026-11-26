//! Captura Windows por DXGI Desktop Duplication (monitor primario).
//!
//! A GPU compoe o quadro; copiamos para uma textura de staging e lemos
//! so quando o DWM apresentou algo novo. Sem mudanca na tela,
//! `AcquireNextFrame` expira e o framebuffer fica como estava.
//!
//! Limites: um monitor (o primeiro do adaptador padrao), sem rotacao.
//! Em sessoes sem GPU (servico, alguns RDP) a criacao falha e o
//! chamador cai para GDI.
#![allow(unsafe_code)]

use openvnc_core::{Error, Result};
use openvnc_framebuffer::Framebuffer;
use windows::core::Interface;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::{
    IDXGIDevice, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource, DXGI_ERROR_ACCESS_LOST,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
};

use crate::ScreenCapture;

fn err(what: &str, e: windows::core::Error) -> Error {
    Error::Unsupported(format!("DXGI {what}: {e}"))
}

/// Captura por Desktop Duplication.
pub struct DxgiCapture {
    device: ID3D11Device,
    ctx: ID3D11DeviceContext,
    output: IDXGIOutput1,
    dup: IDXGIOutputDuplication,
    staging: Option<ID3D11Texture2D>,
    w: u16,
    h: u16,
    have_frame: bool,
    row: Vec<[u8; 4]>,
}

// SAFETY: o device D3D11 e free-threaded; o contexto imediato e a
// duplicacao so sao usados por quem tem `&mut self`, uma thread por vez.
unsafe impl Send for DxgiCapture {}

fn output_size(o: &IDXGIOutput1) -> Result<(u16, u16)> {
    // SAFETY: GetDesc so escreve na struct devolvida.
    let d = unsafe { o.GetDesc() }.map_err(|e| err("GetDesc", e))?;
    let r = d.DesktopCoordinates;
    let (w, h) = (r.right - r.left, r.bottom - r.top);
    match (u16::try_from(w), u16::try_from(h)) {
        (Ok(w), Ok(h)) if w > 0 && h > 0 => Ok((w, h)),
        _ => Err(Error::Unsupported(format!(
            "DXGI: tamanho invalido {w}x{h}"
        ))),
    }
}

impl DxgiCapture {
    /// Abre a duplicacao do monitor primario.
    pub fn new() -> Result<Self> {
        let mut device = None;
        let mut ctx = None;
        // SAFETY: ponteiros de saida validos; o resto sao valores simples.
        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut ctx),
            )
        }
        .map_err(|e| err("D3D11CreateDevice", e))?;
        let device: ID3D11Device =
            device.ok_or_else(|| Error::Unsupported("DXGI: sem device".into()))?;
        let ctx = ctx.ok_or_else(|| Error::Unsupported("DXGI: sem contexto".into()))?;
        let dxgi: IDXGIDevice = device.cast().map_err(|e| err("IDXGIDevice", e))?;
        // SAFETY: chamadas COM em interfaces validas.
        let output: IDXGIOutput1 = unsafe {
            let adapter = dxgi.GetAdapter().map_err(|e| err("GetAdapter", e))?;
            adapter
                .EnumOutputs(0)
                .map_err(|e| err("EnumOutputs", e))?
                .cast()
                .map_err(|e| err("IDXGIOutput1", e))?
        };
        let (w, h) = output_size(&output)?;
        // SAFETY: device e output validos.
        let dup =
            unsafe { output.DuplicateOutput(&device) }.map_err(|e| err("DuplicateOutput", e))?;
        Ok(DxgiCapture {
            device,
            ctx,
            output,
            dup,
            staging: None,
            w,
            h,
            have_frame: false,
            row: vec![[0; 4]; usize::from(w)],
        })
    }

    fn reopen(&mut self) -> Result<()> {
        // SAFETY: device e output validos.
        self.dup = unsafe { self.output.DuplicateOutput(&self.device) }
            .map_err(|e| err("DuplicateOutput", e))?;
        self.have_frame = false;
        Ok(())
    }

    fn staging_for(&mut self, src: &ID3D11Texture2D) -> Result<ID3D11Texture2D> {
        if let Some(s) = &self.staging {
            return Ok(s.clone());
        }
        let mut d = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: GetDesc so escreve em `d`.
        unsafe { src.GetDesc(&mut d) };
        d.Usage = D3D11_USAGE_STAGING;
        d.BindFlags = 0;
        d.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
        d.MiscFlags = 0;
        d.MipLevels = 1;
        d.ArraySize = 1;
        let mut t = None;
        // SAFETY: descricao valida, ponteiro de saida valido.
        unsafe { self.device.CreateTexture2D(&d, None, Some(&mut t)) }
            .map_err(|e| err("CreateTexture2D", e))?;
        let t = t.ok_or_else(|| Error::Unsupported("DXGI: sem textura".into()))?;
        self.staging = Some(t.clone());
        Ok(t)
    }
}

impl ScreenCapture for DxgiCapture {
    fn size(&self) -> (u16, u16) {
        (self.w, self.h)
    }

    fn capture(&mut self, fb: &mut Framebuffer) -> Result<bool> {
        let size = output_size(&self.output)?;
        if size != (self.w, self.h) {
            (self.w, self.h) = size;
            self.staging = None;
            self.row = vec![[0; 4]; usize::from(self.w)];
            self.reopen()?;
            return Ok(false);
        }
        if (fb.width(), fb.height()) != (self.w, self.h) {
            return Ok(false);
        }
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut res: Option<IDXGIResource> = None;
        // ate 100 ms; o laco do servidor ja controla o ritmo
        let timeout = if self.have_frame { 100 } else { 500 };
        // SAFETY: ponteiros de saida validos.
        match unsafe { self.dup.AcquireNextFrame(timeout, &mut info, &mut res) } {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(true),
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                // troca de modo, UAC, tela de bloqueio
                self.reopen()?;
                return Ok(true);
            }
            Err(e) => return Err(err("AcquireNextFrame", e)),
        }
        let out = (|| -> Result<()> {
            // so o cursor mexeu: imagem igual
            if info.LastPresentTime == 0 && self.have_frame {
                return Ok(());
            }
            let tex: ID3D11Texture2D = res
                .as_ref()
                .ok_or_else(|| Error::Unsupported("DXGI: quadro vazio".into()))?
                .cast()
                .map_err(|e| err("textura", e))?;
            let st = self.staging_for(&tex)?;
            let mut m = D3D11_MAPPED_SUBRESOURCE::default();
            // SAFETY: texturas do mesmo tamanho/formato; o Map e desfeito
            // abaixo; leitura restrita a `RowPitch * h` bytes mapeados.
            unsafe {
                self.ctx.CopyResource(&st, &tex);
                self.ctx
                    .Map(&st, 0, D3D11_MAP_READ, 0, Some(&mut m))
                    .map_err(|e| err("Map", e))?;
                let pitch = m.RowPitch as usize;
                let w = usize::from(self.w);
                let data =
                    std::slice::from_raw_parts(m.pData as *const u8, pitch * usize::from(self.h));
                for y in 0..self.h {
                    let src = &data[usize::from(y) * pitch..][..w * 4];
                    for (p, s) in self.row.iter_mut().zip(src.chunks_exact(4)) {
                        *p = [s[2], s[1], s[0], 255]; // BGRA
                    }
                    fb.put_rgba_row(0, y, &self.row);
                }
                self.ctx.Unmap(&st, 0);
            }
            self.have_frame = true;
            Ok(())
        })();
        // SAFETY: quadro adquirido acima.
        let _ = unsafe { self.dup.ReleaseFrame() };
        out.map(|()| true)
    }

    fn name(&self) -> &'static str {
        "dxgi-duplication"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvnc_framebuffer::DEFAULT_MAX_BYTES;

    /// Toca a tela real: so roda com `--ignored`. Nao inspeciona o conteudo.
    #[test]
    #[ignore]
    fn captures_primary_output() {
        let mut c = DxgiCapture::new().expect("DXGI");
        let (w, h) = c.size();
        let mut fb = Framebuffer::new(w, h, DEFAULT_MAX_BYTES).unwrap();
        let t = std::time::Instant::now();
        for _ in 0..10 {
            assert!(c.capture(&mut fb).unwrap());
        }
        eprintln!("{w}x{h}, 10 capturas em {:?}", t.elapsed());
        assert!(c.have_frame);
    }
}
