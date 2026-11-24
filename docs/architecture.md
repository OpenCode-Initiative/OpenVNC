# Arquitetura detalhada

Camadas: Apresentação (desktop/egui+wgpu) → Protocolo (rfb, protocol) → Transporte (tcp/tls/quic) → Rede.

| Crate | Responsabilidade | Fase |
|---|---|---|
| openvnc-core | Tipos, erros, limites | 0–1 |
| openvnc-framebuffer | Framebuffer, dirty regions, conversão RGBA | 1 |
| openvnc-rfb | Handshake 3.3/3.7/3.8, mensagens, estado | 1 |
| openvnc-codecs | Raw, CopyRect, Hextile, ZRLE; depois Tight | 1–2 |
| openvnc-transport | TCP (tokio), TLS (rustls), QUIC (quinn) | 1–3 |
| openvnc-security | VNC Auth, VeNCrypt, certificados, pareamento | 1–3 |
| openvnc-protocol | Protocolo nativo | 4 |
| openvnc-ffi | C ABI | 5 |

Pipeline gráfico do cliente: pacotes → decoder → retângulos → framebuffer → dirty regions → upload parcial de textura → render somente quando necessário.
