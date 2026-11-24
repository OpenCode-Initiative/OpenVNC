# C ABI (Fase 5)

Princípios: handles opacos (`openvnc_session_t*`), funções `openvnc_*` com códigos de erro inteiros, buffers alocados e liberados pela própria biblioteca, header gerado por cbindgen, versionamento semântico da ABI. Nunca expor `String`, `Vec` ou traits Rust.
