# Publicacao

Tudo sai em `dist/`. A versao vem do arquivo `VERSION` na raiz.

```
make all        # Windows + Linux + macOS (+ Android/iOS quando existirem)
make release    # exige arvore limpa: cria a tag vVERSION, faz push, roda make all e publica dist/ no GitHub
make linux      # uma plataforma so (windows, linux, macos, android, ios)
```

| Plataforma | Saida | Onde compila | Requisitos |
|---|---|---|---|
| Windows | `OpenVNC-Setup-X.exe` | local | Rust MSVC, Inno Setup 6 |
| Linux x86_64 | `openvnc-X-linux-x86_64.tar.gz`, `openvnc_X_amd64.deb` | container local | podman ou docker |
| macOS x86_64 | `OpenVNC-X-macos-x86_64.dmg` | Mac remoto via SSH | `packaging/macos/remote.env` (ver `.example`), chave SSH autorizada no Mac, Rust no Mac |
| Android | `OpenVNC-X-android.apk` | local | cliente `clients/android` (a fazer), NDK, `cargo-apk` |
| iOS | `OpenVNC-X-ios.ipa` | Mac remoto | cliente `clients/ios` (a fazer), Xcode completo, conta Apple Developer |

Android e iOS sao pulados com aviso enquanto os clientes moveis nao existirem.
