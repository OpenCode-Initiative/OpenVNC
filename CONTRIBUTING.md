# Contribuindo

1. Abra/discuta uma issue antes de mudanças grandes.
2. Faça fork e branch a partir de `main`.
3. Rode localmente, em `core/`:
   ```sh
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
4. Assine cada commit com o **DCO** (`git commit -s`), certificando o [Developer Certificate of Origin](https://developercertificate.org/).
5. Abra o PR usando o template.

## Regras de código
- Parsers de rede: sem `unwrap`/`panic`, limites via `check_limit`, testes com entrada truncada e malformada.
- Não anuncie encodings não implementados por completo.
- Nada de criptografia própria.
- Logs com `tracing`, sem dados sensíveis.

Siga o [Código de Conduta](CODE_OF_CONDUCT.md).
