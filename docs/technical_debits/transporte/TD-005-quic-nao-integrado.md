---
id: TD-005
titulo: QUIC nao esta ligado ao servidor nem ao cliente e nao foi medido em rede real
componente: transporte
tipo: funcionalidade-pendente
prioridade: P2
status: resolvido
fase-alvo: v0.4
criado-em: 2026-11-26
atualizado-em: 2026-11-26
---

# TD-005: QUIC nao esta ligado ao servidor nem ao cliente e nao foi medido em rede real

## Contexto
O transporte QUIC (quinn) tem handshake e 4 streams com testes, mas so como transporte. Em loopback perdeu para TCP (cerca de 2,3 Gbit/s contra 26 Gbit/s no Windows). Depende do protocolo nativo (Fase 4).

## Impacto
Nao ha evidencia de que o QUIC traga ganho. Codigo sem uso tende a ficar desatualizado.

## Onde
- `core/crates/openvnc-transport/src/quic.rs`
- `core/crates/openvnc-transport/examples/bench_transport.rs`
- `servers/reference/src/native.rs` (servidor: QUIC e TCP+TLS na mesma porta)
- `core/crates/openvnc-client/src/native.rs` (cliente com fallback)
- `clients/cli/src/main.rs` (subcomando `openvnc native`)

## Proposta de solucao
1. Medir em rede com perda e latencia (netem) contra TCP+TLS.
2. Integrar junto do `openvnc-protocol`.
3. Criar o teste equivalente de entrada sob carga em TCP para comparar.

## Criterio de conclusao
- [x] Medicao com netem (perda e latencia) documentada
- [x] Servidor e cliente usando QUIC com fallback TCP+TLS
- [x] Decisao registrada sobre manter ou nao o QUIC como padrao

## Referencias
- Origem: `PLANO.md` (branch `fase-2`, commit 9a0df7e), secao "Progresso consolidado (apos a v0.3)".

## Historico
- 2026-11-26: registrado a partir da analise das fases 0 a 3.
- 2026-11-26: protocolo nativo ligado ao servidor (`--native <addr>` ou `native_listen`, UDP e TCP na mesma porta, mesma sessao para os dois transportes, janela de 2 quadros sem ACK, tiles RAW/ZLIB) e ao cliente (`NativeClient`, modo Auto tenta QUIC e cai para TCP+TLS com a mesma verificacao de certificado). Testes de loopback `native_quic` e `native_tcp_tls` passam, inclusive recusa de senha errada. Decisao: Auto (QUIC primeiro) fica como padrao do cliente, pois o fallback nao reduz a seguranca e o QUIC evita bloqueio de cabeca de fila entre input e graficos; revisar apos a medicao. **Impossivel neste ambiente:** a medicao com netem exige Linux com `tc`/privilegios de rede, indisponivel no Windows desta sessao. Resta apenas esse item.
- 2026-11-26: medicao com netem no loopback de um container Linux (podman, `--cap-add NET_ADMIN`, script `ci/netem/run.sh`, `bench_transport 32 MiB, 200 pings`). Atraso por sentido (RTT = 2x):

| netem | TCP | TLS 1.3 | QUIC | RTT p99 TCP / TLS / QUIC | RTT entrada QUIC c/ graficos saturados (p50 / p99) |
|---|---|---|---|---|---|
| nenhum | 14,65 Gbit/s | 17,40 Gbit/s | 3,08 Gbit/s | 0,17 / 0,24 / 0,25 ms | 0,37 / 2,05 ms |
| 25 ms | 0,21 Gbit/s | 0,01 Gbit/s | 0,15 Gbit/s | 50,6 / 51,1 / 51,3 ms | 50,5 / 51,3 ms |
| 25 ms, 1% perda | 0,09 Gbit/s | 0,03 Gbit/s | 0,01 Gbit/s | 302,6 / 307,2 / 178,5 ms | 60,0 / 126,0 ms |
| 50 ms, 3% perda | 0,04 Gbit/s | 0,01 Gbit/s | 0,00 Gbit/s | 409,5 / 464,0 / 428,8 ms | 140,7 / 429,4 ms |

Leitura: em vazao de massa o QUIC (quinn, controle de congestionamento padrao) perde para o TCP sob perda. Com 1% de perda, porem, o p99 dos pings cai de ~305 ms (TCP/TLS) para 178 ms, e o canal de entrada continua com p99 de 126 ms mesmo com o canal de graficos saturado, o caso que motiva o QUIC (sem bloqueio de cabeca de fila entre input e graficos). Com 3% de perda nao ha vantagem. Decisao mantida: modo Auto (QUIC primeiro, fallback TCP+TLS) continua padrao pela latencia de entrada; a vazao do QUIC sob perda vira trabalho futuro de ajuste (BBR e janelas do quinn), fora deste item.
