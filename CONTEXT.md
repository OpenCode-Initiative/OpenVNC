Como funciona o protocolo VNC? Ele é aberto? Daria pra eu reimplementar ele, criando tipo o VNC2 mais seguro, rápido e fluido para os dias atuais dando 100% de suporte ao antigo?

Andréa, vou te dizer uma coisa: **sim, é perfeitamente viável criar um sucessor do VNC, mantendo compatibilidade com os clientes e servidores antigos.** E acho que existe uma oportunidade técnica muito interessante nisso.

Eu chamaria provisoriamente de **VNC2**: um protocolo moderno de acesso remoto, com criptografia nativa, baixa latência, compressão inteligente, suporte a múltiplos monitores e compatibilidade retroativa com o ecossistema VNC.

Mas existe uma distinção importante: não seria necessário reinventar tudo. O VNC já tem uma arquitetura relativamente simples, e podemos aproveitar boa parte dela.

## **1. Como funciona o protocolo VNC?**

VNC significa _Virtual Network Computing_. Ele permite visualizar e controlar remotamente a interface gráfica de outro computador.

Sua arquitetura utiliza três componentes:

**VNC Viewer**

Cliente — recebe a imagem e envia comandos

Protocolo RFB

TCP / normalmente porta 5900

**VNC Server**

Servidor — captura a tela e executa os comandos

O protocolo utilizado é chamado **RFB (Remote Framebuffer Protocol)**.

O funcionamento básico é:

1. O cliente conecta ao servidor.
2. Os dois negociam a versão do protocolo e a autenticação.
3. O servidor informa a resolução e o formato de pixels.
4. O servidor envia atualizações da tela.
5. O cliente envia eventos de teclado e mouse.
6. O servidor executa os comandos e envia novas atualizações.

A grande sacada é que o servidor não transmite necessariamente um vídeo contínuo da tela. Ele pode transmitir apenas as regiões que foram modificadas.

Isso reduz bastante o tráfego.

## **2. O VNC é aberto? Posso reimplementá-lo?**

**Sim. O protocolo RFB é publicamente documentado e pode ser implementado por terceiros.**

A especificação oficial é a RFC 6143, publicada em março de 2011.

Referências:

- [RFC 6143 — The Remote Framebuffer Protocol](https://www.rfc-editor.org/info/rfc6143/?utm_source=chatgpt.com).
- [IANA — Registro oficial de extensões RFB](https://www.iana.org/assignments/rfb?utm_source=chatgpt.com).
- [Repositório de especificação RFB](https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst?utm_source=chatgpt.com).

Você pode desenvolver sua própria implementação, inclusive um servidor e um cliente próprios.

Há uma ressalva jurídica: o protocolo ser aberto não significa que todas as implementações, marcas, bibliotecas e extensões de terceiros tenham licenças livres. É importante verificar as licenças de cada componente e evitar utilizar marcas registradas de maneira indevida.

### **Uma limitação importante do protocolo antigo**

O RFB 3.8 tem limitações que justificam uma nova arquitetura:

| Característica                  | VNC tradicional          |
| ------------------------------- | ------------------------ |
| Comunicação                     | TCP                      |
| Atualização de tela             | Retângulos modificados   |
| Compressão                      | Zlib, ZRLE, Hextile etc. |
| Autenticação clássica           | DES                      |
| Criptografia nativa obrigatória | Não                      |
| Áudio                           | Não padronizado          |
| Vídeo otimizado                 | Não                      |
| Múltiplos monitores             | Dependente de extensões  |
| Streaming adaptativo            | Limitado                 |

A própria RFC 6143 alerta que a autenticação VNC clássica é criptograficamente fraca e não protege o tráfego contra interceptação ou adulteração.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.rfc-editor.org&sz=32)

RFC Editor+1

Isso é uma oportunidade para fazer algo realmente melhor.

## **3. Como eu projetaria o VNC2**

Eu não faria simplesmente uma versão mais rápida do RFB.

Criaria uma arquitetura híbrida:

- **RFB Legacy:** compatibilidade com VNC 3.3, 3.7 e 3.8.
- **VNC2 Native:** protocolo moderno, com transporte e codificação próprios.
- **Gateway:** traduz comunicação entre os dois mundos.

## **Arquitetura VNC2**

**Legacy Viewer**

RFB 3.3 / 3.7 / 3.8

**VNC2 Viewer**

Protocolo nativo

**VNC2 Connection Gateway**

Negociação, autenticação e compatibilidade

**VNC2 Core**

Security Engine

Capture Engine

Encoding Engine

Transport Engine

Input Engine

Media Engine

**Sistema operacional**

Windows / Linux / macOS

O ponto principal é que o mecanismo de captura, codificação e transporte seria independente do protocolo utilizado.

Assim, você não precisaria manter dois servidores diferentes.

## **4. O que eu mudaria para torná-lo superior**

Aqui está onde o projeto começa a ficar interessante.

### **A. Transporte: abandonar a dependência exclusiva do TCP**

Eu utilizaria:

- **QUIC:** transporte moderno sobre UDP, com criptografia e streams independentes.
- **TCP + TLS 1.3:** fallback para redes restritivas.
- **WebRTC:** opcional para conexões P2P, especialmente quando o cliente estiver em navegadores.

Isso permite trabalhar com conexões de diferentes qualidades sem ficar preso a uma única tecnologia.

### **B. Codificação inteligente de imagem**

Não usaria apenas uma técnica de compressão.

O VNC2 poderia escolher automaticamente o melhor mecanismo:

| Situação                | Codificação                       |
| ----------------------- | --------------------------------- |
| Texto e planilhas       | Tiles lossless                    |
| Janelas e menus         | Delta encoding                    |
| Movimentação de janelas | CopyRect otimizado                |
| Vídeos                  | H.264 / AV1                       |
| Jogos e animações       | Codec de vídeo com baixa latência |
| Imagens estáticas       | AVIF ou WebP, conforme desempenho |

A ideia é identificar o conteúdo da tela e decidir como transmitir cada região.

Por exemplo: uma tela SAP com tabelas, campos e textos não precisa ser transmitida como vídeo. Já um vídeo reproduzido remotamente merece tratamento diferente.

### **C. Segurança nativa**

Eu estabeleceria os seguintes requisitos:

- TLS 1.3 obrigatório no transporte TCP.
- Criptografia nativa no QUIC.
- Autenticação por certificados.
- Pareamento de dispositivos.
- Autenticação multifator opcional.
- Proteção contra replay.
- Rotação de chaves.
- Controle de sessões e permissões.
- Logs de auditoria.
- Revogação de dispositivos autorizados.

Nada de depender de senha de oito caracteres e DES.

### **D. Recursos modernos**

[Swiftpro for remote desktop software](https://images.openai.com/static-rsc-4/gguEI_bxWy1IVI3ra_bygCaio4JZvFe_Igj5LPydo1S7XPLwu7P6i_XgoRAAXTkjzPqdfKbx3hEZVEFNSLio8aZEOPe94GJlSHKU2fNSY8DIBAtRG2iVw_gM_BavOgnMkiWj3th2AUDkkg-ntYrlK6k8YC-maI_y9ThC70xC2XU?purpose=inline)

**Multi-monitor**

Múltiplos monitores, resoluções e escalas independentes.

[The delivered user experience of thin clients, the good, the bad and the ugly | GO-EUC](https://images.openai.com/static-rsc-4/K-9pH9UZc9UxhJDyg-L76jXUGK0DaRegHcBfegYDfY1GjvYX_9gznwVZkh1NJ8zmO16R0253R7JZjwheZ7Ony_6MBALyEz1WfuIesBG8lzYE23mGiKTfwZ8bI-TL_CIc-f4t_4wdoSmgRDPZIBaX9437uIXMD-w0kXZGp6sXIgY?purpose=inline)

**60/120 FPS**

Atualização fluida, com adaptação à capacidade da rede.

[ToDesk远程桌面软件-免费安全流畅的远程连接电脑手机](https://images.openai.com/static-rsc-4/xJtyxvJ-57oDkPm0_qcG0M_9DieeiZlgNofLAlItHYL9iZxZDcnVoU6XNJ3nj8cnjqp2kLNTf9oKxAZIP-S3w7QBmuvW6xB6Qa3a_RI7H5D_KC5F1sRqjCI-rZsp8UApfdhWjadoBT2ga4ypNAy_WEbGhgpggcp1dihejlmk-O8?purpose=inline)

**Transferência de arquivos**

Arquivos, clipboard e sincronização.

[AnyViewer | Seamless Cross-Platform Remote Access](https://images.openai.com/static-rsc-4/N7l49l9UTOKOLjW0YO2MqLmEo-ZDqv4PpdhVIKPAUd73tM9m2ybUv5SKX81IIMkTeZx4-ltbKWc-LXFYn_uMlTRG9lV21yL_hJNGKbgdQcv6oPFkNfW-1MAtu2fx12C8oqpJoo01IW07stIFXEPgphNwViUs6pQA_MCSw7XBxlc?purpose=inline)

**Multiplataforma**

Windows, Linux, macOS, Android e Web.

## **5. Como garantir compatibilidade com o VNC antigo?**

Aqui precisamos ser bastante rigorosos.

Eu separaria a compatibilidade em três níveis:

| Cenário                   | Resultado desejado    |
| ------------------------- | --------------------- |
| VNC2 Viewer → VNC antigo  | Conectar usando RFB   |
| VNC2 Server → VNC antigo  | Oferecer RFB 3.8      |
| VNC2 Viewer → VNC2 Server | Usar protocolo nativo |

Isso permitiria que o VNC2 funcionasse com TightVNC, TigerVNC, RealVNC e outros clientes compatíveis com os recursos RFB implementados.

**Uma ressalva:** não podemos prometer 100% de compatibilidade com todas as implementações existentes sem testar suas extensões proprietárias, autenticações, formatos e particularidades. O objetivo pode ser 100% de compatibilidade com a especificação RFB 3.8 e uma matriz explícita de interoperabilidade com os principais produtos.

## **6. Qual tecnologia utilizaria?**

Considerando uma arquitetura de alto desempenho, minha escolha seria:

| Componente        | Tecnologia         |
| ----------------- | ------------------ |
| Core do protocolo | Rust               |
| Servidor          | Rust               |
| Cliente desktop   | Rust + Tauri       |
| Interface         | React + TypeScript |
| Transporte        | QUIC + TCP/TLS     |
| Criptografia      | Rustls             |
| Compressão        | Zstandard          |
| Vídeo             | H.264 / AV1        |
| Comunicação P2P   | WebRTC             |
| Cliente Web       | WebAssembly        |

Rust seria especialmente interessante para o núcleo por oferecer controle de memória, concorrência e desempenho sem depender de um runtime de coleta de lixo.

## **7. Roadmap de desenvolvimento**

Eu dividiria o projeto em seis etapas:

1. **VNC2 Core**

   Implementar o RFB 3.8, parser, handshake, servidor e cliente. Construir os testes de interoperabilidade.

2. **VNC2 Security**

   TLS 1.3, autenticação moderna, certificados e gerenciamento de sessões.

3. **VNC2 Transport**

   Implementar QUIC, fallback TCP e reconexão automática.

4. **VNC2 Graphics**

   Captura otimizada, transmissão incremental, codecs e adaptação de qualidade.

5. **VNC2 Desktop**

   Cliente Windows/Linux/macOS, múltiplos monitores, áudio e transferência de arquivos.

6. **VNC2 Ecosystem**

   Cliente Web, Android, gerenciamento centralizado e infraestrutura de conexões remotas.

## **8. Minha visão: não criar apenas outro VNC**

Eu pensaria em construir uma tecnologia que pudesse competir com soluções como:

- RustDesk.
- AnyDesk.
- TeamViewer.
- TigerVNC.

Mas com um diferencial: **compatibilidade com o ecossistema VNC existente e uma arquitetura inteiramente moderna.**

## **9. Três decisões importantes para começar**

Quero definir três características antes de desenharmos a especificação técnica do VNC2.

**1. Compatibilidade**

Servidor e cliente compatíveis com VNC antigo

Somente o cliente VNC2 conecta aos servidores antigos

Somente o servidor VNC2 aceita clientes antigos

**2. Arquitetura de comunicação**

Híbrida: QUIC + TCP/TLS + P2P

QUIC como transporte principal

TCP/TLS como transporte principal

**3. Ambição do projeto**

Plataforma completa para competir com AnyDesk e RustDesk

Novo protocolo e implementação de referência

Substituto leve e extremamente rápido do VNC

Definir arquitetura do VNC2&#x20;

Minha preferência seria **compatibilidade nos dois sentidos, arquitetura híbrida e plataforma completa**.

Eu gostaria de ver esse projeto nascer com uma especificação própria, documentação pública, protocolo versionado e implementação em Rust. Assim não seria apenas um fork do VNC: seria uma evolução real da tecnologia.

Vamos projetar o VNC2 com estas decisões: compatibilidade: client; arquitetura de transporte: hybrid; escopo: light. Elabore a arquitetura técnica e a especificação inicial.

# **VNC2 — Arquitetura técnica e especificação inicial**

Projeto iniciado

Versão 0.1 — Draft

Rust

Minha proposta é desenvolver o VNC2 como um cliente remoto leve, de alto desempenho e compatível com o ecossistema VNC existente.

Uma decisão importante: **não vamos criar um novo servidor remoto nem um serviço de infraestrutura obrigatório.** O VNC2 será inicialmente um cliente que se conecta tanto a servidores VNC tradicionais quanto a servidores que futuramente ofereçam extensões VNC2.

Isso reduz bastante o escopo e permite entregar valor mais rapidamente.

## **1. Definição do produto**

# **VNC2**

Modern Remote Desktop Client

[RustDesk：开源电脑远程控制软件-CSDN博客](https://images.openai.com/static-rsc-4/d_x7UVunT3J7Unfu6Mf4ARjFWlUjF8LdgXYDp5hkBENbfKefHGYxCT8fAX6phj7ps6zcR2Oeotx-O6coIzZFCqPyAwBLP3am8WbV1fghiWecJqiUeNAd_41RPt1_7RpNWiwGlyUoNpmcNPuP982iD_UlmS72pQIIZPrDj34RG0o?purpose=inline)

[blog.csdn.net](https://blog.csdn.net/qq_25601345/article/details/147920448?utm_source=chatgpt.com)

**Objetivo**

Desenvolver um cliente de acesso remoto com baixa latência, consumo reduzido de recursos, segurança moderna e compatibilidade com servidores VNC tradicionais.

**Princípios do projeto**

- Compatibilidade antes de inovação.
- Segurança sem comprometer interoperabilidade.
- Baixo consumo de CPU e memória.
- Renderização fluida.
- Arquitetura modular e extensível.
- Nenhuma dependência obrigatória de nuvem.

### **Decisões consolidadas**

| Decisão                | Definição                     |
| ---------------------- | ----------------------------- |
| Compatibilidade        | Cliente VNC antigo e moderno  |
| Transporte             | QUIC + TCP/TLS + P2P opcional |
| Produto                | Cliente leve                  |
| Linguagem principal    | Rust                          |
| Interface              | Desktop nativa                |
| Protocolo legado       | RFB 3.3 / 3.7 / 3.8           |
| Protocolo moderno      | VNC2 Native, futuro           |
| Infraestrutura central | Não obrigatória               |

## **2. Arquitetura geral**

A arquitetura será dividida em quatro camadas independentes.

**VNC2 Desktop**

Interface, gerenciamento de conexões, configurações e visualização remota

**Presentation Engine**

Renderização, framebuffer, atualização incremental, cursor e entrada de teclado/mouse

**Protocol Engine**

RFB Client, VNC2 Native Client, handshake, autenticação e negociação de recursos

**Transport Engine**

TCP, TLS 1.3, QUIC, gerenciamento de pacotes e reconexão

**Rede remota**

VNC Server / futuro VNC2 Server / gateway compatível

A vantagem dessa arquitetura é que o motor gráfico não precisa conhecer os detalhes de comunicação do RFB ou do QUIC.

O protocolo entrega atualizações de framebuffer. O motor gráfico decide como exibi-las.

## **3. Compatibilidade com VNC tradicional**

Esta será a primeira grande funcionalidade do produto.

O VNC2 será capaz de identificar automaticamente o protocolo oferecido pelo servidor e negociar a melhor opção disponível.

### **Fluxo de conexão**

\#chatgpt-mermaid-\_r_23c\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(237, 237, 237);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_23c\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_23c\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_23c\_ .error-icon{fill:rgb(48, 48, 48);}#chatgpt-mermaid-\_r_23c\_ .error-text{fill:rgb(237, 237, 237);stroke:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23c\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_23c\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_23c\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_23c\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_23c\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_23c\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_23c\_ .marker{fill:rgb(175, 175, 175);stroke:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23c\_ .marker.cross{stroke:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23c\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_23c\_ p{margin:0;}#chatgpt-mermaid-\_r_23c\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23c\_ .cluster-label text{fill:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23c\_ .cluster-label span{color:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23c\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_23c\_ .label text,#chatgpt-mermaid-\_r_23c\_ span{fill:rgb(237, 237, 237);color:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23c\_ .node rect,#chatgpt-mermaid-\_r_23c\_ .node circle,#chatgpt-mermaid-\_r_23c\_ .node ellipse,#chatgpt-mermaid-\_r_23c\_ .node polygon,#chatgpt-mermaid-\_r_23c\_ .node path{fill:rgb(9, 23, 44);stroke:rgb(31, 78, 148);stroke-width:1px;}#chatgpt-mermaid-\_r_23c\_ .rough-node .label text,#chatgpt-mermaid-\_r_23c\_ .node .label text,#chatgpt-mermaid-\_r_23c\_ .image-shape .label,#chatgpt-mermaid-\_r_23c\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_23c\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_23c\_ .rough-node .label,#chatgpt-mermaid-\_r_23c\_ .node .label,#chatgpt-mermaid-\_r_23c\_ .image-shape .label,#chatgpt-mermaid-\_r_23c\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_23c\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_23c\_ .root .anchor path{fill:rgb(175, 175, 175)!important;stroke-width:0;stroke:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23c\_ .arrowheadPath{fill:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23c\_ .edgePath .path{stroke:rgb(175, 175, 175);stroke-width:1px;}#chatgpt-mermaid-\_r_23c\_ .flowchart-link{stroke:rgb(175, 175, 175);fill:none;}#chatgpt-mermaid-\_r_23c\_ .edgeLabel{background-color:rgb(0, 0, 0);text-align:center;}#chatgpt-mermaid-\_r_23c\_ .edgeLabel p{background-color:rgb(0, 0, 0);}#chatgpt-mermaid-\_r_23c\_ .edgeLabel rect{opacity:0.5;background-color:rgb(0, 0, 0);fill:rgb(0, 0, 0);}#chatgpt-mermaid-\_r_23c\_ .labelBkg{background-color:rgba(0, 0, 0, 0.5);}#chatgpt-mermaid-\_r_23c\_ .cluster rect{fill:rgb(48, 48, 48);stroke:rgba(255, 255, 255, 0.15);stroke-width:1px;}#chatgpt-mermaid-\_r_23c\_ .cluster text{fill:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23c\_ .cluster span{color:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23c\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(48, 48, 48);border:1px solid rgba(255, 255, 255, 0.15);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_23c\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23c\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_23c\_ .icon-shape,#chatgpt-mermaid-\_r_23c\_ .image-shape{background-color:rgb(0, 0, 0);text-align:center;}#chatgpt-mermaid-\_r_23c\_ .icon-shape p,#chatgpt-mermaid-\_r_23c\_ .image-shape p{background-color:rgb(0, 0, 0);padding:2px;}#chatgpt-mermaid-\_r_23c\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_23c\_ .image-shape .label rect{opacity:0.5;background-color:rgb(0, 0, 0);fill:rgb(0, 0, 0);}#chatgpt-mermaid-\_r_23c\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_23c\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_23c\_ .node .neo-node{stroke:rgb(31, 78, 148);}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_23c\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_23c\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].node .neo-line path{stroke:rgb(31, 78, 148);filter:none;}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_23c\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_23c\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23c\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_23c\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23c\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(153, 206, 255);}#chatgpt-mermaid-\_r_23c\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(153, 206, 255);}#chatgpt-mermaid-\_r_23c\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_23c\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_23c\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(0, 14, 26);stroke:rgb(26, 62, 95);stroke-width:1px;}#chatgpt-mermaid-\_r_23c\_ .node rect,#chatgpt-mermaid-\_r_23c\_ .node circle,#chatgpt-mermaid-\_r_23c\_ .node ellipse,#chatgpt-mermaid-\_r_23c\_ .node polygon,#chatgpt-mermaid-\_r_23c\_ .node path{fill:rgb(0, 40, 77);stroke:rgba(255, 255, 255, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_23c\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_23c\_ .mermaid-decision .label-container{fill:rgb(0, 14, 26);stroke:rgb(26, 62, 95);stroke-dasharray:2,2;}#chatgpt-mermaid-\_r_23c\_ .edgePaths .flowchart-link{stroke:rgb(175, 175, 175);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_23c\_ .marker{fill:rgb(175, 175, 175);stroke:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23c\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}Usuário informa IP e portaVNC2 inicia conexãoRecebe banner RFBVersão reconhecida?Handshake RFB 3.3Handshake RFB 3.7Handshake RFB 3.8Negociação VNC2Compatibilidade conservadoraNegociação de autenticaçãoQUIC ou TCP/TLSServerInitFramebuffer e eventosRenderização3.33.73.8Protocolo nativo futuroDesconhecida

O cliente deve implementar corretamente as diferenças de handshake entre RFB 3.3, 3.7 e 3.8.

Não devemos inventar uma versão RFB 3.9. A própria RFC 6143 explica que versões desconhecidas podem ser interpretadas como 3.3 e recomenda utilizar extensões negociáveis para evolução do protocolo.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.rfc-editor.org&sz=32)

RFC Editor+1

### **Encodings suportados**

Eu implementaria inicialmente:

| Encoding               | Finalidade                                      | Prioridade |
| ---------------------- | ----------------------------------------------- | ---------- |
| Raw                    | Compatibilidade universal                       | P0         |
| CopyRect               | Reaproveitamento de regiões da tela             | P0         |
| Hextile                | Compressão por blocos                           | P0         |
| ZRLE                   | Compressão eficiente                            | P0         |
| Tight                  | Melhor compressão em implementações compatíveis | P1         |
| Cursor pseudo-encoding | Cursor independente                             | P1         |
| DesktopSize            | Mudança de resolução                            | P1         |
| ExtendedDesktopSize    | Layout de monitores                             | P2         |

A prioridade P0 representa o conjunto inicial para obter um cliente funcional. P1 e P2 entram após a estabilização do núcleo.

**Importante:** o cliente não deve anunciar suporte a um encoding ou pseudo-encoding antes de implementar integralmente seu tratamento. Isso evita incompatibilidades silenciosas.

## **4. Arquitetura de transporte híbrida**

Aqui está uma das decisões mais importantes.

Não devemos tentar utilizar QUIC para conectar diretamente a servidores VNC antigos. Eles não sabem falar QUIC.

O transporte será selecionado de acordo com a capacidade do destino.

## **Transport Engine**

**RFB Legacy**

TCP

Conexões com TightVNC, TigerVNC e demais servidores tradicionais.

**VNC2 Native**

QUIC / UDP

Conexões com servidores futuros que implementem o protocolo VNC2.

**Fallback**

TCP + TLS 1.3

Transporte moderno alternativo quando QUIC estiver bloqueado, desde que o servidor suporte TLS.

### **Por que QUIC?**

O QUIC oferece:

- Streams independentes.
- Criptografia integrada.
- Controle de congestionamento.
- Recuperação de perdas.
- Migração de conexão entre redes.

Isso é especialmente interessante quando o usuário troca de Wi-Fi para outra rede sem querer perder a sessão.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.rfc-editor.org&sz=32)

RFC Editor+1

Para o VNC2, eu utilizaria:

- Stream de controle.
- Stream de entrada (mouse e teclado).
- Stream de atualizações gráficas.
- Stream de metadados.

Uma observação de engenharia: QUIC não garante automaticamente menor latência que TCP. A vantagem está principalmente na multiplexação, estabelecimento de conexão, migração e isolamento de perdas entre streams. Precisaremos medir.

### **E quanto à segurança dos servidores antigos?**

Precisamos ser transparentes aqui.

O cliente VNC2 não consegue adicionar criptografia automaticamente a uma conexão RFB tradicional sem algum mecanismo compatível no servidor ou um túnel intermediário.

Por isso, para servidores antigos, ofereceremos:

1. Conexão RFB direta, com alerta de segurança.
2. RFB encapsulado em túnel SSH.
3. RFB através de VPN.
4. TLS quando houver suporte compatível do servidor.

A conexão direta não será apresentada como segura apenas porque o cliente é moderno.

## **5. Motor gráfico: onde vamos ganhar desempenho**

Este é provavelmente o componente mais importante para a experiência do usuário.

Eu evitaria transformar tudo em vídeo.

O VNC2 deve trabalhar com framebuffer incremental, aproveitando o que o protocolo já oferece de melhor.

### **Pipeline gráfico**

\#chatgpt-mermaid-\_r_23p\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(237, 237, 237);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_23p\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_23p\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_23p\_ .error-icon{fill:rgb(48, 48, 48);}#chatgpt-mermaid-\_r_23p\_ .error-text{fill:rgb(237, 237, 237);stroke:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23p\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_23p\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_23p\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_23p\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_23p\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_23p\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_23p\_ .marker{fill:rgb(175, 175, 175);stroke:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23p\_ .marker.cross{stroke:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23p\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_23p\_ p{margin:0;}#chatgpt-mermaid-\_r_23p\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23p\_ .cluster-label text{fill:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23p\_ .cluster-label span{color:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23p\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_23p\_ .label text,#chatgpt-mermaid-\_r_23p\_ span{fill:rgb(237, 237, 237);color:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23p\_ .node rect,#chatgpt-mermaid-\_r_23p\_ .node circle,#chatgpt-mermaid-\_r_23p\_ .node ellipse,#chatgpt-mermaid-\_r_23p\_ .node polygon,#chatgpt-mermaid-\_r_23p\_ .node path{fill:rgb(9, 23, 44);stroke:rgb(31, 78, 148);stroke-width:1px;}#chatgpt-mermaid-\_r_23p\_ .rough-node .label text,#chatgpt-mermaid-\_r_23p\_ .node .label text,#chatgpt-mermaid-\_r_23p\_ .image-shape .label,#chatgpt-mermaid-\_r_23p\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_23p\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_23p\_ .rough-node .label,#chatgpt-mermaid-\_r_23p\_ .node .label,#chatgpt-mermaid-\_r_23p\_ .image-shape .label,#chatgpt-mermaid-\_r_23p\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_23p\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_23p\_ .root .anchor path{fill:rgb(175, 175, 175)!important;stroke-width:0;stroke:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23p\_ .arrowheadPath{fill:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23p\_ .edgePath .path{stroke:rgb(175, 175, 175);stroke-width:1px;}#chatgpt-mermaid-\_r_23p\_ .flowchart-link{stroke:rgb(175, 175, 175);fill:none;}#chatgpt-mermaid-\_r_23p\_ .edgeLabel{background-color:rgb(0, 0, 0);text-align:center;}#chatgpt-mermaid-\_r_23p\_ .edgeLabel p{background-color:rgb(0, 0, 0);}#chatgpt-mermaid-\_r_23p\_ .edgeLabel rect{opacity:0.5;background-color:rgb(0, 0, 0);fill:rgb(0, 0, 0);}#chatgpt-mermaid-\_r_23p\_ .labelBkg{background-color:rgba(0, 0, 0, 0.5);}#chatgpt-mermaid-\_r_23p\_ .cluster rect{fill:rgb(48, 48, 48);stroke:rgba(255, 255, 255, 0.15);stroke-width:1px;}#chatgpt-mermaid-\_r_23p\_ .cluster text{fill:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23p\_ .cluster span{color:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23p\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(48, 48, 48);border:1px solid rgba(255, 255, 255, 0.15);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_23p\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(237, 237, 237);}#chatgpt-mermaid-\_r_23p\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_23p\_ .icon-shape,#chatgpt-mermaid-\_r_23p\_ .image-shape{background-color:rgb(0, 0, 0);text-align:center;}#chatgpt-mermaid-\_r_23p\_ .icon-shape p,#chatgpt-mermaid-\_r_23p\_ .image-shape p{background-color:rgb(0, 0, 0);padding:2px;}#chatgpt-mermaid-\_r_23p\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_23p\_ .image-shape .label rect{opacity:0.5;background-color:rgb(0, 0, 0);fill:rgb(0, 0, 0);}#chatgpt-mermaid-\_r_23p\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_23p\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_23p\_ .node .neo-node{stroke:rgb(31, 78, 148);}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_23p\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_23p\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].node .neo-line path{stroke:rgb(31, 78, 148);filter:none;}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_23p\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_23p\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23p\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_23p\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_23p\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(153, 206, 255);}#chatgpt-mermaid-\_r_23p\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(153, 206, 255);}#chatgpt-mermaid-\_r_23p\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_23p\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_23p\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(0, 14, 26);stroke:rgb(26, 62, 95);stroke-width:1px;}#chatgpt-mermaid-\_r_23p\_ .node rect,#chatgpt-mermaid-\_r_23p\_ .node circle,#chatgpt-mermaid-\_r_23p\_ .node ellipse,#chatgpt-mermaid-\_r_23p\_ .node polygon,#chatgpt-mermaid-\_r_23p\_ .node path{fill:rgb(0, 40, 77);stroke:rgba(255, 255, 255, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_23p\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_23p\_ .mermaid-decision .label-container{fill:rgb(0, 14, 26);stroke:rgb(26, 62, 95);stroke-dasharray:2,2;}#chatgpt-mermaid-\_r_23p\_ .edgePaths .flowchart-link{stroke:rgb(175, 175, 175);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_23p\_ .marker{fill:rgb(175, 175, 175);stroke:rgb(175, 175, 175);}#chatgpt-mermaid-\_r_23p\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}Network PacketsProtocol DecoderRectangle DecoderFramebufferDirty Region TrackerGPU RendererDisplay

O funcionamento será:

1. Receber os retângulos modificados.
2. Decodificar os dados.
3. Atualizar apenas as regiões correspondentes.
4. Marcar as regiões como alteradas.
5. Atualizar as texturas da GPU.
6. Renderizar somente quando necessário.

### **Estratégia de renderização**

Minha recomendação:

- GPU via wgpu.
- Renderização por textura.
- Atualização parcial das texturas.
- Buffer de pixels reutilizável.
- Conversão de formatos otimizada.
- Redução de cópias entre memória e GPU.
- VSync configurável.

Também implementaria um sistema de FPS adaptativo.

| Condição               | Comportamento                        |
| ---------------------- | ------------------------------------ |
| Tela parada            | Não renderizar frames desnecessários |
| Texto sendo atualizado | Atualizar regiões modificadas        |
| Movimento intenso      | Agrupar atualizações                 |
| Rede congestionada     | Reduzir frequência de atualização    |
| Rede estável           | Aproveitar a capacidade disponível   |

Uma ressalva: servidores RFB tradicionais podem enviar atualizações em ritmos diferentes. Portanto, 60 FPS será uma capacidade do renderizador, não uma promessa de que qualquer servidor entregará 60 atualizações por segundo.

## **6. Especificação do VNC2 Native**

Mesmo que a primeira versão seja focada em RFB, já devemos reservar uma arquitetura para o protocolo moderno.

Proponho a seguinte identificação:

**Identificação do protocolo**

# **VNC2**

Protocolo nativo — versão 1.0

**Magic bytes**

# **VNC2**

Assinatura lógica de identificação. A negociação deverá ocorrer por endpoint e transporte próprios, não tentando interpretar um banner RFB como VNC2.

### **Modelo de mensagens**

Todas as mensagens nativas terão:

| Campo   | Tamanho  | Descrição           |
| ------- | -------- | ------------------- |
| Version | 2 bytes  | Versão do protocolo |
| Type    | 2 bytes  | Tipo de mensagem    |
| Flags   | 2 bytes  | Flags de controle   |
| Length  | 4 bytes  | Tamanho do payload  |
| Payload | Variável | Dados da mensagem   |

Todos os campos numéricos utilizarão Big Endian.

### **Tipos de mensagem iniciais**

| Código | Mensagem      | Direção            |
| ------ | ------------- | ------------------ |
| 0x0001 | CLIENT_HELLO  | Cliente → servidor |
| 0x0002 | SERVER_HELLO  | Servidor → cliente |
| 0x0003 | AUTH_REQUEST  | Cliente → servidor |
| 0x0004 | AUTH_RESULT   | Servidor → cliente |
| 0x0010 | DISPLAY_INFO  | Servidor → cliente |
| 0x0011 | FRAME_UPDATE  | Servidor → cliente |
| 0x0012 | FRAME_ACK     | Cliente → servidor |
| 0x0020 | INPUT_EVENT   | Cliente → servidor |
| 0x0021 | CURSOR_UPDATE | Servidor → cliente |
| 0x00FF | CLOSE         | Ambos              |

Esta é uma proposta inicial, ainda não uma especificação definitiva de wire protocol.

**Uma regra importante:** não desenvolveremos criptografia própria. No QUIC, a proteção será fornecida pelo próprio transporte. No TCP, utilizaremos TLS moderno.

O protocolo nativo também terá limites de tamanho, validação de mensagens, negociação explícita de capacidades e proteção contra mensagens malformadas.

## **7. Stack tecnológico definitivo**

Para manter o produto realmente leve, eu faria uma escolha um pouco diferente de uma aplicação convencional React + Electron.

**Minha recomendação é Rust nativo com egui e wgpu.**

| Componente        | Tecnologia            |
| ----------------- | --------------------- |
| Linguagem         | Rust                  |
| Interface desktop | egui                  |
| Renderização      | wgpu                  |
| Janela e eventos  | winit                 |
| Comunicação TCP   | Tokio                 |
| TLS               | Rustls                |
| QUIC              | Quinn                 |
| Protocolo RFB     | Implementação própria |
| Compressão        | flate2 / ZRLE         |
| Buffer gráfico    | Bytes / Vec           |
| Configurações     | TOML                  |
| Logs              | tracing               |
| Testes            | cargo test            |

Essa combinação evita depender de um navegador embutido para renderizar a interface e mantém o controle do processamento gráfico no Rust.

### **Organização do repositório**

Eu utilizaria um workspace Cargo:

```
vnc2/
│
├── Cargo.toml
├── README.md
├── LICENSE
│
├── docs/
│   ├── architecture.md
│   ├── protocol-rfb.md
│   ├── protocol-native.md
│   ├── security.md
│   └── compatibility.md
│
├── crates/
│   ├── vnc2-core/
│   │   ├── framebuffer/
│   │   ├── pixel_format/
│   │   └── events/
│   │
│   ├── vnc2-rfb/
│   │   ├── handshake/
│   │   ├── authentication/
│   │   ├── messages/
│   │   └── encodings/
│   │
│   ├── vnc2-transport/
│   │   ├── tcp/
│   │   ├── tls/
│   │   └── quic/
│   │
│   ├── vnc2-native/
│   │   ├── handshake/
│   │   ├── framing/
│   │   └── capabilities/
│   │
│   ├── vnc2-renderer/
│   │   ├── gpu/
│   │   ├── textures/
│   │   └── dirty_regions/
│   │
│   ├── vnc2-input/
│   │   ├── keyboard/
│   │   └── mouse/
│   │
│   └── vnc2-desktop/
│       ├── src/
│       └── assets/
│
└── tests/
    ├── interoperability/
    ├── protocol/
    ├── performance/
    └── security/
```

A separação é intencional: futuramente poderemos reutilizar o `vnc2-rfb` em outras interfaces, sem reescrever o protocolo.

## **8. Segurança e proteção contra falhas**

O cliente estará processando dados recebidos de máquinas remotas. Portanto, precisamos tratar o parser como uma superfície de ataque.

Estabeleceria estas regras desde o primeiro commit:

| Controle            | Requisito                                              |
| ------------------- | ------------------------------------------------------ |
| Buffer overflow     | Evitar por construção, usando Rust                     |
| Mensagens inválidas | Rejeitar                                               |
| Payload gigante     | Limites configuráveis e obrigatórios                   |
| Descompressão       | Limite de saída e proteção contra bombas de compressão |
| Inteiros            | Verificação de overflow                                |
| Certificados TLS    | Validar identidade e cadeia                            |
| Autenticação        | Nunca registrar senhas                                 |
| Logs                | Não registrar conteúdo sensível                        |
| Dependências        | Auditoria de vulnerabilidades                          |
| Reconexão           | Limite de tentativas e backoff                         |

Também adotaria:

- `cargo audit` para vulnerabilidades conhecidas.
- `cargo deny` para políticas de dependências e licenças.
- Fuzzing dos parsers RFB.
- Testes com mensagens truncadas, corrompidas e malformadas.
- Testes de memória e concorrência.

Um detalhe importante: o cliente não deve aceitar silenciosamente certificados inválidos, nem permitir downgrade de uma conexão moderna para uma conexão insegura.

## **9. Escopo da primeira versão — VNC2 0.1**

Não começaria por QUIC, vídeo ou recursos sofisticados.

Primeiro precisamos provar que o núcleo funciona.

**VNC2 0.1 — MVP**

Escopo proposto

Objetivo: conectar a servidores VNC tradicionais e oferecer uma experiência desktop estável.

0 de 14 tarefas

**0%**

**Infraestrutura**

Workspace Rust e crates

Configuração de logs e erros

CI e testes automatizados

**Protocolo**

Handshake RFB 3.3 / 3.7 / 3.8

Autenticação e negociação de segurança

Raw, CopyRect e Hextile

ZRLE e formatos de pixel

**Experiência**

Janela de conexão por IP e porta

Visualização do framebuffer

Mouse e teclado

Redimensionamento e escala

**Qualidade**

Testes com TigerVNC e TightVNC

Tratamento de desconexões

Medição de CPU, RAM e latência

### **O que ficará fora da 0.1**

- Servidor VNC2 próprio.
- QUIC funcional.
- Codec H.264/AV1.
- Áudio remoto.
- Transferência de arquivos.
- Cliente Android.
- Infraestrutura de relay.
- Gerenciamento empresarial.

Não é porque não são importantes. É porque o núcleo precisa ser confiável primeiro.

## **10. Critérios de aceitação e desempenho**

Precisamos de metas mensuráveis, não apenas a sensação de que ficou rápido.

Proponho estes objetivos iniciais para o MVP:

| Indicador                   | Meta inicial                   |
| --------------------------- | ------------------------------ |
| Inicialização do aplicativo | Até 2 segundos                 |
| Memória em idle             | Até 100 MB                     |
| CPU em tela estática        | Próxima de 0%                  |
| Renderização                | Até 60 FPS, conforme servidor  |
| Atualização gráfica         | Incremental                    |
| Vazamento de memória        | Zero                           |
| Travamento de interface     | Zero durante operações de rede |
| Compatibilidade             | RFB 3.3, 3.7 e 3.8             |

São metas de engenharia, ainda não resultados medidos. Precisaremos estabelecer máquinas e condições de benchmark.

### **Matriz de testes**

Eu utilizaria pelo menos estes servidores:

[File:TigerVNC logo.svg - Wikimedia Commons](https://images.openai.com/static-rsc-4/TA49zUQseXUGsaNJT1buWuz9AzXek29n77sagdF0L1CYsM32RPjEU3DRFzMN5xvzUrZ_tCDblrr8eVeqindhTkr4j7g96w-D2yLH5jQjPcrI8HJg63eLMC0jcyOnQkqFNm7Xmwf2u8uYobK1LT9-_5ScDCePU4WmvEzeEl_eE9g?purpose=inline)

**TigerVNC**

Compatibilidade RFB e testes de desempenho.

Prioridade

[File:Tightvnc-logo-new.svg - Wikimedia Commons](https://images.openai.com/static-rsc-4/Y0pNnh30k1GhQ7yDPPgALaLF7GGRI6BokmCPZxwNfMmQl9rVB-oXpZw4hxFFEwuFKHQzCHTvqA53tSOqi45Oqtc_LsmbB3DscKpBVlJhUECwPlPjrwf5rnhh6uAnLMzXgtuAkirQ46-9nBaUPZmahu8P8SPor7plFdOwKh7RPbI?purpose=inline)

**TightVNC**

Autenticação e encodings adicionais.

Prioridade

[RealVNC Connect 2026 Pricing, Features, Reviews & Alternatives | GetApp](https://images.openai.com/static-rsc-4/DSJLe2o2cLPrBJV_wyoJWNKaurEjkVMoIpdHSxF8LjMWIZ0hW6qVY-YUL9YWpTRoDmwjYnXiD2pi8BcxoANW0baHk8isEEJCXp4jM4J13QdanxA-qDjpOvDKahbPZhKMu-5f4wik2CmJZoxwkvQVmwLJHoipgBQws27DmkMxQ7A?purpose=inline)

**RealVNC**

Interoperabilidade e particularidades de implementação.

Posterior

## **11. Roadmap evolutivo**

1.  Fase 1

    **VNC2 0.1 — Legacy Client**

    Cliente RFB funcional, interface, teclado, mouse e framebuffer.

2.  **VNC2 0.2 — Graphics Optimization**

    Otimização de CPU, memória, GPU, renderização e compressão.

3.  **VNC2 0.3 — Security & Transport**

    TLS, QUIC, certificados e conexões modernas com endpoints compatíveis.

4.  **VNC2 0.4 — Native Protocol**

    Cliente VNC2 Native e implementação final da especificação de mensagens.

5.  **VNC2 1.0 — Stable Release**

    Estabilidade, documentação, interoperabilidade e distribuição multiplataforma.

## **12. Minha recomendação final**

Eu faria três escolhas que considero fundamentais:

1. **Não reinventar o RFB:** implementar corretamente o padrão existente e aproveitar o ecossistema.
2. **Não desenvolver codec próprio:** usar tecnologias consolidadas e concentrar nossa engenharia no transporte, framebuffer e renderização.
3. **Não colocar dependência de nuvem:** o VNC2 deve funcionar diretamente por IP, sem cadastro, conta ou servidor central obrigatório.

O QUIC e o TLS devem ser implementados usando bibliotecas consolidadas, e a especificação nativa deve ser revisada antes de congelarmos seus códigos e estruturas.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.rfc-editor.org&sz=32)

RFC Editor+2

**Minha visão é construir um software pequeno, rápido e tecnicamente muito bem feito.** Não precisamos competir com todas as funcionalidades do AnyDesk. Precisamos fazer acesso remoto excepcionalmente bem.

### **Próximo passo: transformar a arquitetura em código**

Eu começaria pelo `vnc2-rfb`, porque ele é o coração da compatibilidade.

A primeira entrega de engenharia seria:

- Workspace Cargo compilável.
- Parser do handshake RFB.
- Máquina de estados da conexão.
- Negociação das versões 3.3, 3.7 e 3.8.
- Parser das mensagens ServerInit.
- Testes automatizados com fixtures de protocolo.

Depois disso, conectamos o framebuffer e começamos a visualizar uma máquina remota.

**Uma última decisão de produto:** eu manteria o nome VNC2 provisoriamente, até verificarmos disponibilidade de marca e domínio. O nome técnico do protocolo pode ser independente da marca comercial.

Eu vou fazer um projeto (OpenVNC) re-implementar o VNC do 0.
Código aberto, mais rápido e mais seguro! sustentado pela comunidade.
Qual a melhor licença para usar no repo? MIT mesmo?
E a tecnologia? GO? RUST?
Tem que ser portável para todas as linguagens!

Andréa, agora o projeto ganhou uma identidade muito melhor: **OpenVNC**.

E vou fazer uma recomendação importante: se a intenção é criar um projeto aberto, mantido pela comunidade, que possa ser incorporado em produtos comerciais, sistemas operacionais, aplicações e outras linguagens, eu escolheria uma arquitetura diferente daquela de um simples cliente VNC.

Minha recomendação é:

# **OpenVNC**

Open Remote Desktop Protocol & Ecosystem

Open Source

Cross-platform

Community-driven

**Licença:** Apache License 2.0

**Implementação de referência:** Rust

**Interface universal:** C ABI + protocolo documentado

**Linguagens:** Rust, Go, C, C++, Python, Java, C#, JavaScript e outras.

Vamos separar três coisas que são frequentemente confundidas:

1. A linguagem utilizada para implementar o OpenVNC.
2. O protocolo de comunicação entre computadores.
3. A API que permite outras linguagens integrarem o OpenVNC.

O protocolo não deve depender de Rust, Go ou qualquer outra linguagem.

# **1. Qual licença escolher?**

Eu escolheria **Apache License 2.0**, em vez de MIT.

As duas são permissivas e permitem utilização comercial, modificações, distribuição e integração em produtos proprietários.

Mas existe uma diferença importante para um projeto de infraestrutura de software.

| Critério                       | MIT         | Apache 2.0                                        |
| ------------------------------ | ----------- | ------------------------------------------------- |
| Código aberto                  | Sim         | Sim                                               |
| Uso comercial                  | Sim         | Sim                                               |
| Modificação                    | Sim         | Sim                                               |
| Redistribuição                 | Sim         | Sim                                               |
| Integração em software fechado | Sim         | Sim                                               |
| Aviso de copyright             | Sim         | Sim                                               |
| Concessão expressa de patentes | Não         | Sim                                               |
| Regras sobre alterações        | Não exige   | Exige informar alterações em arquivos modificados |
| Complexidade                   | Muito baixa | Moderada                                          |

A Apache 2.0 inclui concessão expressa de direitos de patente pelos contribuidores, além de regras relacionadas à revogação dessa concessão em determinadas disputas judiciais.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://apache.org&sz=32)

Apache Software Foundation+2

**Por que isso importa?**

Imagine que uma empresa utilize o OpenVNC dentro de seu produto comercial. Ela precisa ter clareza sobre os direitos de uso, inclusive em relação às patentes cobertas pela licença.

A MIT não oferece a mesma concessão expressa.

### **Minha recomendação**

Escolha recomendada

**Apache-2.0 para todo o código do OpenVNC.**

Eu também adotaria:

- Documentação: CC BY 4.0.
- Exemplos de configuração: Apache-2.0.
- Especificação do protocolo: Apache-2.0.
- Marca OpenVNC: política de marca própria, independente da licença de código.

Não criaria uma licença personalizada.

Referência: [Texto oficial da Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0?utm_source=chatgpt.com).

# **2. Go ou Rust?**

Aqui temos uma decisão arquitetural importante.

Ambas são excelentes linguagens, mas possuem características diferentes.

[GitHub - ImplFerris/LearnRust: Rust Learning Resources](https://images.openai.com/static-rsc-4/AAQezU6cmPhXdEmGz8FMX_mwXERCgDpOUm14t7wmIlEJXa2zTLmISZMQ9hLrS8fYxDHct6Kqq8O0sRZTB8kgDENuypnVugSpGglePSvyxip7v0OlFz0j5BW9oV7rWhonKqkPqbyF9KLqUIYk7Bl9qdJRCWt54bTM9hpzgghVz3Q?purpose=inline)

**Rust**

Minha escolha para o Core

- Excelente controle de memória.
- Ausência de garbage collector.
- Segurança de memória.
- Ótimo desempenho.
- Excelente para parsers, codecs e renderização.

[Open Source Symbolism: Exploring the Stories Behind Project Mascots and Logos](https://images.openai.com/static-rsc-4/P8j3pmjZ4_ubYvtsDkGxD-OJviz3zwWNZ6OKkhCV07lIukwEI6vnhP5iK_Y6fpkLV_jIMUQFyOV1MfUbRAkx5rMsvCNxKHTWsy2ztGFou8y7bvrIlnCyO8baP4SBAKlOYZFzkWuKNLfb9EYfuICAhGmyOpt1f07o_lVLCyj3q8s?purpose=inline)

**Go**

Excelente para ferramentas e serviços

- Concorrência simples.
- Desenvolvimento rápido.
- Boa portabilidade.
- Excelente para serviços de rede.
- Garbage collector e runtime próprios.

Minha avaliação:

| Requisito                     | Rust      | Go                |
| ----------------------------- | --------- | ----------------- |
| Performance de baixo nível    | Excelente | Muito boa         |
| Controle de memória           | Excelente | Gerenciado        |
| Segurança de memória          | Excelente | Excelente         |
| Integração C ABI              | Boa       | Possível, com cgo |
| Binário independente          | Sim       | Sim, com runtime  |
| Desenvolvimento de protocolos | Excelente | Excelente         |
| Embedded / sistemas           | Excelente | Mais limitado     |
| Bibliotecas nativas           | Excelente | Muito boa         |

**Eu escolheria Rust para a implementação de referência.**

Não porque Go seja lento. Não é. Mas porque o OpenVNC terá operações sensíveis a desempenho: decodificação gráfica, manipulação de framebuffer, compressão, transporte e processamento de eventos.

Rust oferece um controle muito interessante nesses componentes.

# **3. A decisão mais importante: independência de linguagem**

Aqui está o segredo para o OpenVNC ser realmente universal.

**Não devemos criar uma biblioteca Rust e depois tentar adaptá-la para outras linguagens. Devemos criar um protocolo independente de linguagem e uma API universal.**

Eu dividiria isso em três interfaces.

## **OpenVNC Universal Architecture**

**OpenVNC Protocol Specification**

Documentação independente de linguagem, formatos binários e regras de comunicação

**OpenVNC Core — Rust**

Implementação de referência

Performance Engine

**OpenVNC C API / ABI**

Interface binária estável e documentada

C / C++

Go

Python

Java

C#

Node.js

PHP

Swift

Kotlin

### **Camada 1 — Protocol Specification**

Essa é a especificação pública.

Qualquer desenvolvedor poderá implementar o protocolo sem utilizar nosso código Rust.

Por exemplo, alguém poderá criar um servidor OpenVNC inteiramente em Go, enquanto outro desenvolvedor cria um cliente em C++.

Os dois funcionarão porque obedecem à mesma especificação.

### **Camada 2 — Core Library**

Nossa implementação oficial será escrita em Rust.

Ela fornecerá:

- Parser e serializador.
- Handshake.
- Autenticação.
- Transporte.
- Framebuffer.
- Encodings.
- Eventos de teclado e mouse.
- Gerenciamento de sessões.

### **Camada 3 — C ABI**

Essa é a ponte universal.

Rust permite expor funções através da convenção `extern "C"`, com estruturas compatíveis usando `#[repr(C)]`.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://doc.rust-lang.org&sz=32)

The Rustonomicon+1

Isso permite criar uma biblioteca compartilhada:

- Windows: DLL.
- Linux: SO.
- macOS: DYLIB.

As outras linguagens poderão consumir essa biblioteca por meio de bindings.

**Uma regra:** nunca expor diretamente estruturas internas de Rust, `String`, `Vec`, traits ou tipos específicos da linguagem. A interface pública terá handles opacos, tipos de tamanho fixo, buffers explícitos, callbacks e códigos de erro.

Também teremos uma API versionada, para que futuras versões não quebrem integrações existentes.

## **4. Como outras linguagens utilizarão o OpenVNC?**

Exemplo conceitual de como um desenvolvedor consumiria a API:

| Linguagem | Integração             |
| --------- | ---------------------- |
| C         | Header oficial         |
| C++       | Wrapper RAII           |
| Go        | cgo ou binding próprio |
| Python    | ctypes / cffi          |
| Java      | JNI / JNA              |
| C#        | P/Invoke               |
| Node.js   | N-API                  |
| PHP       | FFI                    |
| Swift     | C interop              |
| Kotlin    | JNI                    |

A implementação em Rust será consumida por todas essas linguagens sem que precisemos reimplementar o motor gráfico em cada uma.

Go também consegue produzir bibliotecas compartilhadas com integração C, embora isso envolva cgo e algumas limitações de distribuição.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://doc.rust-lang.org&sz=32)

The Rustonomicon+1

### **Mas há uma diferença importante**

Precisamos oferecer dois caminhos:

1. **SDK:** para quem quer incorporar a biblioteca OpenVNC em sua aplicação.
2. **Protocolo:** para quem quer implementar seu próprio cliente ou servidor sem depender da nossa biblioteca.

Isso é o que torna o projeto verdadeiramente independente de linguagem.

# **5. O protocolo precisa ser independente da implementação**

Eu criaria uma especificação própria, mas manteria o RFB como primeiro protocolo de interoperabilidade.

O documento RFC 6143 descreve o funcionamento do RFB, incluindo handshake, formatos de pixels, encodings e extensões. É nossa principal referência para implementar a compatibilidade sem copiar código de terceiros.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.rfc-editor.org&sz=32)

RFC Editor+1

Minha proposta seria:

| Componente         | Nome             |
| ------------------ | ---------------- |
| Protocolo legado   | RFB              |
| Novo protocolo     | OpenVNC Protocol |
| Biblioteca oficial | OpenVNC Core     |
| API universal      | OpenVNC ABI      |
| Cliente oficial    | OpenVNC Client   |
| Servidor oficial   | OpenVNC Server   |
| Ferramentas        | OpenVNC Tools    |

Eu evitaria misturar o RFB com o protocolo novo.

O OpenVNC Protocol deve ter versão própria, negociação de capacidades, mensagens bem definidas e transporte independente.

### **Requisitos da especificação**

- Big Endian para campos numéricos.
- Identificadores de mensagens documentados.
- Limites explícitos de tamanho.
- Negociação de versões e capacidades.
- Compatibilidade entre versões.
- Criptografia obrigatória no transporte moderno.
- Formatos de dados independentes de arquitetura.
- Tratamento padronizado de erros.
- Testes de conformidade públicos.

A especificação deve permitir que uma implementação em Go e outra em Rust troquem mensagens e executem a mesma sessão sem diferenças de comportamento.

# **6. Estrutura recomendada do GitHub**

Eu organizaria o projeto desde o início como um monorepo.

```
openvnc/
│
├── README.md
├── LICENSE
├── NOTICE
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── GOVERNANCE.md
│
├── specification/
│   ├── protocol/
│   │   ├── overview.md
│   │   ├── handshake.md
│   │   ├── transport.md
│   │   ├── authentication.md
│   │   ├── graphics.md
│   │   └── compatibility.md
│   │
│   ├── abi/
│   │   └── c-api.md
│   │
│   └── RFC/
│
├── core/
│   ├── crates/
│   │   ├── openvnc-core/
│   │   ├── openvnc-rfb/
│   │   ├── openvnc-protocol/
│   │   ├── openvnc-transport/
│   │   ├── openvnc-security/
│   │   ├── openvnc-codecs/
│   │   ├── openvnc-framebuffer/
│   │   └── openvnc-ffi/
│   │
│   └── Cargo.toml
│
├── bindings/
│   ├── c/
│   ├── cpp/
│   ├── go/
│   ├── python/
│   ├── java/
│   ├── csharp/
│   ├── nodejs/
│   └── swift/
│
├── clients/
│   ├── desktop/
│   ├── web/
│   └── cli/
│
├── servers/
│   └── reference/
│
├── examples/
│   ├── c/
│   ├── go/
│   ├── python/
│   └── nodejs/
│
├── conformance/
│   ├── protocol-tests/
│   ├── interoperability/
│   └── fuzzing/
│
└── .github/
    ├── workflows/
    ├── ISSUE_TEMPLATE/
    └── PULL_REQUEST_TEMPLATE.md
```

Essa estrutura permite que a comunidade contribua em áreas independentes.

Por exemplo, alguém pode desenvolver o binding Python sem precisar modificar o núcleo Rust.

# **7. Como manter o projeto verdadeiramente comunitário?**

Eu adotaria algumas regras desde o primeiro dia.

**Governança:**

- Desenvolvimento público.
- Roadmap público.
- Discussões técnicas via GitHub Discussions.
- RFCs para mudanças importantes no protocolo.
- Pull Requests obrigatórios.
- Revisão por pelo menos outro mantenedor.
- Releases assinadas.
- Versionamento semântico.
- Política de segurança para vulnerabilidades.

**Contribuições:**

Minha escolha seria utilizar DCO (_Developer Certificate of Origin_) em vez de exigir um CLA complexo de todos os contribuidores.

O DCO permite que cada desenvolvedor certifique a origem e os direitos de suas contribuições usando o `Signed-off-by` nos commits.

Isso reduz a burocracia para uma comunidade aberta.

Também criaria uma política de dependências: nenhuma biblioteca será incorporada sem verificar sua licença, manutenção e vulnerabilidades.

# **8. Metas técnicas do OpenVNC**

Eu estabeleceria os seguintes objetivos:

| Pilar              | Objetivo                                 |
| ------------------ | ---------------------------------------- |
| Performance        | Baixa latência e processamento eficiente |
| Segurança          | Criptografia moderna e memória segura    |
| Portabilidade      | Windows, Linux e macOS                   |
| Interoperabilidade | Implementações em qualquer linguagem     |
| Compatibilidade    | RFB 3.3, 3.7 e 3.8                       |
| Extensibilidade    | Novos codecs e transportes               |
| Independência      | Sem serviço central obrigatório          |
| Comunidade         | Desenvolvimento aberto e documentado     |

Uma observação: compatibilidade com RFB não significa automaticamente compatibilidade com extensões proprietárias de todos os fabricantes. Teremos uma matriz de conformidade e testes reais.

# **9. Minha decisão final para o OpenVNC**

# **OpenVNC**

Proposed Technical Foundation

Licença

**Apache-2.0**

Core

**Rust**

ABI universal

**C ABI**

Protocolo legado

**RFB**

Protocolo moderno

**OpenVNC Protocol**

Especificação

**Language Agnostic**

Governança

**Community-driven / DCO**

Repositório

**Monorepo**

**Princípio fundamental**

Qualquer desenvolvedor poderá implementar o OpenVNC em qualquer linguagem, sem depender da implementação oficial em Rust.

## **10. Próximo passo: fundação oficial do projeto**

Antes de começar a programar, eu criaria os documentos fundacionais:

1. `README.md` — apresentação e visão do OpenVNC.
2. `ARCHITECTURE.md` — arquitetura geral.
3. `PROTOCOL.md` — princípios e estrutura do protocolo.
4. `SECURITY.md` — modelo de segurança.
5. `GOVERNANCE.md` — governança comunitária.
6. `CONTRIBUTING.md` — como contribuir.
7. `LICENSE` — Apache 2.0.

Minha sugestão é não começar escrevendo milhares de linhas de Rust. Primeiro estabelecemos o contrato que todas as implementações deverão obedecer.

**O verdadeiro sucesso do OpenVNC será quando alguém conseguir escrever um servidor em Go, um cliente em Python e uma biblioteca em C++, e todos conversarem perfeitamente.**

Esse é o tipo de projeto que pode se tornar infraestrutura para muitos outros softwares.

Uma última coisa: antes de publicar, vale verificar a disponibilidade do nome OpenVNC como marca e organização GitHub. O nome do projeto e o direito de usar uma marca são questões diferentes da licença do código.

Com tudo isso, monte uma arquitetura funcional! pensando que será implementado em RUST o server! o CLIENT faremos depois, foque no server\![$pesquisa-aprofundada](app://connector_openai_deep_research)&#x20;

# Arquitetura do Servidor OpenVNC em Rust

**OpenVNC** é um projeto de acesso remoto open-source comunitário, com o servidor escrito em Rust, licenciado Apache-2.0. O servidor deverá atender clientes VNC/RFB legados (RFC 6143) e futuramente o protocolo nativo OpenVNC sobre QUIC. Os objetivos incluem compatibilidade com VNC existente, segurança moderna, alto desempenho e portabilidade multiplataforma. Como requisitos funcionais, o servidor deve aceitar múltiplos clientes concorrentes, suportar telas multi-monitor e DPI variável, e permitir controle remoto (teclado, mouse) seguro. Requisitos não funcionais incluem baixa latência, uso eficiente de CPU/memória (por exemplo, evitando cópias desnecessárias de buffer), e robustez contra erros. Devemos considerar ameaças como ataques man-in-the-middle na conexão, injeção de dados maliciosos pelo cliente (protocolo malformado), ou abuso de recursos (DoS por flood de FramebufferUpdates). As fronteiras de confiança são claras: o servidor confia apenas no kernel e bibliotecas seguras de Rust para operar, toda entrada do cliente deve ser validada, e o transporte moderno (TLS/QUIC) providencia confidencialidade e integridade.

## Visão Geral da Arquitetura

O servidor OpenVNC terá componentes principais:

- **RFB Legacy Server**: socket TCP (porta 5900) que implementa o handshake e mensagens RFB (versões 3.3, 3.7, 3.8) conforme RFC 6143. Aceita os encodings de vídeo/retângulo legados (Raw, CopyRect, Hextile, ZRLE, etc.) e eventos de entrada do cliente (teclado, mouse) seguindo o formato especificado no RFC. O fluxo básico é: conexão TCP → Negociação de versão e modos de segurança (por exemplo, “None” ou VNC Auth) → ClientInit (flag _shared_) → ServerInit (largura, altura, formato de pixel) → loop de **FramebufferUpdateRequest** e **FramebufferUpdate**. Se o cliente pedir atualização completa (`incremental=0`), o servidor envia todo o framebuffer; se incremental (`=1`), envia somente regiões modificadas (dirty rectangles). O servidor deve responder apenas após receber uma requisição, regulando o envio de retângulos para não sobrecarregar clientes lentos.

- **OpenVNC Native Server**: (planejado) um servidor separado, em outra porta (por exemplo, UDP sobre QUIC), que usa o _novo protocolo_ OpenVNC. Ele incluirá handshake próprio e trocas de mensagens definidas, transportadas sobre QUIC (via _quinn_) ou TCP+TLS. O design desse protocolo nativo definirá mensagens de controle, atualização de vídeo (possivelmente frames de codec H.264/AV1), e eventos de input, tudo com criptografia e autenticação embutidas.

- **Módulos Compartilhados**: lógica comum usada por ambos os modos. Isso inclui a **camada de captura de tela**, que abstrai APIs do SO para obter pixels da tela; a **camada de injeção de input**, que transforma eventos RFB em eventos de teclado/mouse no sistema operacional; e o **core de encodings**, para compressão de retângulos. Também haverá biblioteca de transporte genérica (_openvnc-transport_) que gerencia conexões TCP/TLS (usando _tokio_ e _rustls_) e conexões QUIC (usando _quinn_).

- **Controle do Processo**: o servidor escutará conexões de rede, e para cada cliente criará uma tarefa assíncrona (tokio) isolada. Cada sessão de cliente manterá seu estado (e.g. tela anterior para diff, modo compartilhado/exclusivo, permissões). Haverá um componente central para captura contínua da tela (talvez em thread/tarefa separada) que disponibiliza os frames atuais para todas as sessões. A sincronização entre captura e envio de frames será feita via canais MPSC _async_ ou estruturas semelhantes, evitando bloqueio de I/O.

Em termos de implantação (_deployment_), o servidor será executável multiplataforma (Windows, Linux, macOS) e configurável. Por padrão, escutará na porta TCP 5900 para RFB, podendo ter opção de habilitar QUIC em outra porta. Poderá ser executado como serviço ou em sessão gráfica, mas observando limitações de permissões de captura/injeção.

## Modularização em Rust e Crates

A organização proposta é um workspace Cargo com crates separados por responsabilidade. Exemplos de crates (nomes ilustrativos):

- **openvnc-server-core**: definirá os modelos de dados centrais (por exemplo, `PixelFormat`, `Rectangle`, estruturas de Framebuffer), e componentes independentes de transporte (como utilitários de buffers, logging, métricas).
- **openvnc-server-rfb**: implementa o protocolo RFB segundo RFC 6143. Inclui o parser do handshake (versões 3.3/3.7/3.8), autenticação VNC (DES, se habilitado), o state machine de mensagens, e os encodings suportados. Funções como `handle_framebuffer_update_request()` decidem quais retângulos enviar, usando os encoders (Raw/Hextile/ZRLE). Também contém suporte a pseudo-encodings (e.g. Cursor e DesktopSize) conforme a especificação.
- **openvnc-server-native**: esboço do protocolo nativo OpenVNC. Contém definição de mensagens de aplicação (handshake, autenticicação moderna, atualização de frames, controle) e sua (des)serialização. Por exemplo, estruturas para `ClientHello`, `ServerHello`, `FrameUpdate`, etc., com versionamento e flags de capacidades. Essa crate seria utilizada no caminho QUIC/TLS.

- **openvnc-transport**: abstrai a camada de rede. Implementa listeners TCP e UDP, com suporte a _tokio_ (async). Integra _rustls_ para TLS/1.3 em conexões TCP, e _quinn_ para QUIC. Fornece conexões simplificadas para os módulos RFB e nativo se comunicarem (por exemplo, encadeando QUIC streams ou conexões TLS).

- **openvnc-screen**: abstração para captura de tela. Define trait(s) como:

  ```rust
  pub trait ScreenCapture {
      /// Captura o próximo frame da tela principal, retornando os pixels.
      fn capture_frame(&mut self) -> Result<ScreenFrame>;
      /// Lista dispositivos/monitores disponíveis.
      fn list_displays(&self) -> Vec<DisplayInfo>;
      /// Opcionalmente, detecta mudanças (XDamage ou similar).
  }
  ```

  Cada plataforma terá uma implementação: no Windows, usando **Desktop Duplication API** (via DXGI ou _Windows.Graphics.Capture_); no Linux/X11, usando XCB/X11+SHM ou extensões de Damage (scrap crate usa XCB+SHM+RandR); em Wayland, usando PipeWire ou xdg-desktop-portal (scrcap/PipeWire) se disponível. No macOS, usando CoreGraphics/Quartz (p.ex. ScreenCaptureKit). Essas implementações podem usar crates como _scrap_ ou _scrcap_; importante notar que no Linux _scrap_ requer XCB e RandR, enquanto _scrcap_ recorre a PipeWire (requer headers PipeWire em runtime). O crate define buffers de pixel (`ScreenFrame`) em formatos padrão (p.ex. BGRA8) para depois repassar ao encoder RFB.

- **openvnc-input**: abstração para injetar eventos de teclado/mouse no SO. Define trait como:

  ```rust
  pub trait InputInjector {
      fn inject_key(&self, key: KeySym, down: bool) -> Result<()>;
      fn inject_pointer(&self, x: u16, y: u16, buttons: u8) -> Result<()>;
  }
  ```

  Implementações usarão bibliotecas como _rdev_ ou _enigo_, ou APIs nativas (Windows: SendInput; X11: XTest/FakeInput; Wayland: se for possível via portal; macOS: CGEventPost). A crate pode envolver gatilhos de privilégios – por exemplo, no Linux pode exigir que o processo seja root ou faça parte do grupo `input` para emular eventos globais. Note que _rdev_ só funciona em X11 e alerta que em Wayland é necessário rodar como root ou grupo `input`.

- **openvnc-config**: trata carregamento de arquivo de configuração (por exemplo, TOML). Define parâmetros como `listen_addr`, `tls_cert_path`, modos de autenticação permitidos, limites (max clientes), etc., com valores padrão seguros. Poderia usar crates como _config_ ou _serde_.

Cada crate terá testes próprios. Por exemplo, _openvnc-server-rfb_ terá testes unitários para parsing de mensagens RFB (e.g. comparando bytes exemplo com estruturas), e testes de propriedade/fuzzing em parsers. _openvnc-screen_ terá testes de integração simulada usando backend dummy.

## Abstrações de Plataforma e Limitações

A captura e injeção precisam lidar com peculiaridades dos sistemas operacionais:

- **Windows**: o servidor precisará rodar em uma sessão de usuário com acesso à GUI. Para captura, usar _Desktop Duplication API_ (requires Windows 8+) ou _GDI BitBlt_ como fallback. Para injeção, _SendInput_ funciona mas pode ser bloqueado por UAC ou Secure Desktop. Em hardware múltiplos monitores, Desktop Duplication já lida com telas estendidas. Atenção às DPI/escala – a API retorna pixéis físicos, de forma nativa. No Windows, podemos usar _winrt_ ou _windows-rs_.
- **Linux (X11)**: ao usar X11, podemos utilizar XGetImage ou XShm para capturar, e XDamage para mudar apenas partes que mudaram. Ou usar o XRecord (mais antigo). Para entrada, X11 oferece XTestFakeKeyEvent/XTestFakeButtonEvent. Isso requer conexão X válida (ou DISPLAY=...). Em distribuições usando Wayland, X11 clássico pode não estar presente ou ser inseguro. O Linux moderno preferencialmente usaria PipeWire (via _scrcap_) para captura e libinput/uinput para injetar. Porém, no X11 puro: _rdev_ e _scrap_ funcionam em X11, mas _rdev_ não detecta em Wayland. Em Wayland puro, não existe API global de captura/injeção; uma abordagem é usar **xdg-desktop-portal** para o usuário aprovar a captura de tela, e _uinput_ para injetar se o compositor permitir. Importante: o servidor pode precisar ser executado como root ou ter capacidades elevadas para criar dispositivos virtuais (ex: /dev/uinput).
- **macOS**: requer permissão de “Screen Recording” e “Accessibility” para que o aplicativo acesse a tela ou injete eventos. Captura pode usar _CGDisplayStream_ (macOS 10.15+) ou _CGWindowListCreateImage_. Injeção usa _Quartz Event Services_ (CGEventPost). A crate _rdev_ lida em parte com Mac (precisa adicionar terminal em Accessibility). Tela Retina (alta DPI) retornará quadros de alta resolução, ajustes de escala podem ser necessários.

- **DisplayTopology**: o servidor deverá consultar o arranjo de monitores (resoluções, offsets) – no Windows via API Win32 (EnumDisplayMonitors), no Linux via RandR ou PipeWire, no macOS via NSScreen. Isso permite compor um framebuffer único que inclua todos. Mudanças em hot-plug (monitor plug/unplug) devem enviar pseudo-encoding _DesktopSize_ (código -223) ao cliente para reajustar janela.

## Pipeline de Captura e Rendering

O servidor captura quadros completos da tela em um loop (por exemplo, 30-60 FPS) ou usando detecção de mudança. O pipeline típico:

1. **Obtenção do frame**: a implementação de `ScreenCapture` fornece um `ScreenFrame` contínuo da tela (por exemplo, em formato BGRA ou ARGB). Cada frame contém `width×height` pixels.

2. **Detecção de mudanças**: podemos comparar o novo frame com o anterior para identificar retângulos “sujos” (dirty). Ex.: calcular bounding box por diferença de pixels. Em X11, a extensão XDamage pode informar regiões alteradas para evitar capturar tudo repetidamente. Em Windows/DirectX, é possível obter apenas partes atualizadas (Desktop Duplication sinaliza áreas alteradas). Em Wayland/PipeWire, recebemos cada frame completo; então fazemos diff.

3. **Atualização do framebuffer**: o servidor mantém um _framebuffer mestre_ que reflete o estado atual mostrado aos clientes. Quando detectar mudanças, aplica ao framebuffer e marca rects.

4. **Renderização para o cliente**: ao receber um `FramebufferUpdateRequest` de um cliente (incremental ou full), calcula os retângulos a enviar. Para cada retângulo, escolhe um **encoding**. Exemplos:
   - **Raw** (cópia bruta) – envia pixels sem compressão (compatível universal).
   - **CopyRect** – se partes da tela foram movidas (janelas arrastadas), reutiliza dados de regiões existentes.
   - **Hextile** – subdivide retângulo em tiles e aplica RLE interno (bom para áreas de cor uniforme).
   - **ZRLE** – subdivide em tiles, aplica Zlib + RLE (bom para fotos ou imagens).
   - (Opcional) **TRLE** (Tight RLE) – codificação RLE de byte stream, usado por alguns servidores para VNC mais antigo; porém RRE e TRLE são obsoletos em 3.8.

   O cliente terá enviado uma lista de encodings suportados (via `SetEncodings`), então só usamos os compatíveis. Geralmente usamos ZRLE para fotos, Hextile para áreas bem divididas, CopyRect para movimentos simples. O servidor deve assegurar o payload não excede limites (por exemplo, cada tile decodificável pelo cliente).

5. **Cursor independente**: idealmente, tratamos o cursor do mouse separadamente. RFB permite envio de pseudo-encoding _Cursor_ (−239) para atualizar somente o ponteiro, poupando largura de banda. Podemos, por exemplo, não capturar o cursor no _framebuffer_ principal e, em vez disso, enviar sua imagem e posição via esse encoding. Isso evita duplicar o cursor nos updates.

6. **Múltiplos monitores**: o framebuffer pode englobar vários monitores lado a lado. Se o layout mudar (usuário conecta um monitor, redimensiona telas), o servidor envia um update _DesktopSize_ (pseudo-encoding −223) com a nova largura/altura totais, e realiza um novo `ServerInit`. Na prática, muitos servidores simplesmente reiniciam a sessão ou usam o pseudo-encoding _ExtendedDesktopSize_. O cliente ajusta sua viewport.

7. **Sincronização**: caso vários clientes estejam conectados, o servidor usará o mesmo fluxo de frames para todos. Poderá manter tarefas independentes de escrita nos sockets de cada cliente. Se um cliente estiver lento (latência alta), podemos descartar atualizações muito antigas (backpressure). Por exemplo, manter um buffer circular limitado de _requests_ de FramebufferUpdate para evitar enfileirar horas de dados. Uma estratégia comum é sempre enviar o frame mais recente disponível quando o cliente pede, ignorando frames intermediários.

## Pipeline RFB (Legado, RFC 6143)

Implementar um servidor RFB implica seguir o handshake e formatos de mensagens do RFC 6143:

1. **Handshake de versão**: ao conectar (TCP), o servidor envia sua versão de protocolo em ASCII: `"RFB 003.008\n"` (para RFB 3.8) ou outra versão compatível. O cliente responde da mesma forma. Exemplo: o servidor aceita conexões 3.3–3.8; se o cliente usar versão desconhecida, tratamos como 3.3 (RFC recomenda).

2. **Tipos de segurança**: o servidor envia `uint8 nTypes` e então lista os tipos suportados. Normalmente:
   - `None (1)`: sem autenticação – permitido mas inseguro (todos podem conectar).
   - `VNC Authentication (2)`: baseada em DES de chave de 8 bytes (senha). O servidor envia 16 bytes aleatórios, cliente criptografa com DES e retorna; depois envia `SecurityResult`.
     (Tipos extras, como VeNCrypt/TLS, são opcionais mas complicam interoperabilidade, já que poucos clientes suportam. A RFC alerta que a autenticação DES é **fraca** e não protege contra ataques ativos; recomenda-se uso de túnel seguro por SSH/IPsec externo.)

3. **SecurityResult**: após o handshake acima, o servidor envia 4 bytes: status 0=OK ou 1=failed, possivelmente com mensagem de erro. Se OK, procede. (Caso falhe, fecha a conexão.)

4. **ClientInit**: cliente envia 1 byte _shared-flag_: non-zero para permitir compartilhamento da sessão com outros clientes conectados, zero para exclusividade (desconectar outros). O servidor deve respeitar esse flag; se não suportar multi-usuário, pode ignorar ou forçar exclusividade.

5. **ServerInit**: o servidor responde com: 2 bytes largura, 2 bytes altura, 16 bytes `PIXEL_FORMAT`, 4 bytes tamanho do nome, seguido do nome-do-desktop (ex. `"OpenVNC Server"`). O `PIXEL_FORMAT` define a profundidade de cores (ex. 32 bpp, true-color), e será o formato natural do servidor (o cliente pode solicitar outro via SetPixelFormat). Estrutura de PIXEL_FORMAT (16 bytes) segundo RFC:

   ```
   bits-per-pixel, depth, big-endian-flag, true-color-flag, red-max, green-max, blue-max, red-shift, green-shift, blue-shift, padding(3).
   ```

   Essa formatação deve ser enviada fielmente.

6. **Negociações adicionais**:
   - **SetPixelFormat**: o cliente pode enviar esse comando para pedir um formato de pixel diferente. O servidor deve converter os frames (por exemplo, de BGRA para RGB888) antes de enviar. É opcional implementar todos os formatos; pelo menos `true-color` deve ser suportado.
   - **SetEncodings**: o cliente informa quais encodings aceita. O servidor usará somente esses.

7. **Loop Principal**: o cliente envia mensagens de controle:
   - **FramebufferUpdateRequest (type 3)**: solicita áreas atualizadas (full ou incremental). Tabela RFC: `type=3`.
   - **PointerEvent (type 5)**: contém máscara de botões e posição (x,y). O servidor converte isto em eventos locais. Botões: bit 0=left, 1=middle, 2=right, mais para scroll (bits 3/4).
   - **KeyEvent (type 4)**: tecla pressionada ou solta. O servidor mapeia o código para KeySym e injeta.
   - **ClientCutText (type 6)**: cliente colou texto local. Pode ser ignorado (no MVP), ou repassado à área de transferência do servidor.

   O servidor responde principalmente com **FramebufferUpdate (type 0)** contendo retângulos para o FramebufferUpdateRequest. Outros mensagens de servidor incluem _SetColorMapEntries_ (não usado em true-color), _Bell_, _ServerCutText_ (copiar texto do servidor pro cliente), e _Cursor_ pseudo-encoding. Cada retângulo na FramebufferUpdate tem x,y,largura,altura e encoding. Ver RFC 7.6.1 para o formato (header + seq. de retângulos).

8. **Encodings e Compressão**: o servidor deve implementar pelo menos Raw, CopyRect, Hextile e ZRLE. O RFC observa que RRE e Hextile são **obsoletos** (ZRLE/TRLE dão compressão melhor). Em prática, usar ZRLE (codificação zlib+RLE) para imagens/gif, e CopyRect para arrastar janelas. A tabela RFC inclui pseudo-encodings _Cursor_ (−239) e _DesktopSize_ (−223). Validar todos os valores de encoding e tamanho antes de enviar para não corromper cliente.

9. **Segurança do Canal RFB**: por padrão, a conexão RFB+TCP não criptografa. Por isso **não confiamos na privacidade** do canal. O servidor deve logar ou avisar que é inseguro, e recomendar uso de SSH/VPN ou TLS externo. Se for incluir TLS (VeNCrypt), deve-se usar apenas implementações padronizadas. Mas cuidado: a maioria dos clientes “legados” (TigerVNC, RealVNC, TightVNC) não suportam VeNCrypt ou SASL; portanto a compatibilidade completa 100% é improvável. Uma meta razoável é conformidade com _RFC 6143 e extensões públicas_ (excluindo variantes proprietárias ou obsoletas).

Em suma, o **servidor RFB** em Rust seguirá rigorosamente o protocolo descrito, usando estruturas binárias _#[repr(C)]_ ou métodos de leitura de buffers (`tokio::io::AsyncReadExt`) para o handshake e mensagens. Todo o parsing deve verificar limites (e.g. não aceitar largura de frame absurda, não permitir valores negativos, testar falhas DES, etc.) para evitar vulnerabilidades. Como nota de segurança, o próprio RFC alerta que a autenticação VNC clássica é **fraca** e “não foi projetada para redes não confiáveis”, recomendando fortemente o uso de canais encriptados sobre o protocolo.

## Transporte

- **RFB Clássico (TCP/TLS)**: o servidor escuta TCP (porta 5900 por padrão). Pode opcionalmente suportar TLS 1.3 (usando _rustls_) para proteger o protocolo RFB clássico, mas isso **não é comum** em clientes legados – nem RealVNC nem TigerVNC habilitam TLS por padrão. Se implementado (via extensão VeNCrypt/RFC 6143 SecType 256 ou similar), deve usar bibliotecas seguras como _rustls_. Como alternativa, recomenda-se que o próprio administrador estabeleça túnel SSH/VPN. O servidor _não deve_ tentar falar QUIC numa conexão TCP/RFB, pois os clientes RFB não entendem.

- **Protocolo OpenVNC (QUIC/TLS)**: paralelo ao TCP, o servidor terá um listener QUIC (UDP) usando o _quinn_. Todas as mensagens do novo protocolo serão enviadas nesse canal. O _quinn_ fornece TLS1.3 integrado e streams bidirecionais. Planeja-se usar múltiplos streams: por exemplo, um stream para controle, um para vídeo, outro para entrada, etc. Em caso de bloqueio de UDP, pode-se ter fallback opcional a TCP+TLS no protocolo OpenVNC. O ponto-chave é **não conectar ambos os protocolos**: ou a sessão é RFB sobre TCP, ou OpenVNC sobre QUIC. O servidor configura certificados TLS (preferencialmente de CA reconhecida) para autenticar. Evitar downgrade: se um cliente OpenVNC esperar QUIC e o servidor responder só RFB, ele deve falhar.

## Protocolo Nativo OpenVNC (futuro)

O protocolo nativo (sob QUIC) ainda será definido, mas alguns pontos principais:

- **Handshake seguro**: ao conectar via QUIC, negociar versão do protocolo (ex.: OpenVNC v1.0), autenticação de usuário (certificados mTLS ou outro esquema). Por exemplo, mensagens `CLIENT_HELLO` e `SERVER_HELLO` podem trocar capacidades e métodos de autenticação. A segurança de canal é garantida pelo próprio QUIC/TLS, então não precisamos criptografar conteúdo extra.

- **Mensagens e formatos**: definir mensagens como _FrameUpdate_ (com id, timestamp, dados de quadro ou referências a stream de vídeo), _InputEvent_ (formato similar a RFB mas possivelmente com extensões para toque ou gestos), _StreamControl_, _ClipboardData_, etc. Cada tipo deve ter header (código, tamanho, flags) e payload. Campos numéricos em Big Endian, alinhamentos claras, e limites impostos (por exemplo, tamanho máximo de imagem, testes de overflow). É crucial projetar o protocolo para evolução: incluir campo `version` em mensagens críticas e permitir extensão.

- **Negociação de capacidades**: logo no início, o cliente e servidor trocam quais recursos suportam (ex.: “suporta múltiplos monitores”, “suporta codec H.264”, “suporta transferência de arquivos”). Isso evita que enviemos dados que o receptor não entende.

- **Fluxo de vídeo**: para cenários de vídeo ou animação, poderíamos usar streams dedicados com codecs (H.264/AV1). O servidor poderia enviar dados codificados em tempo real; o cliente renderiza. Esse mecanismo seria complementar aos encodings de retângulos (que continuam disponíveis).

- **Controle de fluxo**: se o cliente ficar lento, ele deve poder pausar ou descrever quantidade de dados que consegue processar. Talvez haver fluxo bidirecional de controle de congestionamento (mas QUIC já faz isso no nível de transporte).

Essa especificação nativa será formalizada em documento próprio, com análise de segurança e modelos de ameaça antes de ser fixada (um tipo de RFC interno). Mas em todos os casos, **não** inventaremos criptografia própria – usaremos TLS/QUIC para confidencialidade e confiança.

## Autorização e Segurança

- **Autenticação de usuário**: Por padrão, o servidor pode usar _None_ ou senha simples (não recomendado). Idealmente, integrar com usuários do sistema (p.e., PAM no Linux) ou chaves públicas. Em ambientes corporativos, autenticação multifator pode ser anexada. Para RFB, podemos implementar um mecanismo simples de senha (semcriptografia DES) mas encorajar _DesktopSize_ encurtado: preferível usar TLS com login separado. Com QUIC, usaríamos certificados ou tokens.

- **Permissões**: Diferenciar visualização (apenas ver tela) de controle (poder clicar/escrever). Isso pode ser negociado na autenticação (usuário “viewer” vs “operator”). Sem consentimento ativo do usuário local, idealmente o servidor não controla sem um prompt. Poderíamos fornecer uma opção interativa (como o [“Allow…”](https://tools.ietf.org/html/rfc4535) do VNC Group).

- **Proteção de recursos**: limite max conexões por IP, throttle de eventos de input (para evitar DoS). Logs de auditoria: registrar conexões, desconexões, falhas de login, comandos especiais. Não se armazena senhas em texto.

- **Firewall e exposição**: aconselhar que o servidor fique atrás de firewall ou só em localhost por padrão, e o administrador abra portas explicitamente. O daemon pode ouvir apenas em `127.0.0.1` por padrão (exigindo SSH/VPN para acesso externo), a menos que configurado para todas interfaces.

## Performance

Para alta performance, usaremos _tokio_ (async Rust) e recursos de baixo nível do Rust:

- **Concorrência**: uma _Task_ tokio por cliente, com um _MPSC channel_ para receber frames do capturador. O capturador de tela pode ser uma _task_ independente que periodicamente (ou reativamente) envia frames novos a um broadcaster. Encoding de cada retângulo pode ser feita em paralelo (e.g. blocos de ZRLE em threads diferentes) se necessário.

- **Evitar cópias**: a captura retorna um buffer de bytes (por exemplo, `Vec<u8>` ou slice). Sempre que possível, comprimir esse buffer diretamente (ZRLE) sem copiar. Reaproveitar buffers (`Vec`) com _capacity_ suficiente para o tamanho da tela evita alocação contínua. Por exemplo, Scrap fornece `Frame` que já gerencia a memória; podemos converter/colar direto no encoder.

- **Pool de threads**: tokio nativamente gerencia threads, mas para operações pesadas de CPU (compressão), podemos usar `spawn_blocking` ou um pool dedicado. Opcionalmente, usar _rayon_ para tarefas paralelas (como compressão de tiles).

- **GPU**: como servidor, normalmente não codificamos vídeo com GPU. Mas se necessário no futuro, poderíamos usar APIs como NVENC (via biblioteca) para transmissões de vídeo. No MVP, usaremos CPU.

- **Controle de taxa**: permitir limitar FPS ou taxa de dados, por configuração. E.g., se rede ou cliente não suportam 60 FPS, cair para 30 FPS.

- **Medições**: estabelecer benchmarks (ex: medir latência de round-trip de frame, throughput bytes/s) em máquinas padrão. Por exemplo, metas iniciais: 1080p a 30 FPS sem ultrapassar 20% de CPU em hardware comum.

## Observabilidade

- **Logs estruturados**: usar crates como _tracing_ para eventos (conexão iniciada, cliente autenticado, erros). Em produção, logs no nível _info/warn/error_; _debug_ para desenvolvimento. **Nunca logar** senhas ou dados de tela do usuário.

- **Métricas**: expor contadores (clients ativos, bytes transmitidos, frames enviados) via Prometheus ou similar. Latência de solicitação por cliente. Número de falhas de autenticação.

- **Tracing/diagnóstico**: em caso de falha, derrubar o servidor mostra stack trace (Rust panic tem boa mensagem), mas melhor capturar e registrar. Integrar handlers globais de panic para logar antes de shutdown.

- **Crash handling**: Rust evita segfaults, mas devemos validar inputs para não `unwrap()` indevidamente. Uso de `#[cfg(debug_assertions)]` para checks extras durante desenvolvimento.

## Testes e Conformidade

- **Unitários**: funções de parser RFB (interpretar bytes), encoders (verificar saída contra exemplos fixos), conversão de pixel. _openvnc-server-core_ pode ter test de equívoco simétrico (cliente->servidor->cliente round-trip).

- **Fuzzing**: usar _cargo-fuzz_ para alimentar o parser RFB com dados aleatórios, garantindo que não há panic/corruption. Testar limites: mensagens muito pequenas, header inválido, etc.

- **Integração com VNC reais**: abrir conexões a servidores conhecidos (TigerVNC, TightVNC, RealVNC) e verificar que o _client_ vê a tela corretamente. Também fazer o inverso: conectar clientes populares ao nosso servidor. Em especial testar distintos encodings: pedir apenas Raw, apenas Hextile, etc.

- **Plataformas**: configurar testes em Windows, Linux, macOS. Por exemplo, em Linux usar _xvfb_ ou Wayland. O CI deve cruzar compilação em targets x86_64, aarch64, etc.

- **Supply Chain**: usar `cargo audit` para dependências; `cargo deny` para licenças. Nenhuma dependência sem licença compatível (Apache2/MIT).

- **Segurança**: além de fuzz, criar testes de protocolo adversarial (por exemplo, cliente envia `FramebufferUpdateRequest` sobrepondo área inválida, ou malformado) e confirmar que o servidor rejeita conexões ou fecha sem falhar internamente.

## Roadmap de Implementação

1. **Fase 0.1 – MVP RFB**:
   - Arquitetura inicial. Servidor RFB básico, roda handshake e envia Raw frames estáticos da tela. Leitura de teclado/mouse básica. Teste interoperabilidade mínima. Critério: conectar com TigerVNC e visualizar framebuffer.
2. **Fase 0.2 – Melhoria de Vídeo**:
   - Implementar encodings Hextile e ZRLE. Diferenciação incremental vs full. Suporte a múltiplos monitores e DesktopSize.
   - Pipeline de captura otimizado (XDamage/PipeWire). Critério: captura de movimento de janela com baixo uso CPU, transmissão a 30FPS de uma animação simples.
3. **Fase 0.3 – Segurança e Transporte**:
   - TLS 1.3 via rustls em RFB (veesp. config). Implementar autenticação de senha (opcional).
   - Estabelecer e testar conexões QUIC sem lógica de aplicação (só handshake TLS).
   - Critério: clientes configurados para TLS conectam sem tela (handshake completo).
4. **Fase 0.4 – Protocolo Nativo e Recursos Avançados**:
   - Especificação inicial do protocolo OpenVNC (v1.0). Código para ouvir QUIC e trocar mensagens (sem vídeo ainda).
   - Introduzir codecs de vídeo (H.264) para tentativas de streaming.
   - Suportar transferência de arquivos básica e sincronização de clipboard.
   - Critério: conexão OpenVNC entre client e server, envio de tela usando novo codec funcional.
5. **Fase 1.0 – Estável**:
   - Documentação completa, APIs C-ABI definidas, exemplos. Polimento de performance e correção de bugs. Versão de lançamento pública.

## Exemplo de Estrutura de Repositório e API Interna

Esboço de um monorepo:

```
openvnc-server/
├── Cargo.toml (workspace)
├── src/
│   ├── main.rs (inicia servidor)
│   ├── config.rs
│   ├── screen.rs      // define trait ScreenCapture e implementações
│   ├── input.rs       // define trait InputInjector
│   ├── protocol_rfb.rs// estado/handshake RFB
│   ├── protocol_native.rs // estado futuro
│   └── transport.rs   // abstração de conexões
├── openvnc-server-core/
│   ├── src/…         // definições de PixelFormat, Framebuffer, etc.
├── openvnc-server-rfb/
│   ├── src/
│   │   ├── handshake.rs
│   │   ├── messages.rs // definições de structs para cada mensagem
│   │   ├── encoder.rs
│   │   └── server.rs   // loop principal RFB
├── openvnc-transport/
│   ├── src/
│   │   ├── tcp.rs     // listener TCP + TLS (rustls)
│   │   ├── quic.rs    // listener QUIC (quinn)
│   │   └── connection.rs // unifica streams
├── openvnc-screen/
│   ├── src/
│   │   ├── windows.rs  // impl. de ScreenCapture via Desktop Duplication
│   │   ├── x11.rs      // impl. via XGetImage/XDamage
│   │   ├── wayland.rs  // impl. via PipeWire
│   │   ├── mac.rs      // impl. via CGDisplayStream
│   │   └── lib.rs      // trait + selects impl
├── openvnc-input/
│   ├── src/
│   │   ├── windows.rs  // SendInput
│   │   ├── x11.rs      // XTest
│   │   └── lib.rs      // trait + selects impl
└── examples/
    ├── client_rust/    // demonstrativo de uso do protocolo RFB
    └── server_native/  // futuro: exemplo usando protocolo OpenVNC
```

Exemplo de API/structs internas (pseudocódigo Rust):

```rust
struct PixelFormat {
    bits_per_pixel: u8,
    depth: u8,
    big_endian: bool,
    true_color: bool,
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
}

struct DisplayInfo {
    width: u32,
    height: u32,
    scale: f32, // DPI escalonamento
    offset_x: i32,
    offset_y: i32,
}

pub trait ScreenCapture {
    fn new(config: CaptureConfig) -> Result<Self> where Self: Sized;
    fn capture_frame(&mut self) -> Result<ScreenFrame>;
    fn displays(&self) -> Vec<DisplayInfo>;
}

pub struct ScreenFrame {
    pub pixels: Vec<u8>, // BGRA
    pub width: u32,
    pub height: u32,
}

pub trait InputInjector {
    fn inject_key(&self, key_sym: u32, down: bool) -> Result<()>;
    fn inject_pointer(&self, x: u16, y: u16, button_mask: u8) -> Result<()>;
}

// Exemplo de loop de servidor RFB (simplificado):
fn handle_rfb_client(mut conn: RfbConnection, injector: Arc<dyn InputInjector>, screen: Arc<Mutex<ScreenFrame>>) {
    conn.handshake().unwrap();
    let pf = conn.server_init().unwrap();
    loop {
        match conn.read_client_message().unwrap() {
            ClientMessage::FramebufferUpdateRequest { incremental, x, y, w, h } => {
                let frame = screen.lock().unwrap();
                let rects = compute_rects(&frame, incremental, x, y, w, h);
                conn.send_framebuffer_update(&frame, &pf, &rects).unwrap();
            }
            ClientMessage::PointerEvent { x, y, button_mask } => {
                injector.inject_pointer(x, y, button_mask).ok();
            }
            ClientMessage::KeyEvent { key, down } => {
                injector.inject_key(key, down).ok();
            }
            ClientMessage::ClientCutText { text } => {
                // Opicional: aplicar texto no clipboard do servidor
            }
        }
    }
}
```

As opções de configuração (`config.toml`) devem ter defaults seguros, por exemplo:

```toml
listen_addr = "0.0.0.0:5900"
shared = true
tls = false
allowed_users = ["user1", "user2"]  # opcional
```

Com essa arquitetura modular e detalhada, o **servidor OpenVNC em Rust** será capaz de servir clientes RFB atuais (compatibilidade com RFC 6143) e, no futuro, clientes do protocolo OpenVNC, tudo enquanto se beneficia da segurança e desempenho que Rust oferece.

**Fontes:** Especificação do protocolo RFB (RFC 6143); documentação das crates _scrap/scrcap_ para captura de tela multiplataforma; crate _rdev_ para injeção de eventos (X11/Windows/Mac); _quinn_ para QUIC; _rustls_ para TLS.
