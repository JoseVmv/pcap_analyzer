# Arquitetura e decisões de design

Este documento explica **como** a ferramenta funciona por dentro e **por que** cada escolha foi feita. Para instalar e usar, veja o [README](README.md).

## Índice

- [Fluxo geral](#fluxo-geral)
- [Decisões principais](#decisões-principais)
- [Dependências](#dependências)
- [Como cada detector decide](#como-cada-detector-decide)
- [Correlação e confiança](#correlação-e-confiança)
- [Risk score](#risk-score)
- [Estratégia de testes](#estratégia-de-testes)
- [Limites de memória](#limites-de-memória)
- [Limitações técnicas](#limitações-técnicas)

---

## Fluxo geral

```text
PcapLoader ──stream de NetworkEvent──> coletores (inventory, protocolos, rate, contacts)
                                            │
                                            v  (agregados, não pacotes)
                                        detectores ──> Findings (evidência + confiança)
                                            │
                                            v
                                        correlação ──> Hipóteses (cadeia de ataque)
                                            │
                                            v
                                  timeline + scoring + investigação
                                            │
                                            v
                          investigation.json / investigation.html / timeline.json
```

`pipeline.analyze_capture()` é o fio condutor: é o único lugar que conhece a ordem das etapas, e tanto a CLI quanto os testes passam por ele, garantindo que se comportem de forma idêntica.

### Estrutura de módulos

```text
investigator/
├── cli.py            argparse, formatação da saída de terminal
├── pipeline.py       analyze_capture(): orquestra todas as etapas
├── engine.py         passe único de streaming -> coletores
├── parser.py         validação de arquivo + Scapy -> NetworkEvent
├── models.py         NetworkEvent, CaptureSummary, enums
├── errors.py         hierarquia de exceções tipadas
├── inventory.py      hosts, conversas, baseline de portas
├── stats.py          entropia, média, desvio, mediana, MAD, CV
├── protocols/        dns.py, tcp.py, http.py, tls.py, arp.py, icmp.py
├── detectors/        base, scanning, beaconing, dns_anomaly, rare_destination,
│                     unusual_ports, bursts, exfiltration, lateral,
│                     tls_anomaly, arp_spoofing, icmp_anomaly
├── findings.py       Finding, Evidence, Severity
├── correlation.py    fases, hipóteses, correlação temporal
├── threats.py        mapeamento para táticas (estilo ATT&CK)
├── timeline.py       reconstrução cronológica
├── scoring.py        risk score explicável
├── investigation.py  sumário executivo, ranking de suspeitos
├── reporting.py      geração de JSON e HTML
├── config.py         TODOS os limiares e pesos
└── templates/        report.html.j2
```

---

## Decisões principais

### 1. Passe único de streaming

A captura é lida **uma única vez**. Os coletores implementam `observe(event)` e mantêm apenas agregados compactos; os detectores rodam **depois**, sobre esses agregados, nunca sobre pacotes.

Por quê: memória constante independentemente do tamanho do arquivo, e cada camada fica testável isoladamente. Um detector pode ser testado com um inventário construído à mão, sem nenhum pcap envolvido.

Detalhe de implementação: coletores que precisam do payload bruto (DNS, HTTP, TLS) declaram `wants_packets = True` e recebem `observe_packet(event, packet)`. Se nenhum coletor pedir pacotes, o engine usa o caminho mais barato, só com eventos.

### 2. Scapy confinado ao parser

Nenhum módulo de análise vê objetos Scapy — todos trabalham com `NetworkEvent`, que é imutável (`frozen=True`) e usa `slots=True` para reduzir o custo de memória por pacote.

Por quê: permite trocar o parser no futuro (por exemplo, um decoder próprio com `struct` para ganho de performance) sem tocar em um único detector. E torna toda a lógica de investigação testável sem arquivos binários.

### 3. Todo limiar em `config.py`

Nenhum número mágico no ponto de uso. Um finding consegue dizer "disparou porque X ultrapassou o limiar T", e um operador ajusta esse T sem editar lógica de detecção.

### 4. Evidência é obrigatória

`Finding` carrega uma lista de `Evidence`, cada uma com um resumo legível e os dados numéricos brutos. O módulo de investigação (V7) recusa-se a emitir uma conclusão que não aponte para evidência rastreável.

### 5. Redução de falsos positivos por contexto, não por whitelist

Nada é permanentemente ignorado. O que existe são **penalidades de confiança**: um beacon para a porta 123 (NTP) continua sendo reportado, mas com confiança bem menor e uma nota explicando o motivo. A diferença importa — uma whitelist esconderia um C2 que usasse a porta 123 de propósito.

### 6. Baseline vem da própria captura

"Raro", "incomum" e "muito acima do normal" são medidos contra o resto do tráfego observado no mesmo arquivo, nunca contra uma lista externa de IOC. É isso que permite encontrar comportamento que nenhuma base conhece.

### 7. Erros tipados, pacote quebrado não aborta a análise

Problemas com o **arquivo** (inexistente, formato errado, corrompido) viram exceções tipadas antes da análise começar. Problemas com **um pacote** são contados e pulados. Uma captura truncada encerra o stream de forma limpa mantendo os resultados parciais — capturas de incidentes reais frequentemente vêm danificadas, e evidência parcial ainda é evidência.

### 8. HTML com autoescaping — decisão de segurança

O relatório embute strings controláveis por um atacante: nomes DNS, SNI de TLS, URIs e User-Agents HTTP. Sem escaping, um pacote forjado injetaria markup no navegador do analista — a ferramenta de análise viraria a vítima. Por isso o Jinja2 é configurado com `autoescape` e há um teste que verifica o comportamento com um `<script>` dentro de um nome DNS.

---

## Dependências

| Pacote | Por quê |
|---|---|
| `scapy` | leitura de pcap/pcapng e dissecação em Python puro, sem processos externos |
| `jinja2` | template HTML **com autoescaping** dos dados vindos da captura |
| `pytest` | testes (desenvolvimento) |

**PyShark foi descartado** por ser um wrapper do binário tshark, o que criaria dependência do Wireshark instalado e violaria a premissa de análise autocontida.

**pandas e numpy foram deliberadamente evitados.** As estatísticas usadas (entropia de Shannon, média, desvio padrão, mediana, desvio absoluto mediano, coeficiente de variação) cabem em cerca de 60 linhas em `stats.py`. Não justificaria carregar dezenas de megabytes de dependência para isso.

---

## Como cada detector decide

| Detector | Sinal principal | Guarda contra falso positivo |
|---|---|---|
| Port scan vertical | N portas distintas num mesmo host | exige alta taxa de conexões **não estabelecidas** — um cliente normal completa o handshake |
| Port scan horizontal | mesma porta em N hosts | idem, mais contagem de alvos internos |
| Host discovery | muitos IPs internos tocados | exige alta fração de endereços que **nunca respondem** |
| Beaconing | coeficiente de variação dos intervalos + MAD | penaliza portas de infraestrutura periódica (NTP/DNS/DHCP), destinos resolvidos por DNS e destinos internos |
| DNS anomaly / tunneling | entropia, comprimento de label, subdomínios únicos, taxa de NXDOMAIN, uso de TXT/NULL | exige **≥2 sinais independentes**; só chama de "tunneling" com ≥3, incluindo entropia |
| Rare destination | contatado por um único host interno | severidade limitada a MEDIUM; confiança só sobe com corroboração |
| Unusual port | sessão real (não sonda) em porta atípica | compara com o baseline de portas da própria captura |
| Traffic burst | mediana + k·MAD (robusto a outliers) | piso absoluto de bytes; janelas adjacentes são fundidas |
| Transferência de saída | avaliação **em três níveis** (ver abaixo) | só chega a "indicador de exfiltração" com ≥2 evidências além de volume e direção |
| HTTP periódico | CV dos intervalos entre requisições | exige mínimo de requisições; User-Agent legado entra só como sinal contextual fraco |
| Lateral movement | sessões administrativas **estabelecidas** em N hosts | ignora SYNs sem resposta — isso é scan, não movimento lateral |
| ARP contestado | um IP reivindicado por 2+ MACs | exige repetição por MAC; a confiança sobe com **sobreposição temporal**, não com a mera existência do conflito |
| ICMP tunneling | tamanho médio do payload + variabilidade dos tamanhos | exige **≥2 sinais independentes**; um canal com um único tamanho convencional é ping e sai antes de qualquer avaliação |
| ICMP sweep | echo para N endereços distintos | exige alta fração de alvos que nunca respondem |
| TLS sem SNI | ClientHello sem `server_name` para destino externo | risco MEDIUM e confiança moderada: conexão direta a IP é rotina para agentes de monitoramento |
| TLS SNI sem DNS | SNI que nenhuma resposta DNS da captura associou àquele IP | **só avalia se houve DNS observado** na captura; risco maior quando o DNS resolveu aquele IP para outro nome |
| TLS fingerprint raro | JA3 usado por um único cliente | exige leque mínimo de destinos externos; raridade medida só dentro da captura |

### Transferência ≠ exfiltração: a avaliação em níveis

A regra central: **volume sozinho nunca é exfiltração**. Uma transferência grande pode ser backup, atualização, upload de vídeo, sincronização, varredura ou roubo de dados — e a captura normalmente não distingue, porque o conteúdo é inacessível ou cifrado.

Por isso o detector é escalonado, e só promove ao nível seguinte quando há evidência independente adicional:

| Nível | Exige | Risco |
|---|---|---|
| `large_transfer` | volume acima do piso | LOW |
| `outbound_data_transfer` | + direção dominante de upload | MEDIUM |
| `potential_exfiltration_indicator` | + ≥2 indicadores corroborantes | HIGH |

Os indicadores corroborantes são: destino raro (só um host interno o contatou), ausência de resolução DNS (conexão direta a IP), POSTs/PUTs HTTP repetidos, volume de resposta desproporcionalmente baixo, e upload muito acima da mediana da própria captura.

Mesmo o nível mais alto se chama *indicador*, nunca conclusão, e carrega sempre a limitação explícita de que o conteúdo do payload não pôde ser estabelecido.

### ARP: o que distingue envenenamento de uma troca de endereço

Dois MACs reivindicando o mesmo IP é quase um *fato*, não uma leitura estatística — ou aconteceu, ou não. O que continua incerto é a **causa**, e é aí que a confiança é gasta, não na observação.

As explicações benignas são reais e comuns: o DHCP reatribuiu o endereço, trocaram a placa de rede, uma VM migrou, um par VRRP/CARP fez failover (que move um IP entre MACs por projeto), ou um roteador responde por outros endereços via proxy ARP.

O que separa esses casos do envenenamento é **tempo**. Uma troca é sequencial: o MAC antigo silencia, o novo assume. Envenenamento é concorrente — os dois reivindicam o endereço na mesma janela, e o atacante repete anúncios gratuitos para o cache não expirar. Por isso a confiança é dirigida por sobreposição, repetição e divergência entre o MAC do cabeçalho Ethernet e o do payload ARP — nunca pela simples existência de dois bindings. Há um teste que constrói os dois cenários e exige que o concorrente pontue mais alto que o sequencial.

### O fingerprint TLS não é uma lista de IOC

O JA3 é calculado localmente a partir da ordenação de ciphers, extensões e curvas que o **cliente** escolhe — ou seja, identifica a *implementação* que fez a conexão, não o conteúdo dela. Ele nunca é comparado contra base externa: "raro" significa "poucos hosts desta captura produziram esse fingerprint", mantendo intacta a regra de que o baseline vem do tráfego em mãos.

Os valores GREASE (RFC 8701) são removidos antes do hash. Eles existem justamente para variar entre conexões; se entrassem no cálculo, o mesmo cliente teria fingerprint diferente a cada handshake e a medida não serviria para nada. Há um teste que verifica exatamente isso.

### Por que o MAD e não só o desvio padrão

O desvio padrão é sensível a outliers: um único intervalo enorme num beacon regular inflaria a métrica e esconderia a regularidade. O desvio absoluto mediano (MAD) é robusto a isso. O detector de beaconing usa o **menor** entre o coeficiente de variação e a razão MAD/mediana, então uma pausa isolada não descaracteriza um padrão que é claramente automatizado.

O mesmo raciocínio vale para o detector de bursts: o baseline usa mediana + k·MAD em vez de média + k·σ, para que o próprio pico que se quer detectar não infle o limiar criado para pegá-lo.

---

## Risco e confiança são eixos independentes

Esta é a decisão conceitual mais importante do projeto.

- **Risco** (`Severity`) responde: *quão grave seria isso se a leitura estiver correta?*
- **Confiança** (`Confidence`) responde: *quão forte é a evidência que sustenta essa leitura?*

As duas direções são legítimas e comuns numa investigação real. Uma grande transferência de saída é **risco ALTO com confiança BAIXA** de ser exfiltração — o comportamento preocupa, mas o conteúdo do payload é inacessível. Um port scan de manual é **risco MÉDIO com confiança ALTA** — o comportamento é inconfundível, mas raramente é o incidente em si.

Versões anteriores derivavam severidade da confiança (`Severity.from_confidence()`), o que colapsava os dois eixos e destruía exatamente a nuance de que o analista precisa. Esse método ainda existe, marcado como deprecated, para não quebrar código externo; detectores novos declaram risco explicitamente.

## Correlação: observação, interpretação, hipótese

O sistema mantém três níveis rigorosamente separados:

| Nível | Estrutura | O que afirma |
|---|---|---|
| **Comportamento observado** | `BehaviorGroup` | o que os pacotes mostram, agrupado por categoria. Nenhuma alegação causal. |
| **Indicadores correlacionados** | `HostRiskProfile` | várias categorias atribuíveis ao mesmo host. Consolidado, ainda não causal. |
| **Hipótese** | `Hypothesis` | leitura investigativa da combinação, sempre hedged e rastreável aos findings. |

### Por que a "attack chain" com setas foi removida

Um diagrama `A → B → C` afirma que A *causou* B. Uma captura não estabelece causação — apenas coocorrência e ordenação. O relatório agora apresenta **categorias de comportamento observado**, sem setas.

A ordenação cronológica continua sendo medida e reportada (campo `chronological`, mais as frases de sequência), porque é informação corroborante genuína — mas rotulada como *sequência*, nunca como causalidade. Há um teste que varre a saída em busca de asserções causais ("led to", "resulted in", "consequently") e falha se alguma aparecer.

As categorias também são nomeadas em nível de observação: "Network Discovery / Scanning" em vez de "Reconnaissance", "Periodic / Automated Communication" em vez de "Command & Control". O rótulo interpretativo continua disponível (`interpretive_label`), usado só onde a interpretação está explicitamente sinalizada.

Um detalhe que um teste capturou: `traffic_burst` estava categorizado como "Potential Outbound Data Transfer", o que afirmava direção — exatamente o que o detector de burst declara não conseguir determinar. Bursts agora têm categoria própria, "Traffic Volume Anomalies".

### Agregação de confiança

A confiança parte dos próprios findings (o mais forte, temperado pela média, para que um monte de achados fracos não se disfarce de evidência forte). Depois, cada corroboração consome uma **fração do headroom restante** até o teto:

```python
confidence += (CEILING - confidence) * fraction
```

Por quê essa fórmula: ela é estritamente monotônica (mais fases sempre aumentam a confiança) e nunca satura no teto. A primeira implementação somava bônus diretamente e batia no limite com apenas duas fases, tornando impossível distinguir uma cadeia de 2 fases de uma de 5 — um teste pegou exatamente isso.

O teto é 0.98, nunca 1.0: uma captura mostra comportamento, não intenção.

---

## Risk score

Cada finding contribui com `peso × confiança`, onde o peso vem de `config.weights`.

### O score não é uma probabilidade

`92/100` não significa "92% de chance de comprometimento". Significa que os indicadores ponderados e deduplicados acumularam 92 pontos numa escala cujo topo é atingido por qualquer combinação suficientemente severa. Por isso **dois números são reportados**:

- `raw_score` — a acumulação sem limite, para que uma execução que ultrapassa muito o teto seja visivelmente diferente de uma que apenas o alcança;
- `normalized_score` — o valor 0–100 de apresentação.

No PCAP real de exercício, por exemplo, o raw é 155.02 e o normalizado é 100/100 — a diferença agora fica explícita em vez de escondida. O JSON carrega `"is_probability": false` e uma frase de interpretação, e o campo `capped` diz que o teto marca "combinação severa de indicadores", não certeza.

### Deduplicação por grupo de comportamento

O maior risco ao significado de um score é a contagem dupla. Os retornos decrescentes não são aplicados por *tipo* de finding, e sim por **grupo de comportamento** (`Finding.group_key`, por padrão `tipo:host`).

Três findings de "comunicação periódica" do mesmo host para três destinos são três evidências de **uma** atividade, e são pontuados como tal: peso cheio para o mais forte, depois ×½, ×⅓ e assim por diante. As ocorrências são processadas da mais forte para a mais fraca, então o decaimento penaliza as repetições menos relevantes. No caso real, 25 findings de HTTP periódico colapsaram em um único grupo.

**Bônus de correlação.** Uma combinação coerente de múltiplas categorias é evidência mais forte que a soma das partes, então a melhor hipótese adiciona um bônus escalado pela própria confiança.

### Confiança do score é calculada à parte

`RiskScore.confidence` não deriva do total de pontos. Ela é ancorada na melhor conclusão disponível — a hipótese correlacionada, se houver — e um finding isolado tem a confiança **limitada a 0.75**, porque uma conclusão não corroborada é intrinsecamente mais fraca que uma cadeia correlacionada.

Cada parcela vira um `ScoreComponent` com rótulo, grupo, peso, multiplicador, pontos e total acumulado — é isso que permite imprimir a aritmética completa no terminal e no HTML.

---

## Estratégia de testes

São 212 testes, e nenhum arquivo pcap binário é versionado. Todas as capturas são construídas na hora:

- **`tests/conftest.py`** monta capturas em memória com Scapy, cobrindo formatos pcap (little/big endian, microssegundos/nanossegundos), pcapng, gzip, arquivo vazio, arquivo de lixo, diretório e captura truncada.
- **`tests/synth.py`** gera tráfego de ataque sintético: scan vertical e horizontal, beacon regular, beacon com jitter, beacon NTP legítimo (para testar supressão de falso positivo), tunelamento DNS, movimento lateral e upload em massa.

Duas escolhas valem destaque:

**O pcapng de teste é montado byte a byte com `struct`** (Section Header Block + Interface Description Block + Enhanced Packet Block). Assim o leitor é validado contra a especificação do formato, e não contra o writer do próprio Scapy — se ambos tivessem o mesmo bug, o teste passaria mesmo assim.

**Os handshakes TLS seguem o mesmo princípio**, construídos conforme o RFC 8446. O parser de TLS é escrito à mão, então testá-lo contra bytes que nós mesmos montamos a partir da especificação é o que dá confiança real.

Há também testes explícitos de **não-detecção**: um cliente que abre várias conexões estabelecidas não pode virar "port scan"; um beacon NTP não pode receber a mesma confiança de um beacon para porta 4444; tráfego com download dominante não pode virar "exfiltração".

---

## Limites de memória

Para capturas muito grandes, algumas estruturas param de crescer enquanto os contadores continuam exatos:

| Limite | Valor | Efeito ao estourar |
|---|---|---|
| `MAX_TIMESTAMPS_PER_CONVERSATION` | 200.000 | série temporal para de crescer; contagens seguem exatas |
| Séries de contato (beaconing) | 300.000 séries × 100.000 timestamps | novas séries são descartadas e contabilizadas em `dropped_series` |
| Nomes DNS únicos por cliente | 50.000 | marca `unique_qnames_overflow` |
| Subdomínios por domínio | 20.000 | marca `subdomain_overflow` |
| Registros HTTP / TLS | 100.000 / 50.000 | novos registros não são guardados; contadores seguem |
| `MAX_TRACKED_HOSTS` | 200.000 | novos IPs não entram na tabela; `untracked_host_events` conta, e os contadores globais de porta seguem exatos |
| `MAX_TRACKED_CONVERSATIONS` | 500.000 | novas arestas não entram; `untracked_conversation_events` conta |
| `MAX_PEERS_PER_HOST` | 10.000 | `peer_count` vira um piso, sinalizado por `peers_overflow` |
| `MAX_TRACKED_FLOWS` (TCP) | 400.000 | novos fluxos não entram; `untracked_flows` conta |
| Bindings ARP / canais ICMP | 50.000 / 100.000 | marcam `tracked_overflow` e `channels_overflow` |

O princípio é sempre o mesmo: **nunca perder informação em silêncio**. Quando um limite é atingido, existe um contador ou uma flag registrando isso.

Os quatro últimos limites de tabela merecem uma nota: eles crescem com a **forma** do tráfego, não com o tamanho do arquivo — e o pior caso é exatamente o comportamento que a ferramenta existe para detectar. Uma varredura horizontal cria um host e uma conversa por endereço tocado; uma vertical cria um fluxo por porta sondada. Sem teto, a entrada adversarial seria também a que esgota a memória. Vale registrar a honestidade do custo: passado o teto de fluxos, a detecção que lê estado de fluxo (scan, movimento lateral) degrada — por isso o número de fluxos descartados é reportado em vez de escondido.

---

## Limitações técnicas

- **Performance: cerca de 3 mil pacotes por segundo** no pipeline completo (medido em `samples/scenario_incident.pcap`, Python 3.14). O perfil é inequívoco: ~70% do tempo está em `scapy.read_packet`, ou seja, na dissecação. A busca de camadas no `parser.py` já foi reduzida a uma **passada única** pela cadeia (era um `getlayer` por camada de interesse, cada um percorrendo tudo de novo — 19 visitas de camada por pacote); isso deixou o lookup 24× mais rápido, mas mexe numa fatia pequena do total. O próximo passo real é um fast-path com `RawPcapReader` + `struct`, substituindo a dissecação: a arquitetura isola o parser justamente para permitir isso sem tocar em nenhum detector.

  Detalhe que a passada única obrigou a acertar: o casamento de camadas é por **classe exata**, nunca `isinstance`. O Scapy modela os cabeçalhos citados dentro de um erro ICMP como subclasses dos originais (`TCPerror(TCP)`), e é assim que o `getlayer` se comporta. Um walk com `isinstance` casaria com o `TCPerror` dentro de um *destination unreachable* e reportaria um fluxo TCP fantasma onde havia só um aviso de inalcançabilidade. Há um teste para exatamente esse pacote.
- **Sem reassembly de streams TCP:** HTTP e TLS são parseados apenas quando os cabeçalhos cabem no primeiro segmento. Mensagens fragmentadas são contadas (`multi_segment_skipped`, `fragmented_hellos`), nunca perdidas em silêncio.
- **Interno vs externo é heurístico:** faixas RFC 1918, RFC 6598, loopback e link-local são tratadas como internas. Optou-se por faixas explícitas em vez de `ipaddress.is_private` porque versões recentes do Python estenderam esse atributo para todo o registro de propósitos especiais da IANA, incluindo faixas de documentação — o que não corresponde ao conceito de "host na rede monitorada".
- **Agrupamento de domínio base** usa uma lista curta de sufixos multi-label (`com.br`, `co.uk`, etc.), não a Public Suffix List completa.
- **Atribuição de bursts** aponta o top talker global, não o talker daquela janela específica — isso exigiria série temporal por origem.
- **Números de sequência TCP** não tratam wrap-around de 32 bits.
- **Timestamps** são tratados como epoch UTC; o formato pcap não carrega o fuso horário da máquina que capturou.
- **IPv6** com cadeias exóticas de extension headers não recebe tratamento especial (o caso comum funciona; ICMPv6 é detectado pela classe base do Scapy).
