# 🔍 Automatic PCAP Investigator

**Investigue capturas de rede automaticamente.** Você dá um arquivo `.pcap`, ele te devolve o que provavelmente aconteceu — com as evidências que sustentam cada conclusão.

Nada de IA, nada de listas de bloqueio, nada de serviços externos. A investigação é feita com protocolos, estatística e correlação de eventos, tudo rodando localmente na sua máquina.

---

## O problema que ele resolve

Analisar um pcap manualmente é lento. Você abre o Wireshark, olha milhares de pacotes e tenta responder: *"tem alguma coisa errada aqui?"*

Esta ferramenta responde por você. Ela lê a captura, entende quem conversou com quem, procura comportamentos estranhos, conecta os pontos e monta uma hipótese do que pode ter acontecido — sempre mostrando **por que** chegou àquela conclusão.

## Como é a saída

Rodando na captura de exemplo (um incidente simulado):

```text
Findings:  15 (highest risk first)
  [risk HIGH | confidence HIGH  ] Likely periodic beaconing to 203.0.113.66:4444
      - 30 connections over 870s (TCP/4444)
      - mean interval 30.00s, median 30.00s, stdev 0.000s
      - coefficient of variation 0.0000 (<0.15 = highly regular)
      ! Periodicity alone does not establish command-and-control activity.
  [risk HIGH | confidence MEDIUM] Conflicting ARP claims for 10.0.0.1
      - 2 MACs claimed 10.0.0.1: 02:00:00:00:00:01 (10x), 02:00:00:00:00:15 (10x)
      - claims coexisted for 53.0s (threshold 1.0s)
      - 10 unprompted (gratuitous) announcement(s)
      ! ARP carries no authentication, so the capture cannot establish which
        claim is legitimate.
  [risk HIGH | confidence MEDIUM] ICMP echo payloads inconsistent with ping
      - mean echo payload 981 B exceeds the 128 B threshold (ping sends 32-56 B)
      - 97% of echoes differed from the most common size - a ping repeats one
      ! Payload content is not inspected, so this establishes shape only.

Host risk profiles:
  10.0.0.15
    Risk: HIGH    Confidence: HIGH (98%)
    Indicators (15 findings):
      [+] Periodic / Automated Communication (3) -> 203.0.113.66, 10.0.0.1
      [+] Network Discovery / Scanning (4) -> 10.0.0.23
      [+] DNS Anomalies (1) -> dataleak.io
      [+] Local Segment Addressing Anomalies (1) -> 10.0.0.1
      [+] Potential Outbound Data Transfer (1) -> 203.0.113.66
      [+] Suspicious External Destinations (3) -> 203.0.113.66

Risk Score: 100/100
Severity:   CRITICAL
Confidence: HIGH (98%)

Conclusion:
  10.0.0.15 exhibits anomalous network behaviour. [...] The combination of
  these indicators is consistent with a potentially compromised host and
  warrants further investigation. Network evidence alone cannot establish
  malware execution, compromise, or attacker intent with certainty.
```

Três detalhes importam aqui. **Risco e confiança são separados** — um deles diz o quão grave seria, o outro o quão certa é a evidência. **Findings do mesmo comportamento não inflam o score**: várias comunicações periódicas do mesmo host viram um grupo só, com retornos decrescentes visíveis na conta. E **toda conclusão carrega suas limitações** — nada de "malicioso: sim".

Além do terminal, você recebe um relatório HTML navegável com hosts, comunicações, protocolos, timeline e todas as evidências.

---

## Começando

**Requisitos:** Python 3.10 ou superior. Só isso — não precisa instalar Wireshark, Npcap ou qualquer outra coisa.

```bash
git clone https://github.com/Josevmv/pcap-investigator.git
cd pcap-investigator

python -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1

pip install -e .
```

### Teste em 30 segundos

O projeto inclui geradores de capturas sintéticas, então dá para ver funcionando sem precisar de tráfego real:

```bash
python samples/make_scenario.py                          # cria um incidente simulado
python -m investigator samples/scenario_incident.pcap    # investiga
```

Abra o `reports/investigation.html` que foi gerado e explore.

Quer comparar com tráfego normal? `python samples/make_sample.py` cria uma captura benigna — a ferramenta corretamente devolve score baixo e um veredito "inconclusivo", sem inventar incidente.

### Usando com suas próprias capturas

```bash
python -m investigator minha-captura.pcap
```

Aceita `.pcap`, `.pcapng` e versões comprimidas com gzip. Para gravar uma captura, use o Wireshark (`File → Save As`), `tcpdump -w captura.pcap` no Linux, ou o `pktmon` que já vem no Windows.

> A ferramenta **não** usa Wireshark/tshark para analisar — a leitura e toda a lógica são Python puro. Ele serve só como uma das formas de gravar o arquivo.

---

## O que ele detecta

| Comportamento | O que faz suspeitar |
|---|---|
| 🔎 **Varredura de portas** | Um host tentando muitas portas ou muitos alvos, com a maioria das conexões falhando |
| 📡 **Beaconing** | Conexões repetidas em intervalos regulares demais para serem humanas |
| 🌐 **Anomalias de DNS** | Subdomínios longos, aleatórios e numerosos demais para tráfego legítimo |
| 📤 **Transferência de saída** | Host enviando muito mais do que recebe, para um destino que ninguém mais acessa |
| 🖥️ **HTTP anômalo** | Requisições periódicas, POSTs repetidos, User-Agent legado ou de script |
| 🔐 **TLS anômalo** | Sessão sem SNI, SNI que nenhuma resposta DNS da captura resolveu, versão legada, fingerprint de cliente que nenhum outro host usa |
| 🧨 **ARP contestado** | Um mesmo IP reivindicado por dois MACs ao mesmo tempo — a marca de envenenamento de cache |
| 📶 **ICMP como transporte** | Echo com payload grande e de tamanho variável, que é o oposto do que um ping faz |
| ↔️ **Movimento lateral** | Sessões administrativas bem-sucedidas espalhadas pela rede interna |
| 🗺️ **Descoberta de hosts** | Varredura de endereços internos (TCP ou ICMP), muitos deles inexistentes |
| ⚡ **Picos de tráfego** | Volume muito acima do padrão da própria captura |
| 🎯 **Destinos raros / portas incomuns** | Endpoints externos que só um host acessou, em portas fora do comum |

E o mais importante: ele **agrupa e correlaciona** esses achados. Dezenas de alertas soltos viram poucas categorias de comportamento, consolidadas por host, com risco e confiança avaliados separadamente.

---

## O que torna ele diferente

**Ele explica tudo.** Cada alerta lista as evidências concretas — quantas conexões, qual o intervalo médio, qual o desvio padrão, quantos hosts contataram aquele destino. Você pode discordar da conclusão, mas vai entender como ela foi tirada.

**Ele não depende de listas de IOC.** Não existe base de "IPs maliciosos conhecidos". A referência é o **próprio tráfego da captura**: "raro" significa raro comparado ao resto do que foi observado ali. Isso permite encontrar coisas que nenhuma lista conhece ainda.

**Ele leva contexto em conta.** Servidores NTP, DNS e CDNs também fazem conexões periódicas. A ferramenta reconhece esses casos e rebaixa a confiança — um beacon para a porta 123 não é tratado como um beacon para a porta 4444.

**Ele separa risco de confiança.** São perguntas diferentes: *quão grave seria isso?* e *quão certa é a evidência?* Uma transferência grande de saída é risco alto com confiança baixa de ser exfiltração — o comportamento preocupa, mas o conteúdo dos pacotes é inacessível. Misturar os dois numa nota só apagaria justamente a nuance que o analista precisa.

**Ele nunca afirma além do que os dados permitem.** A linguagem é sempre probabilística, e cada achado declara suas próprias limitações. Volume grande não é chamado de exfiltração; periodicidade não é chamada de C2; entropia de DNS não é chamada de tunelamento. A ferramenta detecta de forma agressiva e conclui de forma conservadora.

**Ele aguenta capturas grandes.** O arquivo é lido uma única vez, pacote a pacote, sem carregar tudo na memória.

---

## Opções úteis

```bash
python -m investigator captura.pcap [opções]
```

| Opção | Para quê |
|---|---|
| `--output-dir PASTA` | Onde salvar os relatórios (padrão: `reports/`) |
| `--config ARQUIVO` | Ajustar limiares e pesos sem editar código (`.toml` ou `.json`) |
| `--fail-on NÍVEL` | Sair com código 20 quando o risco atinge `low`/`medium`/`high`/`critical` — para usar em automação |
| `--max-packets N` | Dar uma espiada rápida numa captura enorme |
| `--top N` | Mostrar mais (ou menos) itens nas listas do terminal |
| `--no-html` / `--no-timeline` | Pular seções que você não quer |
| `-v` / `-vv` | Ver o progresso e detalhes da execução |

Os relatórios gerados:

```text
reports/
├── investigation.html    ← comece por aqui, é o mais fácil de ler
├── investigation.json    ← dados completos, para automatizar ou integrar
└── timeline.json         ← linha do tempo dos eventos
```

---

## Ajustando para a sua rede

Todos os limiares ficam num arquivo só: [`investigator/config.py`](investigator/config.py). Para ajustar sem tocar no código, passe um arquivo `.toml` ou `.json`:

```toml
# minha-rede.toml
beacon_min_events = 10          # quantos contatos até chamar de beacon
transfer_min_bytes = 5_000_000  # a partir de quanto considerar transferência grande

[weights]
beaconing = 30.0                # os pesos não listados mantêm o padrão
```

```bash
python -m investigator captura.pcap --config minha-rede.toml
```

Um nome de opção errado vira erro, não silêncio — um limiar ignorado por causa de um typo faria você acreditar que ajustou algo que continuou no padrão. O relatório sempre mostra qual peso foi usado em cada parcela do score.

---

## Rodando os testes

```bash
pip install -e ".[dev]"
python -m pytest
```

São 212 testes. Todos usam capturas sintéticas geradas na hora — nenhum arquivo binário de origem duvidosa no repositório. Isso inclui testes que verificam que a ferramenta **não** gera alarme falso em tráfego legítimo: um ping comum não pode virar túnel ICMP, uma troca de endereço por DHCP não pode virar ARP spoofing, e uma sessão TLS cujo SNI o DNS resolveu não pode virar alerta.

---

## Limitações (com sinceridade)

- **Não descriptografa TLS** — e nem tenta. Só lê o que está em claro no handshake (SNI, versões, ordenação de ciphers).
- **Não remonta streams TCP.** Cabeçalhos HTTP/TLS partidos entre vários pacotes são contabilizados como "não processados", nunca ignorados em silêncio.
- **A separação interno/externo é uma suposição** baseada em faixas de IP privadas. Redes com endereçamento público interno seriam classificadas de outra forma.
- **Velocidade medida: cerca de 3 mil pacotes por segundo** no pipeline completo (Python 3.14, captura de exemplo). Cerca de 70% desse tempo é a dissecação do Scapy. Serve para capturas de triagem — algo em torno de 1 milhão de pacotes por 5 minutos — mas não é um analisador de linha. O caminho para melhorar isso está descrito na [ARCHITECTURE](ARCHITECTURE.md#limitações-técnicas).
- **É uma ferramenta de triagem, não um veredito final.** Ela aponta onde olhar; a confirmação vem do host, dos logs e do contexto que só você tem.

---

## Estrutura do projeto

```text
investigator/
├── cli.py            interface de linha de comando
├── pipeline.py       orquestra todas as etapas
├── parser.py         lê o arquivo de captura
├── inventory.py      quem está na rede, quem fala com quem
├── protocols/        análise de DNS, TCP, HTTP, TLS, ARP e ICMP
├── detectors/        os detectores de comportamento suspeito
├── correlation.py    conecta achados em hipóteses
├── timeline.py       reconstrói a ordem dos eventos
├── scoring.py        calcula o risco de forma explicável
├── investigation.py  monta o resumo executivo
└── config.py         todos os limiares e pesos
```

Quer entender as decisões de design por trás disso — por que streaming, por que o Scapy fica isolado, como a confiança é calculada? Está tudo em **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Sobre

Projeto construído do zero em Python como estudo aprofundado de redes, análise de pacotes, detecção comportamental e investigação de incidentes.

Ferramenta de uso **defensivo**: blue team, DFIR e threat hunting. Analise apenas capturas de redes que você tem autorização para monitorar.

## Licença

© 2026 Josevmv — Todos os direitos reservados.

O código está publicado para leitura e avaliação, mas **não é open source**. Cópia, redistribuição, modificação ou uso comercial exigem autorização prévia e por escrito. Veja [LICENSE](LICENSE) para os termos completos.

As bibliotecas de terceiros utilizadas (Scapy, Jinja2) mantêm suas licenças originais.
