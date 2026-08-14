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
Findings:  10 (most significant first)
  [HIGH] Likely periodic beaconing to 203.0.113.66:4444  (97%)
           - 30 contacts over 870s
           - mean interval 30.0s, stdev 0.00s (coefficient of variation 0.000)
           - only internal host 10.0.0.15 contacted this destination
  [HIGH] Possible DNS tunneling / exfiltration: dataleak.io  (88%)
           - high subdomain entropy (max 4.78 bits/char, mean 4.54)
           - very long DNS label (48 chars)
           - 40 unique subdomains under one domain
           - high NXDOMAIN ratio (20/40 = 50%)

Correlated hypotheses:
  [HIGH] Possible compromised host with C2 and data exfiltration  (10.0.0.15, 92%)
           Reconnaissance
             |-> Lateral Movement
               |-> External Communication
                 |-> Command & Control
                   |-> Possible Data Exfiltration

Risk Score: 100/100  (CRITICAL)

How this score was calculated:
  + 24.2  Likely periodic beaconing...        [weight 25 x 0.97 = confidence 97%]
  + 17.6  Possible DNS tunneling...           [weight 20 x 0.88 = confidence 88%]
  + 16.0  Likely data exfiltration...         [weight 20 x 0.80 = confidence 80%]
  ------  total 100/100

Verdict:   High confidence: possible compromised host with c2 and data exfiltration
Primary suspect: 10.0.0.15
```

Repare em dois detalhes: **todo alerta vem com os números que o geraram**, e o score mostra a conta inteira. Nada de "malicioso: sim" sem explicação.

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
| 📡 **Beaconing (C2)** | Conexões repetidas em intervalos regulares demais para serem humanas |
| 🌐 **Tunelamento DNS** | Subdomínios longos, aleatórios e numerosos demais para tráfego legítimo |
| 📤 **Exfiltração de dados** | Host enviando muito mais do que recebe, para um destino que ninguém mais acessa |
| ↔️ **Movimento lateral** | Sessões administrativas bem-sucedidas espalhadas pela rede interna |
| 🗺️ **Descoberta de hosts** | Varredura de endereços internos, muitos deles inexistentes |
| ⚡ **Picos de tráfego** | Volume muito acima do padrão da própria captura |
| 🎯 **Destinos raros / portas incomuns** | Endpoints externos que só um host acessou, em portas fora do comum |

E o mais importante: ele **conecta esses achados**. Cinco alertas soltos viram uma hipótese só, com uma cadeia de ataque e uma confiança agregada.

---

## O que torna ele diferente

**Ele explica tudo.** Cada alerta lista as evidências concretas — quantas conexões, qual o intervalo médio, qual o desvio padrão, quantos hosts contataram aquele destino. Você pode discordar da conclusão, mas vai entender como ela foi tirada.

**Ele não depende de listas de IOC.** Não existe base de "IPs maliciosos conhecidos". A referência é o **próprio tráfego da captura**: "raro" significa raro comparado ao resto do que foi observado ali. Isso permite encontrar coisas que nenhuma lista conhece ainda.

**Ele leva contexto em conta.** Servidores NTP, DNS e CDNs também fazem conexões periódicas. A ferramenta reconhece esses casos e rebaixa a confiança — um beacon para a porta 123 não é tratado como um beacon para a porta 4444.

**Ele nunca afirma além do que os dados permitem.** A linguagem é sempre probabilística: "possível", "provável", "alta confiança". Um pcap raramente *prova* um ataque sozinho, e o relatório diz isso explicitamente.

**Ele aguenta capturas grandes.** O arquivo é lido uma única vez, pacote a pacote, sem carregar tudo na memória.

---

## Opções úteis

```bash
python -m investigator captura.pcap [opções]
```

| Opção | Para quê |
|---|---|
| `--output-dir PASTA` | Onde salvar os relatórios (padrão: `reports/`) |
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

Todos os limiares ficam num arquivo só: [`investigator/config.py`](investigator/config.py). Se algum detector estiver sensível ou frouxo demais para o seu ambiente, é lá que você mexe — sem precisar tocar na lógica de detecção.

```python
Config(
    beacon_min_events=10,        # quantos contatos até chamar de beacon
    exfil_min_bytes=5_000_000,   # a partir de quanto considerar exfiltração
)
```

Os pesos do risk score também são configuráveis, e o relatório sempre mostra qual peso foi usado em cada parcela.

---

## Rodando os testes

```bash
pip install -e ".[dev]"
python -m pytest
```

São 127 testes. Todos usam capturas sintéticas geradas na hora — nenhum arquivo binário de origem duvidosa no repositório. Isso inclui testes que verificam que a ferramenta **não** gera alarme falso em tráfego legítimo.

---

## Limitações (com sinceridade)

- **Não descriptografa TLS** — e nem tenta. Só lê o que está em claro no handshake (SNI, versões).
- **Não remonta streams TCP.** Cabeçalhos HTTP/TLS partidos entre vários pacotes são contabilizados como "não processados", nunca ignorados em silêncio.
- **A separação interno/externo é uma suposição** baseada em faixas de IP privadas. Redes com endereçamento público interno seriam classificadas de outra forma.
- **Velocidade é da ordem de dezenas de milhares de pacotes por segundo.** Suficiente para capturas de trabalho, mas não é um analisador de linha de 10 Gbps.
- **É uma ferramenta de triagem, não um veredito final.** Ela aponta onde olhar; a confirmação vem do host, dos logs e do contexto que só você tem.

---

## Estrutura do projeto

```text
investigator/
├── cli.py            interface de linha de comando
├── pipeline.py       orquestra todas as etapas
├── parser.py         lê o arquivo de captura
├── inventory.py      quem está na rede, quem fala com quem
├── protocols/        análise de DNS, TCP, HTTP e TLS
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
