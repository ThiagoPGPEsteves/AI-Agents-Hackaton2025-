# 🛡️ XenDefender — Orquestrador Autônomo de Cibersegurança em Tempo Real
> **CrewAI + Google Gemini 3.5 Flash + Python 3.13**  
> *AI Agents Hackathon 2025*

O **XenDefender** é um orquestrador autônomo de operações de segurança defensiva (SecOps / SOC / CSIRT). Ele monitora fluxos contínuos de logs em tempo real, detecta ameaças cibernéticas (SQL Injection, Command Injection, Path Traversal/LFI, Força Bruta e Exfiltração de Dados) em milissegundos e orquestra uma equipe especializada de agentes de inteligência artificial para triagem forense, correlação técnica (MITRE ATT&CK / OWASP Top 10) e contenção automatizada.

---

## 🏛️ Arquitetura Híbrida de Alta Performance

```
                           [Fluxo de Logs / Simulador]
                                       │
                                       ▼ (Tailing incremental com controle de offset)
                         [Camada Determinística em Python]
                                       ├─ Parsers (JSONL e logs de servidor)
                                       ├─ Mascaramento PII (redact de senhas, cartões, CPFs e tokens)
                                       ├─ Assinaturas Rápidas (SQLi com decodificação de evasão, Cmd, LFI)
                                       ├─ Anomalias com Estado LRU (Força Bruta e Exfiltração)
                                       └─ Agregador de Incidentes (Deduplicação SHA-1 e Cooldown de 30s)
                                       │
                                       ▼ (Incidente candidato)
                          [CrewAI IncidentFlow (@router)]
                                       ├── [LOW] ─────────────> Auditoria Direta (Zero Tokens / Zero Latência)
                                       └── [MEDIUM / HIGH / CRITICAL]
                                                 │
                                                 ▼
                                     [IncidentCrew: Gemini 3.5 Flash]
                                                 ├─ Analyst Agent (Triagem, MITRE, OWASP, Risco)
                                                 └─ Responder Agent (Plano de Contenção e Ação)
                                                 │
                                                 ▼
                                     [Motor de Políticas (Policy Engine)]
                                                 ├─ Imunidade a Prompt Injection (IP de rede imutável)
                                                 ├─ Piso de Severidade (impede rebaixamento por falso-positivo)
                                                 ├─ Firewall Simulado (state/blocklist.json com TTL)
                                                 ├─ Trilha de Auditoria Criptográfica (state/audit.jsonl com SHA-256)
                                                 └─ Alertas Multicanal (Console, Slack e Discord)
```

---

## 🤖 Agentes Especializados (CrewAI + Gemini 3.5 Flash)

| Agente | Papel | Responsabilidade Principal | Saída Tipada |
|---|---|---|---|
| **Analyst Agent** | Analista Sênior de SOC | Avalia evidências, descarta falsos-positivos, mapeia a técnica no framework MITRE ATT&CK e categoria OWASP Top 10, gerando um índice de confiança forense. | `ThreatAssessment` (Pydantic v2) |
| **Responder Agent** | Especialista em Resposta (CIRT) | Define a estratégia de mitigação (`block_ip`, `notify`, `audit_only`) e resume as contramedidas operacionais aplicadas. | `ResponsePlan` (Pydantic v2) |

---

## 🔒 Mecanismos de Proteção e Resiliência

1. **Imunidade a Prompt Injection**:
   - O IP alvo de bloqueio é extraído diretamente da camada de transporte e cabeçalhos de rede sanitizados. Mesmo que um invasor injete comandos de texto livre nos payloads para tentar induzir o modelo a bloquear outro IP ou servidores internos, o motor de políticas ignora qualquer IP gerado pelo LLM.
2. **Piso Inegociável de Severidade**:
   - Ataques com assinaturas comprovadas de alta confiança (ex: `; DROP TABLE`, `; whoami`) não podem ter sua severidade rebaixada por manipulação contextual.
3. **Proteção Rígida de Allowlist**:
   - Endereços de infraestrutura interna (`127.0.0.1`, `::1`, `10.0.0.1`, `localhost`) nunca são bloqueados pelo firewall simulado, prevenindo auto-bloqueio (*self-denial-of-service*).
4. **Firewall Simulado com TTL**:
   - Bloqueios temporizados com expiração automática (TTL de 1h) persistidos em `state/blocklist.json`.
5. **Trilha de Auditoria Criptográfica**:
   - Cada evento é registrado em `state/audit.jsonl` encadeado ao hash SHA-256 do registro anterior, garantindo integridade e impossibilidade de adulteração retroativa.
6. **Fail-Safe e Resiliência a Falhas de API**:
   - Mecanismo automático de *retry* para erros temporários de sobrecarga (503/429). Caso a API fique indisponível, o sistema ativa a contenção heurística autônoma (`llm_status="fallback"`), mantendo a proteção ininterrupta.

---

## 🚀 Como Executar

### Pré-requisitos
- **Python 3.13** instalado via [UV](https://docs.astral.sh/uv/)
- Chave de API do Google Gemini configurada no `.env`

```bash
# 1. Instalar o ambiente e dependências
uv sync
```

### Configurar Variáveis de Ambiente (`.env`)
Copie o template e preencha sua chave:
```bash
cp .env.example .env
```
```ini
MODEL=gemini/gemini-3.5-flash
GEMINI_API_KEY=sua_chave_gemini_aqui
DRY_RUN=true
BLOCK_TTL_SECONDS=3600
LOG_FILE_PATH=logs/server.log
```

---

### Execução dos Módulos

#### 1. Executar a Suíte Completa de Testes Automatizados (33 testes)
```bash
uv run pytest tests/ -v
```

#### 2. Iniciar o Dashboard Web XenDefender (Terminal 1)
Inicia o servidor web interativo com análise sob demanda e feed de segurança ao vivo:
```bash
uv run python -m cybersecurityteam.main web
```
👉 Acesse no navegador: **http://127.0.0.1:5000**

#### 3. Iniciar o Monitor em Tempo Real com os Agentes (Terminal 2)
Lê continuamente `logs/server.log`, detecta anomalias e aciona os agentes para contenção:
```bash
uv run python -m cybersecurityteam.main monitor
```

#### 4. Iniciar o Simulador de Tráfego e Ataques (Terminal 3)
Gera tráfego realista contínuo intercalando consultas normais e ataques cibernéticos:
```bash
uv run python -m cybersecurityteam.main simulate
```

#### 5. Consultar o Status do Firewall e Auditoria Forense
```bash
uv run python -m cybersecurityteam.main status
```

---

## 📁 Estrutura do Repositório

```
.
├── README.md                           # Documentação técnica e operacional
├── pyproject.toml                      # Metadados e dependências UV
├── .python-version                     # Python 3.13 fixado
├── .gitignore                          # Ignora .env, *.md locais, state/, logs/
├── Tempo/                              # Frontend Web XenDefender
│   ├── index.html                      # Dashboard interativo com feed de incidentes
│   └── assets/                         # CSS, JS, ícones e imagens
├── cybersecurityteam/
│   ├── .env.example                    # Template de variáveis de ambiente
│   └── src/
│       └── cybersecurityteam/
│           ├── main.py                 # Ponto de entrada CLI (monitor, simulate, web, status)
│           ├── config.py               # Configurações centrais Pydantic
│           ├── models.py               # Modelos Pydantic v2 (Incident, ThreatAssessment, etc.)
│           ├── crew.py                 # IncidentCrew (CrewBase com Analyst e Responder)
│           ├── flow.py                 # IncidentFlow (orquestração por severidade)
│           ├── simulator.py            # Gerador de tráfego contínuo e ataques
│           ├── web.py                  # API Flask do dashboard XenDefender
│           ├── config/
│           │   ├── agents.yaml         # Definições dos agentes otimizadas para Gemini
│           │   └── tasks.yaml          # Tarefas com saídas tipadas Pydantic
│           ├── ingestion/
│           │   ├── tailer.py           # Leitura incremental com controle de offset
│           │   └── parsers.py          # Parsers JSONL e logs de servidor
│           ├── security/
│           │   ├── redact.py           # Mascaramento de senhas, tokens e dados sensíveis
│           │   └── mitre_map.py        # Mapeamento MITRE ATT&CK e OWASP Top 10
│           ├── detection/
│           │   ├── signatures.py       # Detecção rápida de SQLi, Cmd Injection e LFI
│           │   └── stateful.py         # Janela deslizante para Força Bruta e Exfiltração
│           │   └── aggregator.py       # Deduplicação, cooldown e escalada de severidade
│           └── response/
│               ├── policy.py           # Motor de políticas determinístico e fail-safe
│               ├── firewall.py         # Firewall simulado com TTL e allowlist
│               ├── notifier.py         # Alertas coloridos no Console, Slack e Discord
│               └── audit.py            # Trilha de auditoria encadeada com SHA-256
└── tests/                              # Suíte completa de testes automatizados com pytest
```

---

## 🏆 Critérios de Avaliação do Hackathon Atendidos

- **Orquestração Multi-Agente Avançada**: Uso de `CrewAI Flow` com roteamento condicional inteligente (`@router`), dividindo responsabilidades entre `Analyst Agent` e `Responder Agent`.
- **Eficiência de Recursos e Custo**: Eventos de baixa severidade não consomem tokens de LLM; apenas incidentes relevantes acionam a inteligência generativa.
- **Segurança Prática e Defesa em Profundidade**: Imunidade contra *Prompt Injection*, proteção de infraestrutura com *Allowlist*, mascaramento de dados sensíveis (*LGPD / PCI-DSS*) e encadeamento criptográfico para auditoria.
- **Demonstração Visual Completa**: Dashboard visual integrado (*XenDefender*) com simulação em tempo real para avaliação dos jurados.
