# Yuroo Shield

Multi-agent smart contract security and rugpull detection. LLM-agnostic, multichain, runs useful even with zero API credits via deterministic on-chain heuristics + GoPlus public feed.

> **Status:** v0.1.0 — 6 agents, 6 chains, 20 tests green.

## What it does

Point it at a contract address. Six agents fan out, gather evidence, and return one verdict:

```
Risk: HIGH (47/100)
Avoid significant exposure. Review findings before any interaction.
```

Each agent contributes independent signals. The aggregator weights by severity and a single risk score falls out the bottom.

## Why this exists

Most existing scanners are either:
- Single-source (Etherscan-only or GoPlus-only) → blind spots.
- Behind a paywall (Chainalysis, TRM Labs).
- Closed-box dashboards you can't script against.

Yuroo Shield runs locally, costs nothing without an LLM key, and gives you a Python API + CLI you can wire into your own bots.

## Agents

| Agent | What it checks | Data source |
|---|---|---|
| `contract_scanner` | Verified source, proxy flag, hidden mint, blacklist, set-tax, pause, ownership renouncement | Etherscan v2 |
| `rugpull_monitor` | Contract age, recent tx failure rate (honeypot), inactivity | Etherscan v2 |
| `token_analyzer` | Total supply, top-10 holder concentration | Etherscan v2 (Pro for holders) |
| `threat_intel` | Curated blocklist match (extend with your own feed) | Local |
| `goplus_intel` | Honeypot, hidden owner, mintability, taxes, blacklist, selfdestruct | GoPlus public API (no key) |
| `report_generator` | Severity aggregation + optional LLM exec summary | Internal |

## Supported chains

Single Etherscan v2 API key covers all of them:

`ethereum` (1) · `bsc` (56) · `polygon` (137) · `arbitrum` (42161) · `optimism` (10) · `base` (8453)

## Quickstart

```bash
git clone https://github.com/yuroo-ui/yuroo-shield.git
cd yuroo-shield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # edit ETHERSCAN_API_KEY (free tier is fine)
yuroo-shield scan 0x6B175474E89094C44Da98b954EedeAC495271d0F   # DAI
```

JSON output for piping into other tools:

```bash
yuroo-shield scan 0x... --json | jq '.risk_score'
```

List supported chains:

```bash
yuroo-shield chains
```

## Configuration

| Var | Required | Purpose |
|---|---|---|
| `ETHERSCAN_API_KEY` | yes | On-chain data via Etherscan v2 unified |
| `LLM_API_KEY` | no | Any OpenAI-compatible endpoint |
| `LLM_BASE_URL` | no | Default `https://api.openai.com/v1` |
| `LLM_MODEL` | no | Default `gpt-4o-mini` |
| `HOLDER_CONCENTRATION_THRESHOLD` | no | Default `0.5` (50% top-10 ownership = high) |

LLM is fully optional. Without it, agents return deterministic heuristic signals only — still useful, just no chain-of-thought summary.

## LLM providers

Anything OpenAI-compatible drops in:

```bash
# OpenAI
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini

# OpenRouter
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_MODEL=anthropic/claude-3.5-haiku

# MiMo
LLM_BASE_URL=https://api.xiaomimimo.com/v1
LLM_MODEL=mimo-v2.5-pro

# Local (llama.cpp / vLLM)
LLM_BASE_URL=http://localhost:8080/v1
LLM_MODEL=local
```

## Python API

```python
import asyncio
from yuroo_shield import AgentOrchestrator

async def main():
    async with AgentOrchestrator() as orch:
        report = await orch.scan_contract(
            "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            chain="ethereum",
        )
    print(report.risk_level, report.risk_score)
    print(report.recommendation)

asyncio.run(main())
```

## Architecture

```
                  ┌──────────────────────┐
                  │   AgentOrchestrator   │
                  └──────────┬───────────┘
                             │
        ┌────────────┬───────┼─────────────┬─────────────┐
        │            │       │             │             │
   ┌────▼─────┐ ┌────▼────┐ ┌▼─────────┐ ┌─▼────────┐ ┌──▼────────┐
   │ Contract │ │ Rugpull │ │  Token   │ │ Threat   │ │  GoPlus   │
   │ Scanner  │ │ Monitor │ │ Analyzer │ │ Intel    │ │  Intel    │
   └────┬─────┘ └────┬────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘
        │            │           │            │             │
        └────────────┴───────────┼────────────┴─────────────┘
                                 │
                       ┌─────────▼─────────┐
                       │ Report Generator  │
                       └─────────┬─────────┘
                                 │
                ┌────────────────┴───────────────────┐
                │  Etherscan v2 + GoPlus + LLM       │
                └────────────────────────────────────┘
```

The 5 evidence-gathering agents run in parallel via `asyncio.gather`. The report generator runs sequentially after — it needs all upstream output to score and summarize.

## Risk scoring

Severity weights are aggregated and clamped to 100:

| Severity | Weight |
|---|---|
| info | 0 |
| low | 5 |
| medium | 15 |
| high | 30 |
| critical | 60 |

| Score | Level | Verdict |
|---|---|---|
| 0–4 | safe | No high-risk indicators found |
| 5–14 | low | Minor concerns |
| 15–34 | medium | Proceed with caution |
| 35–59 | high | Avoid significant exposure |
| 60+ | critical | Do not interact |

## Project layout

```
src/yuroo_shield/
├── __init__.py
├── __main__.py
├── cli.py              # typer + rich pretty / --json
├── config.py           # env-driven settings + chain registry
├── etherscan.py        # Etherscan v2 client
├── llm.py              # OpenAI-compatible client
├── orchestrator.py     # parallel agent dispatch
└── agents/
    ├── contract_scanner.py
    ├── rugpull_monitor.py
    ├── token_analyzer.py
    ├── threat_intel.py
    ├── goplus_intel.py
    └── report_generator.py
tests/                  # 20 tests, all mocked, no network
```

## Testing

```bash
pytest -q
```

All tests are network-free; HTTP and Etherscan calls are mocked.

## Roadmap

- [ ] LP lock detection (Uniswap v2/v3 LP holder analysis)
- [ ] Cross-chain whale-movement correlation
- [ ] Telegram bot wrapper
- [ ] Webhook subscriptions for continuous monitoring
- [ ] Redis cache layer for high-volume use

## License

MIT
