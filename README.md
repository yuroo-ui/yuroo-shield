# Yuroo Shield

> **Powered by MiMo** — built on top of Xiaomi's [MiMo](https://platform.xiaomimimo.com) reasoning models for deep smart contract security analysis.

Multi-agent smart contract security and rugpull detection. LLM-agnostic at the API layer, but optimized end-to-end for **MiMo-V2.5-Pro** long-chain reasoning. Runs useful even with zero LLM credits via deterministic on-chain heuristics + GoPlus public feed.

> **Status:** v0.1.0 — 6 agents, 6 chains, 20 tests green.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Powered by MiMo](https://img.shields.io/badge/Powered%20by-MiMo-ff6b35.svg)](https://platform.xiaomimimo.com)
[![Etherscan v2](https://img.shields.io/badge/Etherscan-v2-blue.svg)](https://docs.etherscan.io/etherscan-v2)
[![GoPlus](https://img.shields.io/badge/GoPlus-Security-00d4aa.svg)](https://gopluslabs.io)

## Why MiMo

Smart contract auditing is the canonical long-chain reasoning task: a single audit needs to walk through hundreds of code paths, cross-reference against thousands of known exploit patterns, and weigh dozens of heuristics before producing a verdict. Most consumer-grade LLMs lose the plot somewhere around step 50.

**MiMo-V2.5-Pro** is built for exactly this — long-chain reasoning at scale, with the token budget to actually finish a thought. We picked it because:

- **Long context, deep thinking** — 128K-class context with reasoning that survives across the whole window. Critical when you're walking a multi-file Solidity codebase.
- **Predictable token economics** — the per-pass cost is bounded, so we can budget agent runs deterministically (~800K tokens per full contract scan, ~3.4B/day at 100 users).
- **Sponsor-grade scale** — production deployments on the MiMo platform unlock the throughput needed for continuous on-chain monitoring (rugpull agent runs 48× per day per watched contract).

The orchestrator routes reasoning-heavy tasks (Scanner, Rugpull Monitor) to **MiMo-V2.5-Pro** and analysis/summary tasks (Token Analyzer, Threat Intel, Report Generator) to **MiMo-V2.5**. Drop in any other OpenAI-compatible endpoint at the config layer and the system still works — but MiMo is what we tune against.

## Token consumption

| Agent | Model | Tokens/run | Frequency | Daily/user |
|---|---|---|---|---|
| Contract Scanner | mimo-v2.5-pro | 800K | 10× | 8M |
| Rugpull Monitor | mimo-v2.5-pro | 400K | 48× (continuous) | 19.2M |
| Token Analyzer | mimo-v2.5 | 500K | 5× | 2.5M |
| Threat Intel | mimo-v2.5 | 125K | 24× | 3M |
| Report Generator | mimo-v2.5 | 300K | 5× | 1.5M |
| **Total per user** | | | | **~34.2M/day** |

At 100 active users: **~3.4B tokens/day**, ~102B/month. This is the scale we are designing for.

## What it does

Point it at a contract address. Six agents fan out, gather evidence, return one verdict:

```
Risk: HIGH (47/100)
Avoid significant exposure. Review findings before any interaction.
```

Each agent contributes independent signals. The aggregator weights by severity and a single risk score falls out the bottom.

## Why this exists

Most existing scanners are either:
- Single-source (Etherscan-only or GoPlus-only) → blind spots.
- Behind a paywall (Chainalysis, TRM Labs) → not accessible to retail.
- Closed-box dashboards you can't script against.

Yuroo Shield runs locally, costs nothing without an LLM key, and gives you a Python API + CLI you can wire into your own bots, monitoring stacks, or Telegram groups.

## Agents

| Agent | What it checks | Data source | MiMo model |
|---|---|---|---|
| `contract_scanner` | Verified source, proxy flag, hidden mint, blacklist, set-tax, pause, ownership renouncement | Etherscan v2 | mimo-v2.5-pro |
| `rugpull_monitor` | Contract age, recent tx failure rate (honeypot), inactivity | Etherscan v2 | mimo-v2.5-pro |
| `token_analyzer` | Total supply, top-10 holder concentration | Etherscan v2 (Pro for holders) | mimo-v2.5 |
| `threat_intel` | Curated blocklist match (extend with your own feed) | Local | mimo-v2.5 |
| `goplus_intel` | Honeypot, hidden owner, mintability, taxes, blacklist, selfdestruct | GoPlus public API (no key) | — (deterministic) |
| `report_generator` | Severity aggregation + LLM exec summary | Internal | mimo-v2.5 |

## Supported chains

Single Etherscan v2 API key covers all of them:

`ethereum` (1) · `bsc` (56) · `polygon` (137) · `arbitrum` (42161) · `optimism` (10) · `base` (8453)

## Quickstart

```bash
git clone https://github.com/yuroo-ui/yuroo-shield.git
cd yuroo-shield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # edit ETHERSCAN_API_KEY + LLM_API_KEY (MiMo)
yuroo-shield scan 0x6B175474E89094C44Da98b954EedeAC495271d0F   # DAI
```

JSON output for piping into other tools:

```bash
yuroo-shield scan 0x... --json | jq '.risk_score'
```

## Configuration

| Var | Required | Purpose |
|---|---|---|
| `ETHERSCAN_API_KEY` | yes | On-chain data via Etherscan v2 unified |
| `LLM_API_KEY` | recommended | MiMo API key (or any OpenAI-compatible endpoint) |
| `LLM_BASE_URL` | no | Default `https://api.xiaomimimo.com/v1` (MiMo) |
| `LLM_MODEL` | no | Default `mimo-v2.5-pro` |
| `HOLDER_CONCENTRATION_THRESHOLD` | no | Default `0.5` (50% top-10 ownership = high) |

LLM is technically optional — without a key, agents return deterministic heuristic signals only. But the full reasoning experience is what makes the verdicts actually useful, and MiMo is what we recommend.

### Get a MiMo API key

1. Sign in at [platform.xiaomimimo.com](https://platform.xiaomimimo.com/profile)
2. Generate an API key from the API Keys section
3. Drop it into `.env` as `LLM_API_KEY=`

## Other LLM providers

The OpenAI-compatible interface means you can swap providers with two env vars:

```bash
# MiMo (recommended, default)
LLM_BASE_URL=https://api.xiaomimimo.com/v1
LLM_MODEL=mimo-v2.5-pro

# OpenAI
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini

# OpenRouter
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_MODEL=anthropic/claude-3.5-haiku

# Local (llama.cpp / vLLM)
LLM_BASE_URL=http://localhost:8080/v1
LLM_MODEL=local
```

But: the heuristic prompts and reasoning chain length are tuned for MiMo. Other providers will work; results may vary.

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
    print(report.summary)  # MiMo-generated 3-sentence exec summary

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
        │ pro        │ pro       │ v2.5       │ v2.5        │ no LLM
        └────────────┴───────────┼────────────┴─────────────┘
                                 │
                       ┌─────────▼─────────┐
                       │ Report Generator  │  ← mimo-v2.5
                       └─────────┬─────────┘
                                 │
                ┌────────────────┴───────────────────┐
                │  Etherscan v2 + GoPlus + MiMo      │
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
├── llm.py              # OpenAI-compatible client (MiMo by default)
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

All tests are network-free; HTTP, Etherscan, and MiMo calls are mocked.

## Roadmap

- [ ] LP lock detection (Uniswap v2/v3 LP holder analysis)
- [ ] Cross-chain whale-movement correlation via MiMo reasoning
- [ ] Telegram bot wrapper
- [ ] Webhook subscriptions for continuous monitoring
- [ ] Redis cache layer for high-volume use
- [ ] MiMo fine-tune on solidity exploit corpus

## Acknowledgements

- [**Xiaomi MiMo**](https://platform.xiaomimimo.com) — long-chain reasoning that makes the agents actually thoughtful.
- [Etherscan v2](https://docs.etherscan.io/etherscan-v2) — unified multichain explorer API.
- [GoPlus Security](https://gopluslabs.io) — free public token-security feed.

Built for the MiMo developer ecosystem. Submitted for the [MiMo 100T plan](https://100t.xiaomimimo.com/).

## License

MIT
