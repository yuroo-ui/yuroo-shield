"""End-to-end orchestrator test with all network calls mocked."""
import asyncio
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from yuroo_shield.config import Settings
from yuroo_shield.orchestrator import AgentOrchestrator, RiskLevel


def _settings() -> Settings:
    return Settings(
        etherscan_api_key="x",
        llm_api_key=None,
        llm_base_url="http://x",
        llm_model="x",
        holder_concentration_threshold=0.5,
        min_holders_safe=1000,
    )


def _patches(creation_ts: int = 1573672677):
    """Common Etherscan + GoPlus mocks. Returns a list of patcher contexts."""
    from yuroo_shield.agents.goplus_intel import GoPlusReport

    return [
        patch(
            "yuroo_shield.etherscan.EtherscanClient.get_source_code",
            new=AsyncMock(
                return_value={
                    "SourceCode": (
                        "// 0x000000000000000000000000000000000000dead\n"
                        "contract X { uint x; }"
                    ),
                    "ContractName": "X",
                    "CompilerVersion": "v0.8.20",
                    "Proxy": "0",
                }
            ),
        ),
        patch(
            "yuroo_shield.etherscan.EtherscanClient.get_recent_txs",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "yuroo_shield.etherscan.EtherscanClient.get_token_supply",
            new=AsyncMock(return_value="1000000"),
        ),
        patch(
            "yuroo_shield.etherscan.EtherscanClient.get_token_holders",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "yuroo_shield.etherscan.EtherscanClient.get_contract_creation_timestamp",
            new=AsyncMock(return_value=creation_ts),
        ),
        patch(
            "yuroo_shield.agents.goplus_intel.GoPlusIntelAgent.scan",
            new=AsyncMock(return_value=GoPlusReport(available=False)),
        ),
    ]


async def _scan(address: str):
    with ExitStack() as stack:
        for p in _patches():
            stack.enter_context(p)
        async with AgentOrchestrator(settings=_settings()) as orch:
            return await orch.scan_contract(address, "ethereum")


def test_orchestrator_runs_without_llm():
    report = asyncio.run(_scan("0xabc"))
    assert report.address == "0xabc"
    assert isinstance(report.risk_level, RiskLevel)
    for k in ("scanner", "rugpull", "token", "threat", "goplus"):
        assert k in report.agent_outputs


def test_orchestrator_dampens_canonical_token():
    """Scanning canonical DAI should cap the score at LOW even if heuristics fire."""
    report = asyncio.run(_scan("0x6B175474E89094C44Da98b954EedeAC495271d0F"))
    assert report.canonical_name == "DAI"
    assert report.risk_score <= 5
    assert report.risk_level in (RiskLevel.SAFE, RiskLevel.LOW)
    assert "Canonical" in report.recommendation
