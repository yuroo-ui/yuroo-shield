"""End-to-end orchestrator test with all network calls mocked."""
import asyncio
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


def test_orchestrator_runs_without_llm():
    async def go():
        with (
            patch("yuroo_shield.etherscan.EtherscanClient.get_source_code", new=AsyncMock(
                return_value={
                    "SourceCode": "// 0x000000000000000000000000000000000000dead\ncontract X { uint x; }",
                    "ContractName": "X",
                    "CompilerVersion": "v0.8.20",
                    "Proxy": "0",
                }
            )),
            patch("yuroo_shield.etherscan.EtherscanClient.get_recent_txs", new=AsyncMock(return_value=[])),
            patch("yuroo_shield.etherscan.EtherscanClient.get_token_supply", new=AsyncMock(return_value="1000000")),
            patch("yuroo_shield.etherscan.EtherscanClient.get_token_holders", new=AsyncMock(return_value=[])),
            patch("yuroo_shield.agents.goplus_intel.GoPlusIntelAgent.scan", new=AsyncMock(
                return_value=__import__(
                    "yuroo_shield.agents.goplus_intel", fromlist=["GoPlusReport"]
                ).GoPlusReport(available=False)
            )),
        ):
            async with AgentOrchestrator(settings=_settings()) as orch:
                report = await orch.scan_contract("0xabc", "ethereum")
        return report

    report = asyncio.run(go())
    assert report.address == "0xabc"
    assert isinstance(report.risk_level, RiskLevel)
    assert "scanner" in report.agent_outputs
    assert "rugpull" in report.agent_outputs
    assert "token" in report.agent_outputs
    assert "threat" in report.agent_outputs
    assert "goplus" in report.agent_outputs
