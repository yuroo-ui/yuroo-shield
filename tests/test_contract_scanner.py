"""Tests for ContractScannerAgent — heuristic patterns, no network."""
import asyncio
from unittest.mock import AsyncMock

from yuroo_shield.agents.contract_scanner import ContractScannerAgent
from yuroo_shield.llm import LLMClient


def _make_agent(source_code: str, contract_name: str = "Test", verified: bool = True):
    es = AsyncMock()
    es.get_source_code.return_value = {
        "SourceCode": source_code if verified else "",
        "ContractName": contract_name,
        "CompilerVersion": "v0.8.20",
        "Proxy": "0",
    }
    llm = LLMClient(api_key=None, base_url="http://x", model="x")
    return ContractScannerAgent(es, llm)


def test_unverified_flagged():
    agent = _make_agent("", verified=False)
    report = asyncio.run(agent.scan("0xabc", "ethereum"))
    assert not report.verified
    names = {f.name for f in report.findings}
    assert "unverified_source" in names


def test_hidden_mint_detected():
    src = """
    contract X {
        function mint(address to, uint amount) public {}
    }
    """
    agent = _make_agent(src)
    report = asyncio.run(agent.scan("0xabc", "ethereum"))
    names = {f.name for f in report.findings}
    assert "hidden_mint" in names


def test_blacklist_detected():
    src = "function setBlacklist(address a) external onlyOwner {}"
    agent = _make_agent(src)
    report = asyncio.run(agent.scan("0xabc", "ethereum"))
    assert "blacklist" in {f.name for f in report.findings}


def test_renounced_ownership_no_warning():
    src = "// owner = 0x000000000000000000000000000000000000dead\ncontract X {}"
    agent = _make_agent(src)
    report = asyncio.run(agent.scan("0xabc", "ethereum"))
    assert "ownership_not_renounced" not in {f.name for f in report.findings}


def test_clean_contract_minimal_findings():
    src = "// 0x000000000000000000000000000000000000dead\ncontract X { uint x; }"
    agent = _make_agent(src)
    report = asyncio.run(agent.scan("0xabc", "ethereum"))
    severities = [f.severity for f in report.findings]
    assert "high" not in severities
    assert "critical" not in severities
