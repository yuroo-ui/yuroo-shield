"""Tests for ThreatIntelAgent."""
import asyncio

from yuroo_shield.agents.threat_intel import ThreatIntelAgent


def test_clean_address_no_signals():
    agent = ThreatIntelAgent()
    report = asyncio.run(agent.scan("0x6B175474E89094C44Da98b954EedeAC495271d0F", "ethereum"))
    assert report.signals == []
    assert report.matched_lists == []


def test_blocklisted_address_flagged():
    agent = ThreatIntelAgent()
    report = asyncio.run(agent.scan("0x8589427373d6d84e98730d7795d8f6f8731fda16", "ethereum"))
    assert "local_curated" in report.matched_lists
    assert any(s.severity == "critical" for s in report.signals)


def test_address_match_is_case_insensitive():
    agent = ThreatIntelAgent()
    report = asyncio.run(agent.scan("0x8589427373D6D84E98730D7795D8F6F8731FDA16", "ethereum"))
    assert "local_curated" in report.matched_lists
