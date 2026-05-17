"""Tests for GoPlusIntelAgent — mocked HTTP."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from yuroo_shield.agents.goplus_intel import GoPlusIntelAgent


def _mock_response(payload: dict):
    resp = MagicMock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


def test_unsupported_chain_returns_unavailable():
    agent = GoPlusIntelAgent()
    report = asyncio.run(agent.scan("0xabc", "solana"))
    assert report.available is False
    assert report.signals == []


def test_honeypot_flagged():
    payload = {
        "result": {
            "0xabc": {
                "is_honeypot": "1",
                "is_open_source": "1",
                "buy_tax": "0",
                "sell_tax": "0",
                "holder_count": "100",
            }
        }
    }
    agent = GoPlusIntelAgent()
    with patch.object(agent._http, "get", new=AsyncMock(return_value=_mock_response(payload))):
        report = asyncio.run(agent.scan("0xabc", "ethereum"))
    assert report.available is True
    assert any(s.name == "is_honeypot" and s.severity == "critical" for s in report.signals)


def test_high_buy_tax_flagged():
    payload = {
        "result": {
            "0xabc": {
                "is_open_source": "1",
                "buy_tax": "0.15",
                "sell_tax": "0.05",
                "holder_count": "1000",
            }
        }
    }
    agent = GoPlusIntelAgent()
    with patch.object(agent._http, "get", new=AsyncMock(return_value=_mock_response(payload))):
        report = asyncio.run(agent.scan("0xabc", "ethereum"))
    names = {s.name for s in report.signals}
    assert "high_buy_tax" in names
    assert "elevated_sell_tax" in names
    assert report.buy_tax == 0.15


def test_not_open_source_flagged():
    payload = {
        "result": {
            "0xabc": {
                "is_open_source": "0",
                "buy_tax": "0",
                "sell_tax": "0",
                "holder_count": "10",
            }
        }
    }
    agent = GoPlusIntelAgent()
    with patch.object(agent._http, "get", new=AsyncMock(return_value=_mock_response(payload))):
        report = asyncio.run(agent.scan("0xabc", "ethereum"))
    assert any(s.name == "not_open_source" for s in report.signals)


def test_clean_token_no_signals():
    payload = {
        "result": {
            "0xabc": {
                "is_honeypot": "0",
                "is_open_source": "1",
                "buy_tax": "0",
                "sell_tax": "0",
                "holder_count": "5000",
                "is_mintable": "0",
            }
        }
    }
    agent = GoPlusIntelAgent()
    with patch.object(agent._http, "get", new=AsyncMock(return_value=_mock_response(payload))):
        report = asyncio.run(agent.scan("0xabc", "ethereum"))
    assert report.available is True
    assert report.signals == []
    assert report.holder_count == 5000


def test_empty_result_returns_unavailable():
    agent = GoPlusIntelAgent()
    with patch.object(agent._http, "get", new=AsyncMock(return_value=_mock_response({"result": {}}))):
        report = asyncio.run(agent.scan("0xabc", "ethereum"))
    assert report.available is False
