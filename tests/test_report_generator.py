"""Tests for ReportGeneratorAgent — pure-logic, no network."""
import asyncio

from yuroo_shield.agents.report_generator import ReportGeneratorAgent, VerdictInputs
from yuroo_shield.llm import LLMClient


def _agent() -> ReportGeneratorAgent:
    llm = LLMClient(api_key=None, base_url="http://x", model="x")
    return ReportGeneratorAgent(llm)


def test_safe_when_no_findings():
    agent = _agent()
    inputs = VerdictInputs(
        scanner={"findings": []},
        rugpull={"signals": []},
        token={"signals": []},
        threat={"signals": []},
        goplus={"signals": []},
    )
    verdict = asyncio.run(agent.generate(inputs))
    assert verdict.risk_score == 0
    assert verdict.risk_level == "safe"


def test_critical_signal_pushes_score():
    agent = _agent()
    inputs = VerdictInputs(
        scanner={"findings": []},
        rugpull={"signals": []},
        token={"signals": []},
        threat={"signals": [{"name": "address_on_blocklist", "severity": "critical"}]},
        goplus={"signals": []},
    )
    verdict = asyncio.run(agent.generate(inputs))
    assert verdict.risk_score >= 60
    assert verdict.risk_level == "critical"
    assert "Do not interact" in verdict.recommendation


def test_score_caps_at_100():
    agent = _agent()
    inputs = VerdictInputs(
        scanner={"findings": [{"severity": "critical"}] * 10},
        rugpull={"signals": []},
        token={"signals": []},
        threat={"signals": []},
        goplus={"signals": []},
    )
    verdict = asyncio.run(agent.generate(inputs))
    assert verdict.risk_score == 100


def test_severity_aggregation():
    agent = _agent()
    inputs = VerdictInputs(
        scanner={"findings": [{"severity": "low"}, {"severity": "medium"}]},
        rugpull={"signals": [{"severity": "high"}]},
        token={"signals": []},
        threat={"signals": []},
        goplus={"signals": []},
    )
    # 5 + 15 + 30 = 50
    verdict = asyncio.run(agent.generate(inputs))
    assert verdict.risk_score == 50
    assert verdict.risk_level == "high"


def test_goplus_signals_included_in_score():
    agent = _agent()
    inputs = VerdictInputs(
        scanner={"findings": []},
        rugpull={"signals": []},
        token={"signals": []},
        threat={"signals": []},
        goplus={"signals": [{"name": "is_honeypot", "severity": "critical"}]},
    )
    verdict = asyncio.run(agent.generate(inputs))
    assert verdict.risk_score >= 60
    assert verdict.risk_level == "critical"
