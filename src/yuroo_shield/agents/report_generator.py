"""Report Generator Agent — composes final verdict from upstream agent outputs."""
from __future__ import annotations

from dataclasses import dataclass

from ..llm import LLMClient

_SEVERITY_WEIGHT = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 60,
}


@dataclass
class VerdictInputs:
    scanner: dict
    rugpull: dict
    token: dict
    threat: dict
    goplus: dict


@dataclass
class Verdict:
    risk_score: int  # 0..100
    risk_level: str
    recommendation: str
    summary: str


class ReportGeneratorAgent:
    name = "report_generator"

    def __init__(self, llm: LLMClient):
        self._llm = llm

    def _aggregate_score(self, inputs: VerdictInputs) -> int:
        score = 0
        sources = (inputs.scanner, inputs.rugpull, inputs.token, inputs.threat, inputs.goplus)
        for src in sources:
            for finding in src.get("findings", []) + src.get("signals", []):
                score += _SEVERITY_WEIGHT.get(finding.get("severity", "info"), 0)
        return min(score, 100)

    def _level(self, score: int) -> str:
        if score >= 60:
            return "critical"
        if score >= 35:
            return "high"
        if score >= 15:
            return "medium"
        if score >= 5:
            return "low"
        return "safe"

    def _baseline_recommendation(self, level: str) -> str:
        return {
            "critical": "Do not interact. Multiple critical risks detected.",
            "high": "Avoid significant exposure. Review findings before any interaction.",
            "medium": "Proceed with caution. Some risk indicators detected.",
            "low": "Minor concerns; review before large positions.",
            "safe": "No high-risk indicators found.",
        }[level]

    async def generate(self, inputs: VerdictInputs) -> Verdict:
        score = self._aggregate_score(inputs)
        level = self._level(score)
        rec = self._baseline_recommendation(level)
        summary = ""

        if self._llm.enabled:
            prompt = (
                "Write a 3-sentence executive summary of this contract security report. "
                "Be specific, no boilerplate.\n\n"
                f"Scanner: {inputs.scanner}\n"
                f"Rugpull: {inputs.rugpull}\n"
                f"Token: {inputs.token}\n"
                f"Threat: {inputs.threat}\n"
                f"GoPlus: {inputs.goplus}\n"
                f"Risk score: {score}/100, level: {level}."
            )
            summary = await self._llm.reason(
                prompt=prompt,
                system="You are a Web3 security analyst writing for a non-technical user.",
            )

        return Verdict(
            risk_score=score, risk_level=level, recommendation=rec, summary=summary
        )
