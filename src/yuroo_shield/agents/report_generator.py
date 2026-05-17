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
            findings_only = _flatten_findings(inputs)
            prompt = (
                "Write a 2-3 sentence executive summary of this contract security report.\n"
                "STRICT RULES:\n"
                "1. Use ONLY the findings listed below — do NOT invent vulnerabilities, "
                "CVE references, or attack patterns that are not explicitly in the list.\n"
                "2. If the findings list is empty, say the contract has no high-risk "
                "indicators and stop.\n"
                "3. Mention the risk level and score numerically.\n"
                "4. Keep it factual and short. No marketing language.\n\n"
                f"Risk score: {score}/100, level: {level}.\n"
                f"Contract age (days): {inputs.rugpull.get('contract_age_days')}\n"
                f"Findings ({len(findings_only)} total):\n{findings_only or '  (none)'}"
            )
            summary = await self._llm.reason(
                prompt=prompt,
                system=(
                    "You are a Web3 security analyst. You summarize ONLY what is "
                    "explicitly provided. You never speculate or invent risks."
                ),
            )

        return Verdict(
            risk_score=score, risk_level=level, recommendation=rec, summary=summary
        )


def _flatten_findings(inputs: VerdictInputs) -> str:
    """Render every finding as a single bullet list. Used to constrain the LLM."""
    lines: list[str] = []
    sources = [
        ("scanner", inputs.scanner),
        ("rugpull", inputs.rugpull),
        ("token", inputs.token),
        ("threat", inputs.threat),
        ("goplus", inputs.goplus),
    ]
    for agent, src in sources:
        for f in src.get("findings", []) + src.get("signals", []):
            sev = f.get("severity", "info")
            name = f.get("name", "")
            detail = f.get("detail", "")
            lines.append(f"  - [{agent}/{sev}] {name}: {detail}")
    return "\n".join(lines)
